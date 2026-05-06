using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace USBGuardian
{
    // ══════════════════════════════════════════════════════════════════════════════
    //  EarlyWhitelistChecker
    //
    //  Called at T+10ms from OnPnpDeviceArrived BEFORE CM_Disable_DevNode.
    //  If device matches whitelist → returns true → caller skips freeze entirely.
    //  If no match or any error → returns false → caller freezes as normal.
    //
    //  ANTI-CLONE ANCHOR PARAMETERS (ranked hardest → easiest to fake):
    //
    //  Tier 1 — hardware-burned, cannot be changed without re-flashing controller:
    //    • USB descriptor hash  (bcdUSB, bcdDevice, MaxPacketSize0, class bytes,
    //                            all interface + endpoint descriptors concatenated)
    //    • BOS descriptor hash  (USB 3.x only — capability descriptors, GUID)
    //    • ContainerID          (set by Windows from iSerialNumber; GUID derived
    //                            from serial; same serial → same GUID)
    //
    //  Tier 2 — set by firmware, changeable only by re-flashing:
    //    • SerialNumber         (iSerialNumber string from device descriptor)
    //    • ParentIdPrefix       (Windows-internal; stable per serial per chipset)
    //
    //  Tier 3 — stable but readable without IOCTL, available at T+10ms in registry:
    //    • HardwareId[0]        (VID_xxxx&PID_xxxx&REV_xxxx — includes revision)
    //    • CompatibleIds        (driver-stack hint; Rubber Ducky often differs here)
    //    • LocationInformation  (Port_#NNNN.Hub_#NNNN — physical port path)
    //
    //  WHAT IS AVAILABLE AT T+10ms (registry only, no WMI/IOCTL yet):
    //    VID, PID, SerialNumber (from instanceId), HardwareId, CompatibleId,
    //    LocationInformation, ParentIdPrefix, ContainerId, Service.
    //    Descriptor hashes are NOT available yet — those require hub IOCTL.
    //
    //  RACE-WINDOW SAFETY:
    //    • All registry reads use try/catch with null-fallback.
    //    • Any exception → false (device NOT whitelisted → freeze happens).
    //    • No WMI, no IOCTL, no blocking I/O — pure registry reads (~1ms).
    //    • Does NOT touch CM_* functions — zero driver stack interaction.
    //    • Does NOT modify any registry values — read-only.
    //
    //  CLONE RESISTANCE LOGIC:
    //    Whitelist entry requires ALL of:
    //      (a) VID + PID match, AND
    //      (b) SerialNumber match (if whitelist entry has one), AND
    //      (c) HardwareId[0] match including REV_ field, AND
    //      (d) ContainerId match (if present in registry), AND
    //      (e) DescriptorHash match (if stored — checked post-freeze in normal path)
    //    Attacker must clone: same VID/PID (easy) + same serial (hard if unique)
    //    + same ContainerId (derived from serial → same difficulty) + same REV_
    //    (requires same firmware revision). All four together = extremely hard.
    // ══════════════════════════════════════════════════════════════════════════════

    internal sealed class EarlyWhitelistChecker
    {
        // ── Whitelist store ──────────────────────────────────────────────────────

        private readonly string _whitelistPath;
        private readonly object _lock = new();
        private List<EarlyWhitelistEntry> _entries = new();
        private DateTime _lastLoadTime = DateTime.MinValue;

        // Reload from disk if file changed (supports external edits / UI adds)
        private const int ReloadIntervalSeconds = 30;

        public EarlyWhitelistChecker(string whitelistDirectory)
        {
            _whitelistPath = Path.Combine(whitelistDirectory, "early_whitelist.json");
            Load();
        }

        // ── Public API ───────────────────────────────────────────────────────────

        /// <summary>
        /// Call from OnPnpDeviceArrived at T+10ms.
        /// instanceId format: "USB\VID_xxxx&PID_xxxx\serialOrHash"
        /// Returns true ONLY when device matches whitelist with high confidence.
        /// Returns false on any doubt → caller must freeze.
        /// </summary>
        public bool IsEarlyWhitelisted(string instanceId)
        {
            if (string.IsNullOrWhiteSpace(instanceId))
                return false;

            try
            {
                ReloadIfStale();

                List<EarlyWhitelistEntry> entries;
                lock (_lock) { entries = new List<EarlyWhitelistEntry>(_entries); }

                if (entries.Count == 0)
                    return false;

                // Parse VID/PID/serial from instanceId before touching registry
                if (!ParseInstanceId(instanceId, out string vid, out string pid, out string serialFromId))
                    return false;

                // Quick pre-filter: does any entry match VID:PID at all?
                bool anyVidPidMatch = false;
                foreach (var e in entries)
                    if (string.Equals(e.Vid, vid, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(e.Pid, pid, StringComparison.OrdinalIgnoreCase))
                    { anyVidPidMatch = true; break; }

                if (!anyVidPidMatch)
                    return false;  // Fast exit — no entry for this VID:PID

                // Read anti-clone params from registry (~0.5ms, no driver interaction)
                EarlyDeviceParams p = ReadRegistryParams(instanceId, vid, pid, serialFromId);
                if (p == null)
                    return false;

                // Match against each entry
                foreach (var entry in entries)
                {
                    if (EntryMatches(entry, p))
                    {
                        Debug.WriteLine($"[EarlyWhitelist] MATCH for {instanceId} → entry '{entry.FriendlyLabel}'");
                        return true;
                    }
                }

                Debug.WriteLine($"[EarlyWhitelist] No match for {instanceId} (VID={vid} PID={pid} Serial={p.SerialNumber})");
                return false;
            }
            catch (Exception ex)
            {
                // ANY exception → fail closed. Device gets frozen.
                Debug.WriteLine($"[EarlyWhitelist] Exception in IsEarlyWhitelisted: {ex.Message} → fail closed");
                return false;
            }
        }

        /// <summary>
        /// Add a device to the early whitelist. Call this from the Allow path
        /// (after user approves and full fingerprint is captured).
        /// Pass descriptor hashes from DeviceFingerprint for maximum clone resistance.
        /// </summary>
        public void AddEntry(EarlyWhitelistEntry entry)
        {
            if (entry == null) throw new ArgumentNullException(nameof(entry));
            lock (_lock)
            {
                // Remove existing entry for same device (update)
                _entries.RemoveAll(e =>
                    string.Equals(e.Vid, entry.Vid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(e.Pid, entry.Pid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(e.SerialNumber, entry.SerialNumber, StringComparison.OrdinalIgnoreCase));
                _entries.Add(entry);
                Save();
            }
        }

        /// <summary>
        /// Remove all whitelist entries for a given VID:PID[:serial].
        /// </summary>
        public void RemoveEntry(string vid, string pid, string serialNumber = null)
        {
            lock (_lock)
            {
                _entries.RemoveAll(e =>
                    string.Equals(e.Vid, vid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(e.Pid, pid, StringComparison.OrdinalIgnoreCase) &&
                    (serialNumber == null ||
                     string.Equals(e.SerialNumber, serialNumber, StringComparison.OrdinalIgnoreCase)));
                Save();
            }
        }

        // ── Registry param reading ───────────────────────────────────────────────

        private static EarlyDeviceParams ReadRegistryParams(
            string instanceId, string vid, string pid, string serialFromId)
        {
            // instanceId for registry: strip "USB\" prefix if present, use as-is for key
            // Registry path: HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_x&PID_x\{serial}
            // instanceId is already in form USB\VID_xxxx&PID_xxxx\serial
            // Registry key uses the last two segments: VID_x&PID_x and serial

            string vidPidKey = $"VID_{vid}&PID_{pid}";
            string regPath = $@"SYSTEM\CurrentControlSet\Enum\USB\{vidPidKey}\{serialFromId}";

            try
            {
                using RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key == null)
                {
                    Debug.WriteLine($"[EarlyWhitelist] Registry key not found: {regPath}");
                    return null;
                }

                var p = new EarlyDeviceParams
                {
                    Vid = vid,
                    Pid = pid,
                    SerialNumber = serialFromId,
                };

                // ── TIER 3: available immediately ────────────────────────────────

                // HardwareId[0] includes REV_ (firmware revision) — hard to clone
                // without same exact firmware build
                var hwIds = key.GetValue("HardwareID") as string[];
                if (hwIds != null && hwIds.Length > 0)
                    p.HardwareIdFull = hwIds[0];  // e.g. "USB\VID_0951&PID_1666&REV_0100"

                // CompatibleIds reveal true device class (Rubber Ducky may differ)
                var compatIds = key.GetValue("CompatibleIDs") as string[];
                if (compatIds != null && compatIds.Length > 0)
                    p.CompatibleIdPrimary = compatIds[0];

                // LocationInformation = physical port path — stable for fixed devices
                p.LocationInformation = key.GetValue("LocationInformation") as string;

                // Service driver — "usbstor" for storage, "kbdhid" for keyboard etc.
                p.Service = key.GetValue("Service") as string;

                // ── TIER 2: stable, firmware-derived ─────────────────────────────

                // ParentIdPrefix — Windows-internal ID derived from serial + hub topology
                // Different machines may differ, but on SAME machine, stable per device
                p.ParentIdPrefix = key.GetValue("ParentIdPrefix") as string;

                // ── TIER 1 (partial): ContainerID ────────────────────────────────
                // ContainerID is a GUID. Windows derives it from iSerialNumber.
                // Same serial → same ContainerID. Attacker must know the serial to clone.
                // Format in registry: "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
                string containerIdStr = key.GetValue("ContainerID") as string;
                if (!string.IsNullOrWhiteSpace(containerIdStr) &&
                    Guid.TryParse(containerIdStr, out Guid cid) &&
                    cid != Guid.Empty)
                {
                    p.ContainerId = cid;
                }

                // ClassGUID (device setup class) — sanity cross-check
                p.ClassGuid = key.GetValue("ClassGUID") as string;

                Debug.WriteLine($"[EarlyWhitelist] Params for {instanceId}:");
                Debug.WriteLine($"  HardwareId   = {p.HardwareIdFull}");
                Debug.WriteLine($"  CompatId     = {p.CompatibleIdPrimary}");
                Debug.WriteLine($"  ContainerId  = {p.ContainerId}");
                Debug.WriteLine($"  ParentPrefix = {p.ParentIdPrefix}");
                Debug.WriteLine($"  Location     = {p.LocationInformation}");
                Debug.WriteLine($"  Service      = {p.Service}");

                return p;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[EarlyWhitelist] ReadRegistryParams exception: {ex.Message}");
                return null;  // fail closed
            }
        }

        // ── Matching logic ───────────────────────────────────────────────────────

        private static bool EntryMatches(EarlyWhitelistEntry entry, EarlyDeviceParams p)
        {
            // MUST match: VID + PID
            if (!string.Equals(entry.Vid, p.Vid, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!string.Equals(entry.Pid, p.Pid, StringComparison.OrdinalIgnoreCase))
                return false;

            // MUST match if stored: SerialNumber (iSerialNumber from device descriptor)
            // This is the primary uniqueness anchor. If a device has a serial, we require it.
            if (!string.IsNullOrWhiteSpace(entry.SerialNumber))
            {
                if (!string.Equals(entry.SerialNumber, p.SerialNumber, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            else
            {
                // Entry has no serial → device had no iSerialNumber.
                // In this case serial from instanceId is a Windows-generated hash (e.g. "5&3abc&0&1").
                // We still require it matches (Windows generates same hash per port per device).
                if (!string.Equals(entry.InstanceSerial, p.SerialNumber, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // MUST match if stored: HardwareId including REV_ (firmware revision)
            if (!string.IsNullOrWhiteSpace(entry.HardwareIdFull) &&
                !string.Equals(entry.HardwareIdFull, p.HardwareIdFull, StringComparison.OrdinalIgnoreCase))
                return false;

            // MUST match if stored: ContainerID (GUID derived from serial)
            if (entry.ContainerId.HasValue && entry.ContainerId != Guid.Empty)
            {
                if (!p.ContainerId.HasValue || p.ContainerId != entry.ContainerId)
                    return false;
            }

            // MUST match if stored: CompatibleId[0] — prevents Rubber Ducky spoofing
            // a storage device (Ducky will have keyboard-class CompatibleId)
            if (!string.IsNullOrWhiteSpace(entry.CompatibleIdPrimary))
            {
                if (!string.Equals(entry.CompatibleIdPrimary, p.CompatibleIdPrimary, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // MUST match if stored: Service — symmetric check against WHATEVER the
            // whitelisted device actually uses ("usbstor", "kbdhid", "USBHUB", etc.).
            // Whitelisted keyboard → entry.Service="kbdhid" → legit keyboard passes.
            // Whitelisted storage  → entry.Service="usbstor" → Ducky with "kbdhid" fails here.
            // Ducky vs whitelisted keyboard → both "kbdhid" → passes this, fails serial above.
            if (!string.IsNullOrWhiteSpace(entry.Service))
            {
                if (!string.Equals(entry.Service, p.Service, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // OPTIONAL check: DescriptorHash (from full fingerprint, stored after first Allow)
            // If present, it's a strong anti-clone signal. Mismatch → reject.
            if (!string.IsNullOrWhiteSpace(entry.DescriptorHash) &&
                !string.IsNullOrWhiteSpace(p.DescriptorHash))
            {
                if (!string.Equals(entry.DescriptorHash, p.DescriptorHash, StringComparison.Ordinal))
                    return false;
            }

            // OPTIONAL check: HidReportDescriptorHash — strongest anchor for HID devices.
            // Mouse vs keyboard are fundamentally different at HID report level.
            // Ducky cannot fake mouse report descriptor — it IS a keyboard.
            // Only checked if both sides have the value (populated after first Allow
            // once HidReportDescriptorReader is implemented).
            if (!string.IsNullOrWhiteSpace(entry.HidReportDescriptorHash) &&
                !string.IsNullOrWhiteSpace(p.HidReportDescriptorHash))
            {
                if (!string.Equals(entry.HidReportDescriptorHash, p.HidReportDescriptorHash, StringComparison.Ordinal))
                    return false;
            }

            // OPTIONAL: ParentIdPrefix — stable on same machine, used as extra signal
            // Don't hard-reject on mismatch (can change after port switch), but log it.
            if (!string.IsNullOrWhiteSpace(entry.ParentIdPrefix) &&
                !string.IsNullOrWhiteSpace(p.ParentIdPrefix) &&
                !string.Equals(entry.ParentIdPrefix, p.ParentIdPrefix, StringComparison.OrdinalIgnoreCase))
            {
                Debug.WriteLine($"[EarlyWhitelist] ParentIdPrefix mismatch (soft): entry='{entry.ParentIdPrefix}' device='{p.ParentIdPrefix}' — continuing (port may have changed)");
                // Soft — don't block. Device may have been moved to different port.
                // If you want strict physical-port locking, change to: return false;
            }

            return true;
        }

        // ── Build entry from full DeviceFingerprint (call this on Allow path) ────

        /// <summary>
        /// Build an EarlyWhitelistEntry from a full DeviceFingerprint.
        /// Call this after the user clicks Allow and CaptureAllIdentifiers has run.
        /// The entry stores all hard-to-clone params for future T+10ms matching.
        /// </summary>
        public static EarlyWhitelistEntry BuildEntry(DeviceFingerprint fp, string label = null)
        {
            if (fp == null) throw new ArgumentNullException(nameof(fp));

            // Parse serial vs instance-hash from instanceId.
            // fp.InstanceId may be just the serial segment (e.g. "A8F3291C")
            // or full path ("USB\VID_xxxx&PID_xxxx\A8F3291C") — handle both.
            string instanceIdFull = fp.InstanceId?.Contains('\\') == true
                ? fp.InstanceId
                : $"USB\\VID_{fp.Vid}&PID_{fp.Pid}\\{fp.InstanceId}";
            ParseInstanceId(instanceIdFull, out _, out _, out string serialFromId);

            bool hasTrueSerial = !string.IsNullOrWhiteSpace(fp.SerialNumber) &&
                                 !IsWindowsGeneratedSerial(fp.SerialNumber);

            // DeviceFingerprint field names vary across codebase versions.
            // Use null-safe access for every optional field — BuildEntry must
            // never throw regardless of which fingerprint fields are populated.
            string hardwareIdFirst = null;
            try { hardwareIdFirst = fp.HardwareIds?.Count > 0 ? fp.HardwareIds[0] : null; }
            catch { /* field may not exist in this build */ }

            string compatIdFirst = null;
            try { compatIdFirst = fp.CompatibleIds?.Count > 0 ? fp.CompatibleIds[0] : null; }
            catch { /* field may not exist in this build */ }

            Guid? containerId = null;
            try
            {
                // DeviceFingerprint.ContainerId is a string e.g. "{a3f2-bc91-...}"
                string cidStr = fp.ContainerId;
                if (!string.IsNullOrWhiteSpace(cidStr) && Guid.TryParse(cidStr, out Guid g) && g != Guid.Empty)
                    containerId = g;
            }
            catch { }

            string parentIdPrefix = null;
            try { parentIdPrefix = fp.ParentIdPrefix; }
            catch { }

            string bosHash = null;
            try { bosHash = fp.BosHash; }
            catch { }

            string hidReportHash = null;
            // HidReportDescriptorHash is a future field — DeviceFingerprint doesn't have it yet.
            // When you add IOCTL_HID_GET_REPORT_DESCRIPTOR capture, set fp.HidReportDescriptorHash
            // and uncomment the line below:
            // try { hidReportHash = fp.HidReportDescriptorHash; } catch { }

            var entry = new EarlyWhitelistEntry
            {
                Vid = fp.Vid,
                Pid = fp.Pid,
                FriendlyLabel = label ?? fp.Description ?? $"USB {fp.Vid}:{fp.Pid}",
                ApprovedAtUtc = DateTime.UtcNow,

                // Tier 1 anchors — strongest, requires hub IOCTL (populated after Allow)
                DescriptorHash = fp.DescriptorHash,   // SHA256 of all USB descriptor bytes
                BosHash = bosHash,             // USB 3.x only
                ContainerId = containerId,         // GUID derived from iSerialNumber
                HidReportDescriptorHash = hidReportHash,     // future: IOCTL_HID_GET_REPORT_DESCRIPTOR

                // Tier 2 anchors — firmware-set, requires re-flash to change
                SerialNumber = hasTrueSerial ? fp.SerialNumber : null,
                InstanceSerial = serialFromId,
                ParentIdPrefix = parentIdPrefix,

                // Tier 3 anchors — registry-readable at T+10ms
                HardwareIdFull = hardwareIdFirst,
                CompatibleIdPrimary = compatIdFirst,
                Service = fp.Service,
            };

            return entry;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Parse instanceId "USB\VID_xxxx&PID_xxxx\{serialOrHash}" into components.
        /// </summary>
        private static bool ParseInstanceId(
            string instanceId, out string vid, out string pid, out string serial)
        {
            vid = pid = serial = null;
            if (string.IsNullOrWhiteSpace(instanceId)) return false;

            // Normalize slashes
            string norm = instanceId.Replace('/', '\\');

            // Strip leading "USB\" segment if present
            string[] parts = norm.Split('\\');
            // Expected: ["USB", "VID_xxxx&PID_xxxx", "serial"]
            // or:       ["VID_xxxx&PID_xxxx", "serial"]  (already stripped)

            string vidPidPart = null;
            string serialPart = null;

            if (parts.Length >= 3 &&
                parts[0].Equals("USB", StringComparison.OrdinalIgnoreCase))
            {
                vidPidPart = parts[1];
                serialPart = parts[2];
            }
            else if (parts.Length >= 2)
            {
                vidPidPart = parts[0];
                serialPart = parts[1];
            }

            if (vidPidPart == null) return false;

            int vidIdx = vidPidPart.IndexOf("VID_", StringComparison.OrdinalIgnoreCase);
            int pidIdx = vidPidPart.IndexOf("PID_", StringComparison.OrdinalIgnoreCase);
            if (vidIdx < 0 || pidIdx < 0 || pidIdx < vidIdx + 8) return false;

            vid = vidPidPart.Substring(vidIdx + 4, 4);
            pid = vidPidPart.Substring(pidIdx + 4, 4);
            serial = serialPart ?? string.Empty;
            return true;
        }

        /// <summary>
        /// Windows generates a serial like "5&3a8f1b2c&0&1" when device has no iSerialNumber.
        /// These start with a digit and contain "&".
        /// True hardware serials are typically alphanumeric without "&".
        /// </summary>
        private static bool IsWindowsGeneratedSerial(string serial)
        {
            if (string.IsNullOrWhiteSpace(serial)) return true;
            return serial.Contains('&');
        }

        // ── Persistence ──────────────────────────────────────────────────────────

        private void ReloadIfStale()
        {
            lock (_lock)
            {
                if ((DateTime.UtcNow - _lastLoadTime).TotalSeconds < ReloadIntervalSeconds)
                    return;
            }
            Load();
        }

        private void Load()
        {
            lock (_lock)
            {
                try
                {
                    if (!File.Exists(_whitelistPath))
                    {
                        _entries = new List<EarlyWhitelistEntry>();
                        _lastLoadTime = DateTime.UtcNow;
                        return;
                    }
                    string json = File.ReadAllText(_whitelistPath);
                    var loaded = JsonSerializer.Deserialize<List<EarlyWhitelistEntry>>(json,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    _entries = loaded ?? new List<EarlyWhitelistEntry>();
                    _lastLoadTime = DateTime.UtcNow;
                    Debug.WriteLine($"[EarlyWhitelist] Loaded {_entries.Count} entries from {_whitelistPath}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[EarlyWhitelist] Load failed: {ex.Message}");
                    _entries = new List<EarlyWhitelistEntry>();
                    _lastLoadTime = DateTime.UtcNow;
                }
            }
        }

        private void Save()
        {
            // Already called inside lock(_lock)
            try
            {
                string json = JsonSerializer.Serialize(_entries,
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_whitelistPath, json);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[EarlyWhitelist] Save failed: {ex.Message}");
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    //  Data structures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Params collected from registry at T+10ms — no WMI, no IOCTL.
    /// This is what we have during the PnP callback race window.
    /// </summary>
    internal sealed class EarlyDeviceParams
    {
        public string Vid { get; set; }
        public string Pid { get; set; }
        public string SerialNumber { get; set; }  // from instanceId (may be Windows-generated)
        public string HardwareIdFull { get; set; }  // VID_x&PID_x&REV_x — includes firmware rev
        public string CompatibleIdPrimary { get; set; } // device class hint
        public string LocationInformation { get; set; } // Port_#NNNN.Hub_#NNNN
        public string Service { get; set; }  // usbstor / kbdhid / etc.
        public string ParentIdPrefix { get; set; }
        public Guid? ContainerId { get; set; }  // GUID derived from serial
        public string ClassGuid { get; set; }
        public string DescriptorHash { get; set; }  // only available post-IOCTL; null at T+10ms
        public string HidReportDescriptorHash { get; set; }  // only available post-IOCTL; null at T+10ms
    }

    /// <summary>
    /// Whitelist entry. Stored as JSON. Each field is a separate anti-clone anchor.
    /// More fields filled in → harder to clone.
    /// Minimum viable entry: Vid + Pid + (SerialNumber or InstanceSerial) + HardwareIdFull.
    /// Ideal entry: all fields from BuildEntry() after full fingerprint capture.
    /// </summary>
    public sealed class EarlyWhitelistEntry
    {
        // ── Identity ─────────────────────────────────────────────────────────────
        public string Vid { get; set; }
        public string Pid { get; set; }
        public string FriendlyLabel { get; set; }
        public DateTime ApprovedAtUtc { get; set; }

        // ── Tier 1: hardware-burned, hardest to clone ─────────────────────────
        /// <summary>
        /// SHA256 of HID Report Descriptor bytes (IOCTL_HID_GET_REPORT_DESCRIPTOR).
        /// Mouse report descriptor describes XY axes + buttons + scroll wheel.
        /// Keyboard report descriptor describes key matrix.
        /// These are FUNDAMENTALLY different — a Ducky cannot fake a mouse report descriptor
        /// because it IS a keyboard internally. Strongest possible anchor for HID devices.
        /// Populated by HidReportDescriptorReader (future) after first Allow.
        /// Null until then — matching skipped if null on either side.
        /// </summary>
        public string HidReportDescriptorHash { get; set; }

        /// <summary>
        /// SHA256 of full USB descriptor tree (device + config + interface + endpoint bytes).
        /// Requires hub IOCTL — only stored after first full Allow. Null until then.
        /// If attacker clones VID/PID but uses different firmware, this will differ.
        /// </summary>
        public string DescriptorHash { get; set; }

        /// <summary>
        /// SHA256 of BOS (Binary Object Store) descriptor. USB 3.x only.
        /// Contains device capability GUIDs — very hard to replicate exactly.
        /// </summary>
        public string BosHash { get; set; }

        /// <summary>
        /// ContainerID GUID. Windows derives from iSerialNumber.
        /// Same serial → same GUID on same machine. Attacker needs the serial to clone.
        /// </summary>
        [JsonConverter(typeof(NullableGuidConverter))]
        public Guid? ContainerId { get; set; }

        // ── Tier 2: firmware-set, requires re-flash to change ────────────────
        /// <summary>
        /// iSerialNumber string from USB device descriptor. Null if device has none.
        /// </summary>
        public string SerialNumber { get; set; }

        /// <summary>
        /// The serial portion of the instanceId (may be Windows-generated hash if
        /// device has no iSerialNumber). Stable per device on same machine.
        /// </summary>
        public string InstanceSerial { get; set; }

        /// <summary>
        /// Windows-internal ParentIdPrefix. Derived from serial + hub topology.
        /// Stable per device on same machine. Soft-checked (port changes affect it).
        /// </summary>
        public string ParentIdPrefix { get; set; }

        // ── Tier 3: registry-readable immediately, stable ────────────────────
        /// <summary>
        /// HardwareId[0] = "USB\VID_xxxx&PID_xxxx&REV_xxxx" — includes firmware revision.
        /// Rubber Ducky with different firmware revision will fail this check.
        /// </summary>
        public string HardwareIdFull { get; set; }

        /// <summary>
        /// CompatibleIds[0] — device class hint. A Rubber Ducky masquerading as
        /// a storage device will have keyboard CompatibleId, not storage.
        /// </summary>
        public string CompatibleIdPrimary { get; set; }

        /// <summary>
        /// Windows driver service: "usbstor" / "kbdhid" / "USBHUB" etc.
        /// Rubber Ducky always loads kbdhid. A whitelisted storage drive → usbstor.
        /// Mismatch = immediate reject.
        /// </summary>
        public string Service { get; set; }
    }

    // ── Tiny JSON converter for nullable Guid ────────────────────────────────────
    internal sealed class NullableGuidConverter : JsonConverter<Guid?>
    {
        public override Guid? Read(ref Utf8JsonReader reader, Type t, JsonSerializerOptions o)
        {
            if (reader.TokenType == JsonTokenType.Null) { return null; }
            string s = reader.GetString();
            return Guid.TryParse(s, out Guid g) ? g : (Guid?)null;
        }
        public override void Write(Utf8JsonWriter writer, Guid? value, JsonSerializerOptions o)
        {
            if (value.HasValue) writer.WriteStringValue(value.Value.ToString("B"));
            else writer.WriteNullValue();
        }
    }
}