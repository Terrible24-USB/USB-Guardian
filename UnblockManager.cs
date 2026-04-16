using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Result of an <see cref="UnblockManager.UnblockDevice"/> call.
    /// </summary>
    public class UnblockResult
    {
        /// <summary>Human-readable messages, one per action attempted.</summary>
        public List<string> Messages { get; set; } = new();

        /// <summary>
        /// True when the device node could not be immediately re-enumerated by the OS
        /// and the user should unplug and reconnect the device to complete recovery.
        /// </summary>
        public bool NeedsReplug { get; set; } = true;
    }

    /// <summary>
    /// Reverses block operations that were recorded in a <see cref="BlockedDeviceRecord"/>.
    ///
    /// Safety design:
    /// - Only touches registry keys/values that were explicitly recorded at block time.
    ///   Nothing is changed unless the original value was captured in <see cref="BlockActionRecord"/>.
    /// - Does NOT use hardcoded service Start defaults; always restores the captured previous value.
    /// - Legacy recovery (<see cref="RestoreLegacyUsbStor"/>) is the sole exception: it uses
    ///   a safe hardcoded default (3 = Demand/Manual) only when no previous value was recorded.
    /// - <see cref="DryRun"/> mode: when true, every action is logged but no system changes are made.
    ///   Enable via the <c>USB_GUARDIAN_DRY_RUN=1</c> environment variable or by setting the property.
    /// </summary>
    public class UnblockManager
    {
        // ConfigFlags bits added by USB Guardian at block time
        private const int ConfigFlagDisabled  = 0x100;
        private const int ConfigFlagReinstall = 0x40;

        // Timing constants for post-unblock device verification
        // ConfigFlags changes need a brief delay before Windows processes them.
        private const int ConfigFlagsProcessingDelayMs = 500;
        // After re-enumeration, Windows may need extra time to bind drivers.
        private const int ReEnumerationDelayMs = 800;

        // CfgMgr32 P/Invoke for device re-enumeration
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string? pDeviceID, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Reenumerate_DevNode(uint dnDevInst, uint ulFlags);

        private const int  CR_SUCCESS                = 0;
        private const uint CM_LOCATE_DEVNODE_NORMAL  = 0;
        private const uint CM_REENUMERATE_NORMAL     = 0;

        private readonly BlockedDeviceStore _store;
        private readonly SecurityEventLogger _logger;

        /// <summary>
        /// When true, all actions are logged but no system changes are made.
        /// Activated by the USB_GUARDIAN_DRY_RUN=1 environment variable, or
        /// by setting this property directly.
        /// </summary>
        public bool DryRun { get; set; }

        public UnblockManager(BlockedDeviceStore store, SecurityEventLogger logger)
        {
            _store = store;
            _logger = logger;
            DryRun = string.Equals(
                Environment.GetEnvironmentVariable("USB_GUARDIAN_DRY_RUN"),
                "1",
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Reverse all block actions recorded for <paramref name="record"/>.
        /// After successful completion the record is removed from the store.
        /// </summary>
        public UnblockResult UnblockDevice(BlockedDeviceRecord record)
        {
            var result = new UnblockResult();
            if (record == null) return result;

            string vidPid = $"{record.Vid}:{record.Pid}";
            string dryTag = DryRun ? " [DRY RUN]" : string.Empty;
            _logger.LogInfo(0, "Unblock", $"Unblocking {vidPid} ({record.Description}){dryTag}", vidPid);

            bool wmiDoneExplicitly = false;

            // Sort actions so critical restorations happen in the correct order:
            //   0 – ServiceStart for "usbstor" (restore the global storage driver first)
            //   1 – other ServiceStart actions
            //   2 – ConfigFlags (per-device registry)
            //   3 – WmiDisable (re-enable the device node last)
            var orderedActions = record.Actions
                .OrderBy(a =>
                {
                    if (a.ActionType == "ServiceStart" &&
                        string.Equals(a.ServiceName, "usbstor", StringComparison.OrdinalIgnoreCase))
                        return 0;
                    if (a.ActionType == "ServiceStart") return 1;
                    if (a.ActionType == "ConfigFlags")  return 2;
                    if (a.ActionType == "WmiDisable")   return 3;
                    return 4;
                })
                .ToList();

            foreach (var action in orderedActions)
            {
                try
                {
                    string msg = action.ActionType switch
                    {
                        "ConfigFlags"  => RestoreConfigFlags(action),
                        "ServiceStart" => RestoreServiceStart(action),
                        "WmiDisable"   => EnableViaWmi(record, ref wmiDoneExplicitly),
                        _              => $"Unknown action type '{action.ActionType}' — skipped"
                    };
                    result.Messages.Add(msg);
                    _logger.LogInfo(0, "UnblockAction",
                        $"{action.ActionType}: {msg}{dryTag}", vidPid);
                }
                catch (Exception ex)
                {
                    string msg = $"Error in '{action.ActionType}': {ex.Message}";
                    result.Messages.Add(msg);
                    Debug.WriteLine($"[UnblockManager] {msg}");
                }
            }

            // Always attempt WMI re-enable even if it was not recorded as an explicit action
            // (e.g., in the UsbStorageBlocker path where WMI disable is done separately).
            if (!wmiDoneExplicitly)
            {
                try
                {
                    bool dummy = false;
                    string wmiResult = EnableViaWmi(record, ref dummy);
                    result.Messages.Add($"WMI re-enable: {wmiResult}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[UnblockManager] WMI enable fallback failed: {ex.Message}");
                }
            }

            // Re-enumeration via cfgmgr32 — give Windows time to process the
            // ConfigFlags change before triggering hardware re-scan.
            if (!DryRun)
                System.Threading.Thread.Sleep(ConfigFlagsProcessingDelayMs);

            bool reEnumOk = TryReEnumerateDevice(record, result.Messages);

            // Wait for Windows to process the re-enumeration, then check whether
            // the device can actually be found in a ready state via WMI.
            if (reEnumOk && !DryRun)
            {
                System.Threading.Thread.Sleep(ReEnumerationDelayMs);
                bool deviceReady = IsDeviceReadyViaWmi(record);
                result.NeedsReplug = !deviceReady;
                if (deviceReady)
                    result.Messages.Add("Device confirmed active — no replug required.");
                else
                    result.Messages.Add("Device not yet visible after re-enumeration — please unplug and replug the device.");
            }
            else
            {
                result.NeedsReplug = !reEnumOk;
            }

            // Remove from the store so it no longer appears in the unblock list
            if (!DryRun)
                _store.Remove(record);

            return result;
        }

        /// <summary>
        /// Returns true if the device described by <paramref name="record"/> can be
        /// found in an enabled (non-error) state via WMI Win32_PnPEntity after an
        /// unblock/re-enumeration cycle.
        /// </summary>
        private static bool IsDeviceReadyViaWmi(BlockedDeviceRecord record)
        {
            if (string.IsNullOrEmpty(record.Vid) || string.IsNullOrEmpty(record.Pid))
                return false;

            try
            {
                // Try exact PnpDeviceId first for fastest lookup
                if (!string.IsNullOrEmpty(record.PnpDeviceId))
                {
                    string exactWql = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{WmiEscape(record.PnpDeviceId)}'";
                    ManagementObjectCollection exactResults = null;
                    try
                    {
                        using var exact = new ManagementObjectSearcher(exactWql);
                        exactResults = exact.Get();
                        foreach (ManagementObject obj in exactResults)
                        {
                            string status = obj["Status"]?.ToString() ?? string.Empty;
                            // "OK" or "Unknown" both indicate the device is present and not in error
                            if (!string.Equals(status, "Error", StringComparison.OrdinalIgnoreCase))
                                return true;
                        }
                    }
                    finally
                    {
                        exactResults?.Dispose();
                    }
                }

                // Broad VID/PID search as fallback
                string broadWql = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{record.Vid}&PID_{record.Pid}%'";
                ManagementObjectCollection broadResults = null;
                try
                {
                    using var broad = new ManagementObjectSearcher(broadWql);
                    broadResults = broad.Get();
                    foreach (ManagementObject obj in broadResults)
                    {
                        string status = obj["Status"]?.ToString() ?? string.Empty;
                        if (!string.Equals(status, "Error", StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
                finally
                {
                    broadResults?.Dispose();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UnblockManager] IsDeviceReadyViaWmi error: {ex.Message}");
            }
            return false;
        }

        /// <summary>
        /// Clears the USB Guardian block bits (0x100 and 0x40) from ConfigFlags on the
        /// device's likely registry paths, even when no actions were formally recorded
        /// (legacy / pre-record-era blocks).
        ///
        /// Only bits 0x100 and 0x40 are cleared; no other flags are modified.
        /// Returns a list of human-readable result strings.
        /// </summary>
        public List<string> ClearLegacyConfigFlags(BlockedDeviceRecord record)
        {
            var results = new List<string>();
            if (record == null) return results;

            string dryTag = DryRun ? " [DRY RUN]" : string.Empty;
            _logger.LogInfo(0, "LegacyClear",
                $"Clearing legacy ConfigFlags for {record.Vid}:{record.Pid}{dryTag}",
                $"{record.Vid}:{record.Pid}");

            // Collect registry paths to check: recorded ones first, then well-known defaults.
            var paths = record.Actions
                .Where(a => a.ActionType == "ConfigFlags" && !string.IsNullOrEmpty(a.RegistryPath))
                .Select(a => a.RegistryPath)
                .ToList();

            // Add the canonical USB enum path if not already present
            if (!string.IsNullOrEmpty(record.Vid) && !string.IsNullOrEmpty(record.Pid)
                && !string.IsNullOrEmpty(record.InstanceId))
            {
                string canonicalPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{record.Vid}&PID_{record.Pid}\{record.InstanceId}";
                if (!paths.Contains(canonicalPath, StringComparer.OrdinalIgnoreCase))
                    paths.Add(canonicalPath);
            }

            // Add USBSTOR child path from PnpDeviceId if it looks like a USBSTOR path
            if (!string.IsNullOrEmpty(record.PnpDeviceId)
                && record.PnpDeviceId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase))
            {
                string storPath = $@"SYSTEM\CurrentControlSet\Enum\{record.PnpDeviceId.Replace('/', '\\')}";
                if (!paths.Contains(storPath, StringComparer.OrdinalIgnoreCase))
                    paths.Add(storPath);
            }

            if (paths.Count == 0)
            {
                results.Add("No registry paths to clear (no recorded paths and no InstanceId available).");
                return results;
            }

            foreach (string path in paths)
            {
                try
                {
                    if (DryRun)
                    {
                        results.Add($"[DRY RUN] Would clear bits 0x{ConfigFlagDisabled:X}/0x{ConfigFlagReinstall:X} on {path}");
                        continue;
                    }

                    using var key = Registry.LocalMachine.OpenSubKey(path, writable: true);
                    if (key == null)
                    {
                        results.Add($"Key not found (may be expected for absent device): {path}");
                        continue;
                    }

                    int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                    int cleared = current & ~(ConfigFlagDisabled | ConfigFlagReinstall);
                    key.SetValue("ConfigFlags", cleared, RegistryValueKind.DWord);
                    results.Add($"Cleared ConfigFlags: 0x{current:X} → 0x{cleared:X} on {path}");
                    _logger.LogInfo(0, "LegacyClear",
                        $"ConfigFlags cleared on {path}: 0x{current:X}→0x{cleared:X}",
                        $"{record.Vid}:{record.Pid}");
                }
                catch (Exception ex)
                {
                    results.Add($"Error on {path}: {ex.Message}");
                    Debug.WriteLine($"[UnblockManager.ClearLegacyConfigFlags] {ex.Message}");
                }
            }

            // Trigger a device re-enumeration so Windows can rediscover the restored device
            // without requiring a manual unplug/replug in most cases.
            try
            {
                string rescanResult = TriggerDeviceRescan();
                results.Add($"Re-enumeration: {rescanResult}");
                _logger.LogInfo(0, "DeviceRescan", rescanResult, $"{record.Vid}:{record.Pid}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UnblockManager] Device rescan failed: {ex.Message}");
                results.Add("Re-enumeration: not available — unplug and replug the device if it does not appear");
            }

            return results;
        }

        /// <summary>
        /// Restores the USBSTOR service Start value to <paramref name="targetStart"/>
        /// (default 3 = Demand/Manual) when there is no recorded previous value.
        ///
        /// This is the guided recovery path for legacy blocks created before
        /// blocked_devices.json existed.  A critical event is logged.
        ///
        /// Returns a human-readable result string.
        /// </summary>
        public string RestoreLegacyUsbStor(int targetStart = 3)
        {
            string dryTag = DryRun ? " [DRY RUN]" : string.Empty;

            _logger.LogCritical(0, "LegacyStorageRecovery",
                $"Legacy USBSTOR recovery requested — setting Start={targetStart}{dryTag}",
                null);

            if (DryRun)
                return $"[DRY RUN] Would set HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbstor\\Start = {targetStart}";

            try
            {
                const string svcPath = @"SYSTEM\CurrentControlSet\Services\usbstor";
                using var key = Registry.LocalMachine.OpenSubKey(svcPath, writable: true);
                if (key == null)
                    return @"Service key not found: SYSTEM\CurrentControlSet\Services\usbstor";

                int current = key.GetValue("Start") is int s ? s : -1;
                key.SetValue("Start", targetStart, RegistryValueKind.DWord);

                string msg = $"USBSTOR Start restored: {current} → {targetStart}";
                _logger.LogCritical(0, "LegacyStorageRecovery", msg, null);
                return msg;
            }
            catch (Exception ex)
            {
                string err = $"Failed to restore USBSTOR Start: {ex.Message}";
                _logger.LogCritical(0, "LegacyStorageRecovery", err, null);
                return err;
            }
        }

        /// <summary>
        /// Returns true if the USBSTOR service is currently globally disabled (Start == 4)
        /// AND no blocked-device record contains a ServiceStart(usbstor) action with a
        /// recorded previous value that could be restored through the normal unblock path.
        /// </summary>
        public bool IsLegacyUsbStorBlock()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\usbstor");
                if (key == null) return false;
                if (key.GetValue("Start") is not int start || start != 4) return false;
            }
            catch { return false; }

            // If any record has a ServiceStart usbstor action with a known previous value,
            // the standard unblock path can handle it — not a legacy block.
            return !_store.GetAll().Any(r =>
                r.Actions.Any(a =>
                    a.ActionType == "ServiceStart" &&
                    string.Equals(a.ServiceName, "usbstor", StringComparison.OrdinalIgnoreCase) &&
                    a.PreviousServiceStart.HasValue));
        }

        // ---- Action reversal helpers ----

        private string RestoreConfigFlags(BlockActionRecord action)
        {
            if (string.IsNullOrEmpty(action.RegistryPath))
                return "Skipped: no registry path recorded";

            if (DryRun)
                return $"[DRY RUN] Would restore ConfigFlags on {action.RegistryPath} " +
                       $"(target value: 0x{(action.PreviousConfigFlags ?? 0):X})";

            using var key = Registry.LocalMachine.OpenSubKey(action.RegistryPath, writable: true);
            if (key == null)
                return $"Registry key not found: {action.RegistryPath}";

            // If we captured the previous value, restore it exactly.
            // If not, at minimum clear the bits USB Guardian set.
            int newValue;
            if (action.PreviousConfigFlags.HasValue)
            {
                newValue = action.PreviousConfigFlags.Value;
            }
            else
            {
                int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                newValue = current & ~(ConfigFlagDisabled | ConfigFlagReinstall);
            }

            key.SetValue("ConfigFlags", newValue, RegistryValueKind.DWord);
            return $"Restored ConfigFlags=0x{newValue:X} on {action.RegistryPath}";
        }

        private string RestoreServiceStart(BlockActionRecord action)
        {
            if (string.IsNullOrEmpty(action.ServiceName))
                return "Skipped: no service name recorded";

            if (action.PreviousServiceStart == null)
            {
                bool isUsbStor = string.Equals(action.ServiceName, "usbstor",
                    StringComparison.OrdinalIgnoreCase);
                if (isUsbStor)
                    // Return a sentinel that the UI layer can detect to show a recovery prompt.
                    // Do NOT guess a default — the caller must guide the user to restore manually.
                    return "RECOVERY_REQUIRED: No previous Start value was recorded for the USBSTOR " +
                           "service. USB storage remains disabled. Manual restoration required: " +
                           @"HKLM\SYSTEM\CurrentControlSet\Services\usbstor → Start = 3 (Windows default)";

                return $"Skipped: no previous Start value was recorded for service '{action.ServiceName}'";
            }

            if (DryRun)
                return $"[DRY RUN] Would restore service '{action.ServiceName}' " +
                       $"Start to {action.PreviousServiceStart.Value}";

            string svcPath = $@"SYSTEM\CurrentControlSet\Services\{action.ServiceName}";
            using var svcKey = Registry.LocalMachine.OpenSubKey(svcPath, writable: true);
            if (svcKey == null)
                return $"Service key not found: {svcPath}";

            svcKey.SetValue("Start", action.PreviousServiceStart.Value, RegistryValueKind.DWord);
            return $"Restored service '{action.ServiceName}' Start={action.PreviousServiceStart.Value}";
        }

        /// <summary>
        /// Re-enables one or more device nodes via WMI Win32_PnPEntity.
        ///
        /// Targeting strategy (most-precise first):
        ///  1. Exact match on PnpDeviceId (USB\ level node).
        ///  2. Exact match on InstanceId within the USB\ tree.
        ///  3. LIKE match on VID/PID (catches all interfaces of the same device).
        ///  4. USBSTOR\ child node LIKE match (storage class child).
        /// All matched nodes are enabled so that both the USB composite device and its
        /// Mass Storage child are re-enabled where possible.
        /// </summary>
        private string EnableViaWmi(BlockedDeviceRecord record, ref bool markedDone)
        {
            markedDone = true;

            if (DryRun)
                return $"[DRY RUN] Would enable VID_{record.Vid}&PID_{record.Pid} via WMI";

            var enabled = new List<string>();
            try
            {
                // Build a de-duplicated list of queries to try (most precise first)
                var queries = new List<(string wql, bool exact)>();

                if (!string.IsNullOrEmpty(record.PnpDeviceId))
                    queries.Add(($"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{WmiEscape(record.PnpDeviceId)}'", true));

                // Broad VID/PID LIKE match (catches composite device + all interface nodes)
                queries.Add(($"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{record.Vid}&PID_{record.Pid}%'", false));

                // USBSTOR child node (storage class driver layer)
                queries.Add(($"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USBSTOR%' AND DeviceID LIKE '%VID_{record.Vid}&PID_{record.Pid}%'", false));

                var alreadySeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var (wql, exact) in queries)
                {
                    ManagementObjectCollection results = null;
                    try
                    {
                        using var searcher = new ManagementObjectSearcher(wql);
                        results = searcher.Get();
                        foreach (ManagementObject obj in results)
                        {
                            try
                            {
                                // Defensive check: ensure object is still valid
                                if (obj == null)
                                {
                                    Debug.WriteLine("[UnblockManager] Device object became null before Enable");
                                    continue;
                                }

                                // Try to get DeviceID one more time to validate object is alive
                                string devId = obj["DeviceID"]?.ToString() ?? string.Empty;
                                if (string.IsNullOrEmpty(devId))
                                {
                                    Debug.WriteLine("[UnblockManager] Could not retrieve DeviceID from object");
                                    continue;
                                }

                                if (!alreadySeen.Add(devId)) continue;

                                // Null-safety and exception handling right before the risky invoke
                                try
                                {
                                    obj.InvokeMethod("Enable", null);
                                    enabled.Add(devId);
                                    Debug.WriteLine($"[UnblockManager] Enabled via WMI: {devId}");
                                }
                                catch (InvalidOperationException invalidEx)
                                {
                                    string msg = $"WMI Enable failed for '{devId}' (object no longer available): {invalidEx.Message}";
                                    Debug.WriteLine($"[UnblockManager] {msg}");
                                    _logger.LogInfo(0, "WmiEnableWarning", msg, $"{record.Vid}:{record.Pid}");
                                }
                                catch (ManagementException mex) when (
                                    mex.ErrorCode == ManagementStatus.NotFound ||
                                    mex.ErrorCode == ManagementStatus.InvalidObject ||
                                    mex.ErrorCode == ManagementStatus.InvalidQuery)
                                {
                                    string msg = $"WMI Enable skipped for '{devId}': device no longer available " +
                                                 $"(WMI status: {mex.ErrorCode})";
                                    Debug.WriteLine($"[UnblockManager] {msg}");
                                    _logger.LogInfo(0, "WmiEnableWarning", msg, $"{record.Vid}:{record.Pid}");
                                }
                                catch (ManagementException mex)
                                {
                                    string msg = $"WMI Enable failed for '{devId}' (Management error: {mex.ErrorCode}): {mex.Message}";
                                    Debug.WriteLine($"[UnblockManager] {msg}");
                                    _logger.LogInfo(0, "WmiEnableWarning", msg, $"{record.Vid}:{record.Pid}");
                                }
                                catch (COMException comEx)
                                {
                                    string msg = $"WMI Enable failed for '{devId}' (COM error, device may be disconnected): {comEx.Message}";
                                    Debug.WriteLine($"[UnblockManager] {msg}");
                                    _logger.LogInfo(0, "WmiEnableWarning", msg, $"{record.Vid}:{record.Pid}");
                                }
                                catch (NullReferenceException nre)
                                {
                                    string msg = $"WMI Enable failed for '{devId}' ({nre.GetType().Name}): {nre.Message} " +
                                                 "(device may have been disconnected; skipping this node)";
                                    Debug.WriteLine($"[UnblockManager] {msg}");
                                    _logger.LogInfo(0, "WmiEnableWarning", msg, $"{record.Vid}:{record.Pid}");
                                }
                                catch (Exception ex)
                                {
                                    string msg = $"WMI Enable failed for '{devId}' ({ex.GetType().Name}): {ex.Message} " +
                                                 "(device may already be active or temporarily absent — this is usually harmless)";
                                    Debug.WriteLine($"[UnblockManager] {msg}");
                                    _logger.LogInfo(0, "WmiEnableWarning", msg, $"{record.Vid}:{record.Pid}");
                                }

                                if (exact) break; // only need one result for exact-match queries
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"[UnblockManager] Error processing device in WMI enable loop ({ex.GetType().Name}): {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[UnblockManager] WMI query failed: {ex.Message}");
                    }
                    finally
                    {
                        results?.Dispose();
                    }
                }

                if (enabled.Count == 0)
                    return "Device not found via WMI (may already be active or physically absent)";

                return $"Enabled via WMI ({enabled.Count} node(s)): {string.Join(", ", enabled)}";
            }
            catch (Exception ex)
            {
                return $"WMI enable failed: {ex.Message}";
            }
        }

        /// <summary>
        /// Best-effort re-enumeration of the device node via cfgmgr32
        /// so Windows may bind drivers without a physical unplug/replug.
        /// Returns true if re-enumeration was successfully requested.
        /// </summary>
        private bool TryReEnumerateDevice(BlockedDeviceRecord record, List<string> log)
        {
            if (DryRun)
            {
                log.Add("[DRY RUN] Would attempt cfgmgr32 device re-enumeration");
                return false;
            }

            bool anyOk = false;

            // Try the specific device node by PnpDeviceId first
            if (!string.IsNullOrEmpty(record.PnpDeviceId))
                anyOk |= ReEnumerateNode(record.PnpDeviceId, log);

            // Also try the USB\ level node by InstanceId
            if (!string.IsNullOrEmpty(record.InstanceId) && record.InstanceId != "Unknown")
            {
                string usbPath = $@"USB\VID_{record.Vid}&PID_{record.Pid}\{record.InstanceId}";
                if (!string.Equals(usbPath, record.PnpDeviceId, StringComparison.OrdinalIgnoreCase))
                    anyOk |= ReEnumerateNode(usbPath, log);
            }

            // Always trigger a root-level re-enumeration as a catch-all (scan for hardware changes)
            try
            {
                int cr = CM_Locate_DevNodeW(out uint rootInst, null, CM_LOCATE_DEVNODE_NORMAL);
                if (cr == CR_SUCCESS)
                {
                    CM_Reenumerate_DevNode(rootInst, CM_REENUMERATE_NORMAL);
                    log.Add("Triggered root re-enumeration (scan for hardware changes)");
                    anyOk = true;
                }
                else
                {
                    Debug.WriteLine($"[UnblockManager] CM_Locate_DevNode for root failed: 0x{cr:X}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UnblockManager] Root re-enum failed: {ex.Message}");
            }

            return anyOk;
        }

        private static bool ReEnumerateNode(string deviceInstanceId, List<string> log)
        {
            try
            {
                int cr = CM_Locate_DevNodeW(out uint devInst, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                if (cr != CR_SUCCESS)
                {
                    Debug.WriteLine($"[UnblockManager] CM_Locate_DevNode failed for '{deviceInstanceId}': 0x{cr:X}");
                    return false;
                }
                CM_Reenumerate_DevNode(devInst, CM_REENUMERATE_NORMAL);
                log.Add($"Re-enumerated device node: {deviceInstanceId}");
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UnblockManager] ReEnumerateNode error for '{deviceInstanceId}': {ex.Message}");
                return false;
            }
        }

        private static string WmiEscape(string value)
            => value.Replace("\\", "\\\\").Replace("'", "\\'");

        /// <summary>
        /// Triggers a system-wide device re-enumeration using the CfgMgr32 API so that
        /// Windows rediscovers hardware whose block was just lifted without requiring
        /// the user to physically unplug and replug the device.
        /// </summary>
        private string TriggerDeviceRescan()
        {
            if (DryRun)
                return "[DRY RUN] Would trigger device re-enumeration scan";

            try
            {
                // Locate the root devnode (null device ID = root) then reenumerate its children.
                int cr = CM_Locate_DevNodeW(out uint devInst, null, CM_LOCATE_DEVNODE_NORMAL);
                if (cr == CR_SUCCESS)
                {
                    CM_Reenumerate_DevNode(devInst, CM_REENUMERATE_NORMAL);
                    return "Device re-enumeration scan triggered — Windows will rediscover restored devices";
                }
                return $"Device rescan: CM_Locate_DevNodeW returned code {cr} — unplug and replug the device if it does not appear";
            }
            catch (Exception ex)
            {
                return $"Device rescan not available: {ex.Message} — unplug and replug the device if it does not appear";
            }
        }

        /// <summary>
        /// Escapes WQL LIKE pattern metacharacters (%, _, [) in <paramref name="input"/>
        /// so that the string can be safely embedded in a WQL LIKE clause without
        /// inadvertently matching unintended device IDs.
        /// </summary>
        private static string SanitizeWqlLike(string input)
        {
            var sb = new System.Text.StringBuilder(input.Length * 2);
            foreach (char c in input)
            {
                switch (c)
                {
                    case '%': sb.Append("[%]"); break;
                    case '_': sb.Append("[_]"); break;
                    case '[': sb.Append("[[]"); break;
                    default:  sb.Append(c);    break;
                }
            }
            return sb.ToString();
        }
    }
}
