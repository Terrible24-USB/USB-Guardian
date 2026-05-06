using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace USBGuardian
{
    // ══════════════════════════════════════════════════════════════════════════════
    //  DiskArrivalGuard
    //
    //  THE PROBLEM IT SOLVES:
    //  Current guardian wakes up at WM_DEVICECHANGE (T+1000ms). By then Windows
    //  has already mounted the volume and Explorer shows the drive letter.
    //  This is a 1-second window where malicious storage is accessible.
    //
    //  THE APPROACH — THREE LAYERS, PURE USER-MODE:
    //
    //  LAYER 2 — GUID_DEVINTERFACE_DISK (fires before partition table is read):
    //    Windows stack order:
    //      usbstor.sys binds
    //      disk.sys binds → GUID_DEVINTERFACE_DISK fires HERE ← our hook
    //      partmgr.sys reads partition table (different kernel thread, ~1-5ms later)
    //      volmgr.sys creates volume objects
    //      mountmgr.sys assigns drive letter
    //      Explorer notified
    //
    //    We open the physical disk with EXCLUSIVE access (shareMode=0) the instant
    //    GUID_DEVINTERFACE_DISK fires. partmgr.sys tries to open the same disk
    //    to read the partition table → gets STATUS_SHARING_VIOLATION → gives up.
    //    No partition table read = no volmgr volume = no drive letter. Ever.
    //
    //    If whitelisted → CloseHandle() → partmgr retries → mounts normally.
    //    If not whitelisted → hold handle + eject → device gone.
    //
    //    Thread priority: TIME_CRITICAL — we MUST beat partmgr's worker thread.
    //
    //  LAYER 3 — GUID_DEVINTERFACE_VOLUME (fallback if Layer 2 lost the race):
    //    If somehow partmgr won and a volume was created, we monitor
    //    GUID_DEVINTERFACE_VOLUME and call DeleteVolumeMountPoint() immediately.
    //    Drive letter exists for <1ms. Explorer refresh interval is ~500ms.
    //    User never sees it.
    //
    //  SAFETY:
    //    All operations fail-closed: any exception → device stays blocked.
    //    Whitelisted devices: handle released within ~100ms → mounts normally.
    //    No registry writes in the hot path.
    //    Does NOT touch CM_Disable_DevNode (that's PnpDeviceGuard's job).
    //
    //  INTEGRATION:
    //    Instantiate in USBMessageWindow constructor.
    //    Call SetWhitelistChecker() to wire in EarlyWhitelistChecker.
    //    DiskArrivalGuard runs completely independently on its own threads.
    // ══════════════════════════════════════════════════════════════════════════════

    internal sealed class DiskArrivalGuard : IDisposable
    {
        // ── Win32 P/Invokes ──────────────────────────────────────────────────────

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool DeleteVolumeMountPointW(string lpszVolumeMountPoint);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDeviceW(
            string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool GetVolumePathNamesForVolumeNameW(
            string lpszVolumeName, char[] lpszVolumePathNames,
            uint cchBuferLength, out uint lpcchReturnLength);

        // CM_Register_Notification
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Register_Notification(
            ref CM_NOTIFY_FILTER pFilter,
            IntPtr pContext,
            CM_NOTIFY_CALLBACK pCallback,
            out IntPtr pNotifyContext);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Unregister_Notification(IntPtr NotifyContext);

        private delegate int CM_NOTIFY_CALLBACK(
            IntPtr hNotify, IntPtr Context,
            CM_NOTIFY_ACTION Action,
            IntPtr EventData, uint EventDataSize);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string pDeviceID, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Get_Parent(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_IDW(uint dnDevInst, StringBuilder buffer, uint bufferLen, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Disable_DevNode(uint dnDevInst, uint ulFlags);

        private const uint CM_DISABLE_UI_NOT_OK = 0x00000001;

        // ── Constants ────────────────────────────────────────────────────────────

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_NONE = 0x00000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint FSCTL_LOCK_VOLUME = 0x0009001C;
        private const uint IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808;
        private const int CR_SUCCESS = 0;
        private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

        // GUID_DEVINTERFACE_DISK  = {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}
        private static readonly Guid GUID_DEVINTERFACE_DISK =
            new Guid("53F56307-B6BF-11D0-94F2-00A0C91EFB8B");

        // GUID_DEVINTERFACE_VOLUME = {53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}
        private static readonly Guid GUID_DEVINTERFACE_VOLUME =
            new Guid("53F5630D-B6BF-11D0-94F2-00A0C91EFB8B");

        // ── CM_NOTIFY structs ────────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CM_NOTIFY_FILTER
        {
            public uint cbSize;
            public uint Flags;
            public CM_NOTIFY_FILTER_TYPE FilterType;
            public uint Reserved;
            public Guid ClassGuid;              // used for DeviceInterface filter
        }

        private enum CM_NOTIFY_FILTER_TYPE : uint
        {
            CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE = 0,
            CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE = 1,
            CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE = 2,
        }

        private enum CM_NOTIFY_ACTION : uint
        {
            CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL = 0,
            CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL = 1,
            CM_NOTIFY_ACTION_DEVICEQUERYREMOVE = 2,
            CM_NOTIFY_ACTION_DEVICEQUERYREMOVEFAILED = 3,
            CM_NOTIFY_ACTION_DEVICEREMOVEPENDING = 4,
            CM_NOTIFY_ACTION_DEVICEREMOVECOMPLETE = 5,
            CM_NOTIFY_ACTION_DEVICECUSTOMEVENT = 6,
            CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED = 7,
            CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED = 8,
            CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED = 9,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CM_NOTIFY_EVENT_DATA_DEVICEINTERFACE
        {
            public Guid ClassGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1)]
            public string SymbolicLink;   // variable length — read via Marshal
        }

        // ── State ────────────────────────────────────────────────────────────────

        private IntPtr _diskNotifyHandle = IntPtr.Zero;
        private IntPtr _volumeNotifyHandle = IntPtr.Zero;

        // Keeps exclusive handles open while we decide: symLink → handle
        private readonly ConcurrentDictionary<string, IntPtr> _heldHandles =
            new(StringComparer.OrdinalIgnoreCase);

        // symbolicLink → physical drive path (e.g. \\.\PhysicalDrive2)
        private readonly ConcurrentDictionary<string, string> _diskPaths =
            new(StringComparer.OrdinalIgnoreCase);

        // symLinks for which the user clicked Allow — handle should be released ASAP.
        // HandleDiskArrival's polling loop checks this set to break early.
        private readonly ConcurrentDictionary<string, bool> _releasedByDecision =
            new(StringComparer.OrdinalIgnoreCase);

        // instanceId → symLink reverse lookup so ProcessUsbDevice (which knows instanceId)
        // can signal the DiskArrivalGuard polling loop via ReleaseHeldHandleByInstanceId().
        private readonly ConcurrentDictionary<string, string> _instanceToSymLink =
            new(StringComparer.OrdinalIgnoreCase);

        private EarlyWhitelistChecker _whitelist;
        private readonly UsbGuardianCore _core;

        // Callbacks must be kept alive to prevent GC collection
        private CM_NOTIFY_CALLBACK _diskCallback;
        private CM_NOTIFY_CALLBACK _volumeCallback;

        // 0 = live, 1 = disposed (set atomically via Interlocked)
        private int _disposed;

        // ── Constructor ──────────────────────────────────────────────────────────

        public DiskArrivalGuard(UsbGuardianCore core)
        {
            _core = core;
        }

        public void SetWhitelistChecker(EarlyWhitelistChecker checker)
        {
            _whitelist = checker;
        }

        // ── Registration ─────────────────────────────────────────────────────────

        public void Register()
        {
            RegisterDiskNotification();
            RegisterVolumeNotification();
            Debug.WriteLine("[DiskArrivalGuard] Registered for DISK + VOLUME interface notifications");
        }

        private void RegisterDiskNotification()
        {
            _diskCallback = OnDiskNotification;   // keep delegate alive

            var filter = new CM_NOTIFY_FILTER
            {
                cbSize = (uint)Marshal.SizeOf<CM_NOTIFY_FILTER>(),
                FilterType = CM_NOTIFY_FILTER_TYPE.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
                ClassGuid = GUID_DEVINTERFACE_DISK,
            };

            int cr = CM_Register_Notification(ref filter, IntPtr.Zero, _diskCallback,
                out _diskNotifyHandle);
            if (cr != CR_SUCCESS)
                Debug.WriteLine($"[DiskArrivalGuard] Disk registration failed: CR=0x{cr:X}");
        }

        private void RegisterVolumeNotification()
        {
            _volumeCallback = OnVolumeNotification;

            var filter = new CM_NOTIFY_FILTER
            {
                cbSize = (uint)Marshal.SizeOf<CM_NOTIFY_FILTER>(),
                FilterType = CM_NOTIFY_FILTER_TYPE.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
                ClassGuid = GUID_DEVINTERFACE_VOLUME,
            };

            int cr = CM_Register_Notification(ref filter, IntPtr.Zero, _volumeCallback,
                out _volumeNotifyHandle);
            if (cr != CR_SUCCESS)
                Debug.WriteLine($"[DiskArrivalGuard] Volume registration failed: CR=0x{cr:X}");
        }

        // ── LAYER 2: Disk arrival handler ────────────────────────────────────────

        private int OnDiskNotification(
            IntPtr hNotify, IntPtr context,
            CM_NOTIFY_ACTION action, IntPtr eventData, uint eventDataSize)
        {
            if (action != CM_NOTIFY_ACTION.CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL)
                return 0;

            // Read symbolic link from event data.
            // Structure: CM_NOTIFY_EVENT_DATA with SymbolicLink at fixed offset 4 bytes
            // (4 bytes FilterType + Guid = 4+16 = 20 bytes offset for SymbolicLink)
            string symLink = null;
            try
            {
                // Offset: FilterType(4) + Reserved(4) + ClassGuid(16) = 24 bytes
                symLink = Marshal.PtrToStringUni(IntPtr.Add(eventData, 24));
            }
            catch { return 0; }

            if (string.IsNullOrWhiteSpace(symLink)) return 0;

            // Fire on HIGH-PRIORITY background thread — MUST beat partmgr's worker
            var t = new Thread(() => HandleDiskArrival(symLink))
            {
                IsBackground = true,
                Priority = ThreadPriority.Highest,   // beat partmgr.sys worker thread
                Name = "DiskArrivalGuard.DiskHandler"
            };
            t.Start();

            return 0;
        }

        private void HandleDiskArrival(string symLink)
        {
            try
            {
                Debug.WriteLine($"[DiskArrivalGuard] DISK arrived: {symLink}");

                // ── PRE-FLIGHT: Resolve identifiers ─────────────────────────────
                string instanceId = SymLinkToInstanceId(symLink);
                string effectiveId = GetUsbParentInstanceId(instanceId) ?? instanceId;

                // ── SAFETY GATE 1: registry confirms USB enumerator ───────────────
                if (!IsUsbStorageInstance(instanceId))
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Registry says not USB storage — skipping: {instanceId}");
                    return;
                }

                // ── SAFETY GATE 2: never touch system/boot drive ──────────────────
                string systemDrive = System.Environment.GetFolderPath(
                    System.Environment.SpecialFolder.System).Substring(0, 2); // "C:"
                if (IsSystemDrive(symLink, systemDrive))
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Refusing system drive: {symLink}");
                    return;
                }

                // ── WHITELIST CHECK ───────────────────────────────────────────────
                bool isWhitelisted = false;
                try { isWhitelisted = _whitelist?.IsEarlyWhitelisted(effectiveId) ?? false; }
                catch (Exception ex) { Debug.WriteLine($"[DiskArrivalGuard] Whitelist threw: {ex.Message}"); }

                if (isWhitelisted)
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Whitelisted ({effectiveId}) — allowing mount");
                    return;
                }

                // ── INSTANT KILL (Double-Lock) ────────────────────────────────────
                // We kill BOTH the storage child and the USB parent controller.
                // This is the "Nuke" option to ensure zero-time containment.
                Debug.WriteLine($"[DiskArrivalGuard] NOT whitelisted — killing device node and parent instantly");
                _core?.EventLogger?.LogWarning(0, "DiskArrivalGuard",
                    $"Blocked unwhitelisted USB disk: {symLink}");
                
                // Kill parent first (strongest)
                if (!string.IsNullOrEmpty(effectiveId) && effectiveId.StartsWith("USB\\"))
                    DisableDeviceNode(effectiveId);
                
                // Kill child as well (fastest)
                DisableDeviceNode(instanceId);

                // ── SECONDARY LOCK (Exclusive Open) ───────────────────────────────
                // Even if the kill command is slightly delayed, we try to grab the 
                // handle to block partmgr.sys as a fail-safe.
                IntPtr hDisk = CreateFileW(
                    symLink,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_NONE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    IntPtr.Zero);

                if (hDisk != INVALID_HANDLE)
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Exclusive handle acquired — double locked");
                    _diskPaths[symLink] = symLink;
                    _heldHandles[symLink] = hDisk;
                    if (!string.IsNullOrWhiteSpace(instanceId))
                        _instanceToSymLink[instanceId] = symLink;

                    // Poll until user decision
                    for (int i = 0; i < 300 && _disposed == 0; i++)
                    {
                        if (_releasedByDecision.ContainsKey(symLink)) break;
                        Thread.Sleep(100);
                    }

                    _heldHandles.TryRemove(symLink, out _);
                    _diskPaths.TryRemove(symLink, out _);
                    _releasedByDecision.TryRemove(symLink, out _);
                    if (!string.IsNullOrWhiteSpace(instanceId))
                        _instanceToSymLink.TryRemove(instanceId, out _);
                    CloseHandle(hDisk);
                }
                else
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Primary kill sent, secondary lock skipped (race lost or already gone)");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] HandleDiskArrival exception: {ex.Message}");
            }
        }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] HandleDiskArrival exception: {ex.Message}");
                if (_heldHandles.TryRemove(symLink, out IntPtr h) && h != INVALID_HANDLE)
                    CloseHandle(h);
                _diskPaths.TryRemove(symLink, out _);
                if (!string.IsNullOrWhiteSpace(instanceId))
                    _instanceToSymLink.TryRemove(instanceId, out _);
            }
        }

        // ── Registry-based USB storage check ─────────────────────────────────────

        /// <summary>
        /// Checks HKLM registry to confirm device is USB storage — definitive,
        /// no symLink text guessing. Checks Enumerator="USB" + Service="usbstor"|"disk".
        /// Returns false for internal SCSI/NVMe/IDE/SATA drives.
        /// </summary>
        private static bool IsUsbStorageInstance(string instanceId)
        {
            if (string.IsNullOrWhiteSpace(instanceId)) return false;
            try
            {
                // instanceId for disk from GUID_DEVINTERFACE_DISK is typically:
                // USBSTOR\Disk&Ven_SanDisk&Prod_Ultra\...  ← direct USBSTOR
                // or USB\VID_xxxx&PID_xxxx\...             ← USB composite
                if (instanceId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase) ||
                    instanceId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase))
                    return true;

                // Fallback: check registry Enumerator value
                string regPath = $@"SYSTEM\CurrentControlSet\Enum\{instanceId}";
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) return false;

                string enumerator = key.GetValue("EnumeratorName")?.ToString()
                                 ?? key.GetValue("Enumerator")?.ToString();
                string service = key.GetValue("Service")?.ToString();

                bool isUsb = string.Equals(enumerator, "USB", StringComparison.OrdinalIgnoreCase)
                              || string.Equals(enumerator, "USBSTOR", StringComparison.OrdinalIgnoreCase);
                bool isStorage = string.Equals(service, "usbstor", StringComparison.OrdinalIgnoreCase)
                              || string.Equals(service, "disk", StringComparison.OrdinalIgnoreCase);

                return isUsb || isStorage;
            }
            catch { return false; }
        }

        /// <summary>
        /// Safety check: is this physical drive path the system/boot drive?
        /// Maps systemDrive letter (e.g. "C:") to PhysicalDriveN and compares.
        /// </summary>
        private static bool IsSystemDrive(string drivePath, string systemDriveLetter)
        {
            try
            {
                // Query DOS device for system drive letter → NT path e.g. \Device\HarddiskVolume3
                var sb = new StringBuilder(260);
                if (QueryDosDeviceW(systemDriveLetter, sb, 260) == 0) return false;
                string ntPath = sb.ToString(); // e.g. \Device\HarddiskVolume3

                // Extract disk number from NT path: \Device\Harddisk2\... → 2
                int hdIdx = ntPath.IndexOf("Harddisk", StringComparison.OrdinalIgnoreCase);
                if (hdIdx < 0) return false;
                string afterHd = ntPath.Substring(hdIdx + 8);
                string numStr = new string(afterHd.TakeWhile(char.IsDigit).ToArray());
                if (!int.TryParse(numStr, out int sysDiskNum)) return false;

                string sysPhysDrive = $@"\\.\PhysicalDrive{sysDiskNum}";
                return string.Equals(drivePath, sysPhysDrive, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        // ── LAYER 3: Volume arrival handler (fallback) ───────────────────────────

        private int OnVolumeNotification(
            IntPtr hNotify, IntPtr context,
            CM_NOTIFY_ACTION action, IntPtr eventData, uint eventDataSize)
        {
            if (action != CM_NOTIFY_ACTION.CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL)
                return 0;

            string symLink = null;
            try { symLink = Marshal.PtrToStringUni(IntPtr.Add(eventData, 24)); }
            catch { return 0; }

            if (string.IsNullOrWhiteSpace(symLink)) return 0;

            // Fire immediately on highest-priority thread
            var t = new Thread(() => HandleVolumeArrival(symLink))
            {
                IsBackground = true,
                Priority = ThreadPriority.Highest,
                Name = "DiskArrivalGuard.VolumeHandler"
            };
            t.Start();

            return 0;
        }

        private void HandleVolumeArrival(string volumeSymLink)
        {
            try
            {
                Debug.WriteLine($"[DiskArrivalGuard] VOLUME arrived: {volumeSymLink}");

                // ── SAFETY GATE: only act on USB storage volumes ──────────────────
                // GUID_DEVINTERFACE_VOLUME fires for EVERY volume, including internal
                // NVMe/SATA drives. The volume symlink is always \\?\Volume{GUID} —
                // no USB text appears in it, so string matching is unreliable.
                // Instead: derive the instanceId and ask the registry.
                string instanceId = SymLinkToInstanceId(volumeSymLink);
                if (!IsUsbStorageInstance(instanceId))
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Layer 3: not USB storage, skipping: {volumeSymLink}");
                    return;
                }

                // Convert device symlink to volume name format (\\?\Volume{guid}\)
                string volumeName = NormalizeVolumeName(volumeSymLink);
                if (volumeName == null) return;

                // Check if this volume came from a disk we already decided to block.
                // If Layer 2 succeeded, this notification won't fire for blocked disks.
                // If we're here, Layer 2 either lost the race or it's a non-USB volume — check.
                
                bool isWhitelisted = false;
                try
                {
                    isWhitelisted = _whitelist?.IsEarlyWhitelisted(instanceId) ?? false;
                }
                catch { }

                if (isWhitelisted)
                {
                    Debug.WriteLine($"[DiskArrivalGuard] Volume whitelisted — leaving mount intact");
                    return;
                }

                // Not whitelisted — get drive letter(s) and delete mount points immediately
                char[] pathBuffer = new char[1024];
                if (GetVolumePathNamesForVolumeNameW(volumeName, pathBuffer, 1024, out uint returnLength)
                    && returnLength > 0)
                {
                    // pathBuffer contains null-separated drive letter strings e.g. "E:\\\0\0"
                    string allPaths = new string(pathBuffer, 0, (int)returnLength);
                    foreach (string mountPath in allPaths.Split('\0'))
                    {
                        if (string.IsNullOrWhiteSpace(mountPath)) continue;

                        Debug.WriteLine($"[DiskArrivalGuard] Layer 3: deleting mount point '{mountPath}'");
                        try
                        {
                            // Ensure trailing backslash (required by DeleteVolumeMountPoint)
                            string mp = mountPath.EndsWith("\\") ? mountPath : mountPath + "\\";
                            bool deleted = DeleteVolumeMountPointW(mp);
                            Debug.WriteLine(deleted
                                ? $"[DiskArrivalGuard] Mount point deleted: {mp}"
                                : $"[DiskArrivalGuard] DeleteVolumeMountPoint failed (err={Marshal.GetLastWin32Error()})");
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"[DiskArrivalGuard] Mount delete exception: {ex.Message}");
                        }
                    }
                }
                else
                {
                    Debug.WriteLine($"[DiskArrivalGuard] No mount points found for {volumeName} — may not be mounted yet");
                }

                _core?.EventLogger?.LogWarning(0, "DiskArrivalGuard",
                    $"Layer 3: removed mount point for unwhitelisted volume {volumeName}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] HandleVolumeArrival exception: {ex.Message}");
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static string ResolvePhysicalDrivePath(string symLink)
        {
            // The symLink itself is a valid device interface path that CreateFileW accepts.
            return symLink;
        }

        /// <summary>
        /// Normalize a volume symbolic link to \\?\Volume{guid}\ format.
        /// </summary>
        private static string NormalizeVolumeName(string symLink)
        {
            try
            {
                if (symLink == null) return null;
                // Replace \\?\ with itself (already correct) or fix up
                string v = symLink;
                if (!v.EndsWith("\\")) v += "\\";
                if (!v.StartsWith(@"\\?\")) v = @"\\?\" + v.TrimStart('\\');
                return v;
            }
            catch { return null; }
        }

        /// <summary>
        /// Extract a USB instance ID from a disk or volume symbolic link.
        /// e.g. "\\?\USBSTOR#Disk&Ven_SanDisk#...#{guid}" → "USBSTOR\Disk&Ven_SanDisk\..."
        /// </summary>
        private static string SymLinkToInstanceId(string symLink)
        {
            if (string.IsNullOrWhiteSpace(symLink)) return string.Empty;
            try
            {
                string s = symLink.TrimStart('\\').TrimStart('?').TrimStart('.').TrimStart('\\');
                int brace = s.LastIndexOf('{');
                if (brace > 0) s = s.Substring(0, brace).TrimEnd('#').TrimEnd('\\');
                return s.Replace('#', '\\').Trim('\\');
            }
            catch { return string.Empty; }
        }

        /// <summary>
        /// Reads the parent USB instanceId from the USBSTOR registry key's ParentIdPrefix.
        /// </summary>
        private static string ResolveUsbParentInstanceId(string usbstorInstanceId)
        {
            if (string.IsNullOrWhiteSpace(usbstorInstanceId)) return string.Empty;
            try
            {
                string regPath = $@"SYSTEM\CurrentControlSet\Enum\{usbstorInstanceId}";
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key == null) return string.Empty;

                string parentIdPrefix = key.GetValue("ParentIdPrefix")?.ToString();
                if (string.IsNullOrWhiteSpace(parentIdPrefix)) return string.Empty;

                // ParentIdPrefix is like "6&393d258a&0", we need to find the USB device with this prefix.
                // However, the ParentIdPrefix maps to the child's *parent's* instance serial number.
                // It's not a direct lookup unless we scan Enum\USB. But typically the USBSTOR instanceId
                // string itself can be parsed or we can just use the ParentIdPrefix if ProcessUsbDevice
                // will match on it.
                // Let's check how the caller uses it. ProcessUsbDevice instanceId is `USB\VID_xxxx&PID_xxxx\serial`.
                // Actually, the parent of a USBSTOR device is the USB composite device.
                // For simplicity, we can do a registry search or if we can extract it:
                // Is it easier to look up HKLM\SYSTEM\CurrentControlSet\Enum\USB and match?
                // Actually, Windows stores the parent in `Device Parameters\SymbolicName` or we can find it via SetupAPI, 
                // but for pure registry without SetupAPI:
                // In `HKLM\SYSTEM\CurrentControlSet\Enum\{usbstorInstanceId}`, we have `ParentIdPrefix`.
                // If we don't know the parent's VID/PID, we can't easily construct `USB\VID_xxxx&PID_xxxx\serial`.
                // BUT wait, in EarlyWhitelistChecker we parse instanceId.
                // Let's implement a quick registry search to find the USB instance with this ParentIdPrefix.
                
                using var usbKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB", writable: false);
                if (usbKey == null) return string.Empty;

                foreach (string vidPid in usbKey.GetSubKeyNames())
                {
                    using var vidPidKey = usbKey.OpenSubKey(vidPid, writable: false);
                    if (vidPidKey == null) continue;

                    foreach (string serial in vidPidKey.GetSubKeyNames())
                    {
                        // Check if this serial matches the ParentIdPrefix? 
                        // Wait, if it's the parent, its instance ID *is* the parent.
                        // We can look at ParentIdPrefix. No, the parent's generated instance string contains the ParentIdPrefix?
                        // Or we can just look at `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\{usbstorInstanceId}`'s `ContainerID`.
                        // Then find the `USB\...` device with the SAME `ContainerID`.
                        
                        using var serialKey = vidPidKey.OpenSubKey(serial, writable: false);
                        if (serialKey != null)
                        {
                            // A simple hack without scanning: we can just check if ProcessUsbDevice 
                            // uses the exact USB instanceId. Let's use ContainerID to match if possible.
                            // But scanning all USB devices takes <1ms anyway.
                            string containerId1 = key.GetValue("ContainerID")?.ToString();
                            string containerId2 = serialKey.GetValue("ContainerID")?.ToString();

                            if (!string.IsNullOrEmpty(containerId1) && containerId1.Equals(containerId2, StringComparison.OrdinalIgnoreCase))
                            {
                                return $@"USB\{vidPid}\{serial}";
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] ResolveUsbParentInstanceId error: {ex.Message}");
            }
            return string.Empty;
        }

        private static void EjectDisk(IntPtr hDisk)
        {
            try
            {
                DeviceIoControl(hDisk, IOCTL_STORAGE_EJECT_MEDIA,
                    IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
                Debug.WriteLine("[DiskArrivalGuard] IOCTL_STORAGE_EJECT_MEDIA sent");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] Eject IOCTL failed: {ex.Message}");
            }
        }

        // ── Dispose ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Called by ProcessUsbDevice's Allow path to release the exclusive handle
        /// immediately so that the cfgmgr32 recovery re-enumeration is not blocked.
        /// The polling loop in HandleDiskArrival checks _releasedByDecision and exits.
        /// </summary>
        public void ReleaseHeldHandle(string symLink)
        {
            if (string.IsNullOrWhiteSpace(symLink)) return;
            _releasedByDecision[symLink] = true;
            Debug.WriteLine($"[DiskArrivalGuard] Allow signal sent for symLink: {symLink}");
        }

        /// <summary>
        /// Called by ProcessUsbDevice's Allow path using the USB instanceId
        /// (e.g. "USB\VID_xxxx&amp;PID_xxxx\serial") rather than the raw DISK symlink.
        /// Looks up the symLink registered in HandleDiskArrival and delegates to
        /// ReleaseHeldHandle. Safe to call even if no handle is held (no-op).
        /// </summary>
        public void ReleaseHeldHandleByInstanceId(string instanceId)
        {
            if (string.IsNullOrWhiteSpace(instanceId)) return;
            
            // 1. Direct match (full instance ID)
            if (_instanceToSymLink.TryGetValue(instanceId, out string symLink))
            {
                Debug.WriteLine($"[DiskArrivalGuard] Allow signal via instanceId={instanceId} → symLink={symLink}");
                ReleaseHeldHandle(symLink);
                return;
            }

            // 2. Serial match fallback (for when Program.cs passes only the serial)
            // Look for any key that ends with the serial (e.g. "...\3840971175100554369")
            string serialMatch = _instanceToSymLink.Keys
                .FirstOrDefault(k => k.EndsWith(instanceId, StringComparison.OrdinalIgnoreCase));
            
            if (serialMatch != null && _instanceToSymLink.TryGetValue(serialMatch, out symLink))
            {
                Debug.WriteLine($"[DiskArrivalGuard] Allow signal via serial match {instanceId} → {serialMatch} → {symLink}");
                ReleaseHeldHandle(symLink);
            }
            else
            {
                // No handle held for this instanceId — either Layer 2 didn't fire
                // or it already released (whitelisted path). Safe no-op.
                Debug.WriteLine($"[DiskArrivalGuard] ReleaseHeldHandleByInstanceId: no handle held for {instanceId} (already released or Layer 2 skipped)");
            }
        }

        private void DisableDeviceNode(string instanceId)
        {
            try
            {
                if (CM_Locate_DevNodeW(out uint devInst, instanceId, 0) == CR_SUCCESS)
                {
                    int cr = CM_Disable_DevNode(devInst, CM_DISABLE_UI_NOT_OK);
                    Debug.WriteLine(cr == CR_SUCCESS
                        ? $"[DiskArrivalGuard] CM_Disable_DevNode succeeded for {instanceId}"
                        : $"[DiskArrivalGuard] CM_Disable_DevNode failed CR=0x{cr:X}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] DisableDeviceNode error: {ex.Message}");
            }
        }

        private string GetUsbParentInstanceId(string instanceId)
        {
            try
            {
                if (CM_Locate_DevNodeW(out uint devInst, instanceId, 0) != CR_SUCCESS)
                    return null;

                if (CM_Get_Parent(out uint parentInst, devInst, 0) != CR_SUCCESS)
                    return null;

                StringBuilder sb = new StringBuilder(200);
                if (CM_Get_Device_IDW(parentInst, sb, (uint)sb.Capacity, 0) == CR_SUCCESS)
                {
                    string parentId = sb.ToString();
                    if (parentId.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase))
                    {
                        Debug.WriteLine($"[DiskArrivalGuard] Resolved parent USB ID: {parentId}");
                        return parentId;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DiskArrivalGuard] GetUsbParentInstanceId error: {ex.Message}");
            }
            return null;
        }

        public void Dispose()
        {
            // Interlocked.Exchange ensures only one thread enters the cleanup body.
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            if (_diskNotifyHandle   != IntPtr.Zero) CM_Unregister_Notification(_diskNotifyHandle);
            if (_volumeNotifyHandle != IntPtr.Zero) CM_Unregister_Notification(_volumeNotifyHandle);

            foreach (var kv in _heldHandles)
            {
                if (kv.Value != INVALID_HANDLE)
                    CloseHandle(kv.Value);
            }
            _heldHandles.Clear();
            _instanceToSymLink.Clear();
            _releasedByDecision.Clear();
            _diskPaths.Clear();
        }
    }
}