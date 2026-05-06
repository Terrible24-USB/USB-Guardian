using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace USBGuardian
{
    /// <summary>
    /// Registers a PnP device-interface notification via CM_Register_Notification and
    /// provides CM_Disable_DevNode / CM_Enable_DevNode helpers.
    ///
    /// WHY this is faster than WM_DEVICECHANGE / WMI:
    ///   WM_DEVICECHANGE (DBT_DEVICEARRIVAL) fires after the device stack has fully
    ///   initialised — the HID driver is already loaded and keystroke reports are
    ///   already flowing.  CM_Register_Notification fires from the PnP kernel callback
    ///   before that stack is complete, giving us a 20-40 ms head-start that we use to
    ///   call CM_Disable_DevNode and freeze the device before it can send a single key.
    ///
    ///   WMI fires even later (~200-400 ms) so it is not used for the fast path at all.
    /// </summary>
    internal sealed class PnpDeviceGuard : IDisposable
    {
        // ── CM_NOTIFY_FILTER ────────────────────────────────────────────────────────

        private const int CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE = 0;
        private const int CM_NOTIFY_FILTER_SIZE = 36; // sizeof(CM_NOTIFY_FILTER) on x64

        // ── CM_NOTIFY_ACTION values we care about ───────────────────────────────────
        private const int CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL = 0;

        // ── cfgmgr32 return codes ───────────────────────────────────────────────────
        private const int CR_SUCCESS = 0;

        // ── CM_DISABLE flags ────────────────────────────────────────────────────────
        private const uint CM_DISABLE_UI_NOT_OK = 0x00000001;

        // ── USB device-interface GUID ───────────────────────────────────────────────
        private static readonly Guid GUID_DEVINTERFACE_USB_DEVICE =
            new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED");

        // ── state ───────────────────────────────────────────────────────────────────
        private IntPtr _notifyHandle = IntPtr.Zero;
        private CM_NOTIFY_CALLBACK? _callbackDelegate; // keep-alive to prevent GC
        private bool _disposed;

        /// <summary>
        /// Raised on the PnP thread the moment a new USB device interface arrives.
        /// The string argument is the symbolic device path (\\?\USB\...).
        /// </summary>
        public event Action<string>? DeviceArrived;

        // ── P/Invoke ────────────────────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        private struct CM_NOTIFY_FILTER
        {
            public int cbSize;
            public int Flags;
            public int FilterType;
            public int Reserved;
            // union — for DEVICEINTERFACE we only need the GUID (16 bytes)
            public Guid ClassGuid;
        }

        private delegate int CM_NOTIFY_CALLBACK(
            IntPtr hNotify,
            IntPtr Context,
            int Action,
            IntPtr EventData,
            int EventDataSize);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Register_Notification(
            ref CM_NOTIFY_FILTER pFilter,
            IntPtr pContext,
            CM_NOTIFY_CALLBACK pCallback,
            out IntPtr pNotifyContext);

        [DllImport("CfgMgr32.dll")]
        private static extern int CM_Unregister_Notification(IntPtr NotifyContext);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(
            out uint pdnDevInst,
            string pDeviceID,
            uint ulFlags);

        [DllImport("CfgMgr32.dll")]
        private static extern int CM_Disable_DevNode(uint dnDevInst, uint ulFlags);

        [DllImport("CfgMgr32.dll")]
        private static extern int CM_Enable_DevNode(uint dnDevInst, uint ulFlags);

        // ── public API ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Registers the PnP notification. Safe to call multiple times — only one
        /// registration is kept.
        /// </summary>
        public void Register()
        {
            if (_notifyHandle != IntPtr.Zero) return;

            _callbackDelegate = OnPnpNotification;

            var filter = new CM_NOTIFY_FILTER
            {
                cbSize     = CM_NOTIFY_FILTER_SIZE,
                Flags      = 0,
                FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
                Reserved   = 0,
                ClassGuid  = GUID_DEVINTERFACE_USB_DEVICE
            };

            int cr = CM_Register_Notification(ref filter, IntPtr.Zero, _callbackDelegate,
                                              out _notifyHandle);
            if (cr != CR_SUCCESS)
                Debug.WriteLine($"[PnpDeviceGuard] CM_Register_Notification failed CR=0x{cr:X}");
            else
                Debug.WriteLine("[PnpDeviceGuard] PnP notification registered.");
        }

        /// <summary>
        /// Disables the device node identified by its PnP device-instance ID
        /// (e.g. "USB\\VID_1234&PID_5678\\ABC123").
        /// Returns true on success.
        /// </summary>
        public static bool DisableDevNode(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                int cr = CM_Locate_DevNodeW(out uint devInst, deviceInstanceId, 0);
                if (cr != CR_SUCCESS)
                {
                    Debug.WriteLine($"[PnpDeviceGuard] CM_Locate_DevNodeW failed CR=0x{cr:X} for {deviceInstanceId}");
                    return false;
                }

                cr = CM_Disable_DevNode(devInst, CM_DISABLE_UI_NOT_OK);
                bool ok = cr == CR_SUCCESS;
                Debug.WriteLine(ok
                    ? $"[PnpDeviceGuard] Disabled dev-node: {deviceInstanceId}"
                    : $"[PnpDeviceGuard] CM_Disable_DevNode CR=0x{cr:X} for {deviceInstanceId}");
                return ok;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PnpDeviceGuard] DisableDevNode exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Re-enables the device node after the user clicks Allow.
        /// </summary>
        public static bool EnableDevNode(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                int cr = CM_Locate_DevNodeW(out uint devInst, deviceInstanceId, 0);
                if (cr != CR_SUCCESS) return false;

                cr = CM_Enable_DevNode(devInst, 0);
                bool ok = cr == CR_SUCCESS;
                Debug.WriteLine(ok
                    ? $"[PnpDeviceGuard] Re-enabled dev-node: {deviceInstanceId}"
                    : $"[PnpDeviceGuard] CM_Enable_DevNode CR=0x{cr:X} for {deviceInstanceId}");
                return ok;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PnpDeviceGuard] EnableDevNode exception: {ex.Message}");
                return false;
            }
        }

        // ── private ─────────────────────────────────────────────────────────────────

        private int OnPnpNotification(
            IntPtr hNotify,
            IntPtr Context,
            int Action,
            IntPtr EventData,
            int EventDataSize)
        {
            Debug.WriteLine($"[PnpDeviceGuard] OnPnpNotification Action={Action}");
            try
            {
                if (Action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL)
                {
                    // EventData points to a CM_NOTIFY_EVENT_DATA structure.
                    // The SymbolicLink is a variable-length Unicode string starting at
                    // offset 20 (4 FilterType + 4 Reserved + 16 ClassGuid — on x64 the
                    // struct is naturally aligned so this is reliable).
                    string symLink = ReadSymbolicLink(EventData, EventDataSize);
                    Debug.WriteLine($"[PnpDeviceGuard] Arrival detected: {symLink}");
                    DeviceArrived?.Invoke(symLink ?? string.Empty);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PnpDeviceGuard] Callback exception: {ex.Message}");
            }
            return 0; // CR_SUCCESS
        }

        /// <summary>
        /// Reads the SymbolicLink string from the CM_NOTIFY_EVENT_DATA blob.
        /// Layout: FilterType(4) + Reserved(4) + ClassGuid(16) + SymbolicLink(variable wchar).
        /// </summary>
        private static string? ReadSymbolicLink(IntPtr eventData, int eventDataSize)
        {
            const int offset = 24; // 4 + 4 + 16
            if (eventData == IntPtr.Zero || eventDataSize <= offset) return null;
            try
            {
                return Marshal.PtrToStringUni(eventData + offset);
            }
            catch
            {
                return null;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_notifyHandle != IntPtr.Zero)
            {
                CM_Unregister_Notification(_notifyHandle);
                _notifyHandle = IntPtr.Zero;
            }
        }
    }
}
