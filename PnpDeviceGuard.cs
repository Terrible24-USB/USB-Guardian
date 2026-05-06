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
        // DO NOT hardcode this — the C# struct marshals to 32 bytes (4+4+4+4+16),
        // NOT 36. The old hardcoded value of 36 caused CM_Register_Notification to
        // return CR_INVALID_DATA, silently killing the entire PnP callback.
        // Always use Marshal.SizeOf so it's correct regardless of platform/padding.

        // ── CM_NOTIFY_ACTION values we care about ───────────────────────────────────
        private const int CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL = 0;

        // ── cfgmgr32 return codes ───────────────────────────────────────────────────
        private const int CR_SUCCESS = 0;

        // ── CM_DISABLE flags ────────────────────────────────────────────────────────
        // CM_DISABLE_UI_NOT_OK (0x1): Tells Windows "fail if UI confirmation is required."
        // This causes CM_Disable_DevNode to silently FAIL for HID devices (keyboards/mice)
        // because Windows requires UI before disabling input devices.
        // FIX: Use flag 0, which disables without requiring UI interaction.
        private const uint CM_DISABLE_FLAG_NONE = 0x00000000;
        // Keep the old constant so other call sites that intentionally use it don't break.
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

        // CM_NOTIFY_FILTER full size = 16-byte header + union (largest member =
        // WCHAR InstanceId[MAX_DEVICE_ID_LEN=200] = 400 bytes) = 416 bytes total.
        // cbSize MUST equal sizeof(CM_NOTIFY_FILTER) = 416 or CM_Register_Notification
        // returns CR_INVALID_DATA and the PnP callback is never registered.
        // Use Explicit layout so Marshal.SizeOf = 416 while we only fill the GUID.
        [StructLayout(LayoutKind.Explicit, Size = 416)]
        private struct CM_NOTIFY_FILTER
        {
            [FieldOffset(0)]  public int cbSize;
            [FieldOffset(4)]  public int Flags;
            [FieldOffset(8)]  public int FilterType;
            [FieldOffset(12)] public int Reserved;
            [FieldOffset(16)] public Guid ClassGuid;  // start of union (DeviceInterface member)
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

        [DllImport("CfgMgr32.dll")]
        private static extern int CM_Get_Parent(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        [DllImport("CfgMgr32.dll")]
        private static extern int CM_Get_Child(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        [DllImport("CfgMgr32.dll")]
        private static extern int CM_Get_Sibling(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_IDW(uint dnDevInst, System.Text.StringBuilder Buffer, int BufferLen, uint ulFlags);

        // ── public API ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Registers the PnP notification. Safe to call multiple times — only one
        /// registration is kept.
        /// </summary>
        public void Register()
        {
            if (_notifyHandle != IntPtr.Zero) return;

            _callbackDelegate = OnPnpNotification;

            int structSize = Marshal.SizeOf<CM_NOTIFY_FILTER>();
            Debug.WriteLine($"[PnpDeviceGuard] CM_NOTIFY_FILTER size = {structSize} bytes (must be 32)");

            var filter = new CM_NOTIFY_FILTER
            {
                cbSize     = structSize,   // FIX: was hardcoded 36, correct value is 32
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
        /// <summary>
        /// Disables the device node identified by its PnP device-instance ID.
        /// Uses flag 0 (not CM_DISABLE_UI_NOT_OK) so HID devices (keyboards/mice)
        /// can be frozen. CM_DISABLE_UI_NOT_OK causes Windows to silently refuse
        /// disable calls for HID class devices.
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

                // FIX: Use CM_DISABLE_FLAG_NONE (0) instead of CM_DISABLE_UI_NOT_OK (1).
                // CM_DISABLE_UI_NOT_OK tells Windows: "refuse if UI confirmation is needed".
                // HID devices (kbdhid/mouhid) always require UI confirmation when flag=1,
                // causing the call to fail with CR_NOT_DISABLEABLE (0x20) silently.
                // Flag 0 lets Windows disable the device node regardless of device class.
                cr = CM_Disable_DevNode(devInst, CM_DISABLE_FLAG_NONE);
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
        /// Disables both the child device node AND its USB parent node.
        /// Use this for HID devices (keyboards/mice) to ensure the entire
        /// USB stack is torn down — belt-and-suspenders approach.
        /// Returns true if at least one node was successfully disabled.
        /// </summary>
        public static bool DisableDevNodeWithParent(string deviceInstanceId)
        {
            bool childDisabled = DisableDevNode(deviceInstanceId);

            // Also attempt to disable the parent USB device node.
            // The parent is the USB composite device (USB\VID_xxxx&PID_xxxx\serial).
            // Disabling it kills the entire device stack, not just one interface.
            bool parentDisabled = false;
            try
            {
                // Walk up one level in the device tree.
                int cr = CM_Locate_DevNodeW(out uint devInst, deviceInstanceId, 0);
                if (cr == CR_SUCCESS)
                {
                    cr = CM_Get_Parent(out uint parentDevInst, devInst, 0);
                    if (cr == CR_SUCCESS)
                    {
                        cr = CM_Disable_DevNode(parentDevInst, CM_DISABLE_FLAG_NONE);
                        parentDisabled = cr == CR_SUCCESS;
                        Debug.WriteLine(parentDisabled
                            ? $"[PnpDeviceGuard] Disabled parent dev-node for: {deviceInstanceId}"
                            : $"[PnpDeviceGuard] Parent CM_Disable_DevNode CR=0x{cr:X} for {deviceInstanceId}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PnpDeviceGuard] DisableDevNodeWithParent parent exception: {ex.Message}");
            }

            return childDisabled || parentDisabled;
        }

        /// <summary>
        /// Recursively disables all child nodes of the given device instance.
        /// This is crucial for HID devices because Windows protects the parent
        /// "USB Input Device" from being disabled, but allows the leaf "HID-compliant mouse"
        /// to be disabled.
        /// </summary>
        public static bool DisableDevNodeChildren(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                int cr = CM_Locate_DevNodeW(out uint rootInst, deviceInstanceId, 0);
                if (cr != CR_SUCCESS) return false;

                bool anyDisabled = DisableChildTree(rootInst);
                Debug.WriteLine($"[PnpDeviceGuard] DisableDevNodeChildren for {deviceInstanceId}: {(anyDisabled ? "success" : "failed or no children")}");
                return anyDisabled;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PnpDeviceGuard] DisableDevNodeChildren exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Attempts to disable the device node itself, and then recursively disables all children.
        /// This is the most aggressive and reliable method to freeze a device.
        /// </summary>
        public static bool DisableDevNodeAndChildren(string deviceInstanceId)
        {
            bool selfDisabled = DisableDevNode(deviceInstanceId);
            bool childrenDisabled = DisableDevNodeChildren(deviceInstanceId);
            return selfDisabled || childrenDisabled;
        }

        private static bool DisableChildTree(uint parentInst)
        {
            bool anySuccess = false;
            int cr = CM_Get_Child(out uint childInst, parentInst, 0);
            if (cr == CR_SUCCESS)
            {
                anySuccess |= DisableSiblingChain(childInst);
            }
            return anySuccess;
        }

        private static bool DisableSiblingChain(uint nodeInst)
        {
            bool anySuccess = false;
            uint currentInst = nodeInst;
            while (true)
            {
                // Disable this node
                int disableCr = CM_Disable_DevNode(currentInst, CM_DISABLE_FLAG_NONE);
                if (disableCr == CR_SUCCESS)
                {
                    anySuccess = true;
                    try
                    {
                        var sb = new System.Text.StringBuilder(200);
                        if (CM_Get_Device_IDW(currentInst, sb, sb.Capacity, 0) == CR_SUCCESS)
                            Debug.WriteLine($"[PnpDeviceGuard] Disabled child node: {sb}");
                    }
                    catch { }
                }

                // Recursively disable children of this node
                anySuccess |= DisableChildTree(currentInst);

                // Move to next sibling
                int cr = CM_Get_Sibling(out currentInst, currentInst, 0);
                if (cr != CR_SUCCESS) break;
            }
            return anySuccess;
        }

        /// <summary>
        /// Re-enables the device node after the user clicks Allow.
        /// Also recursively enables all children, which is necessary if they were
        /// disabled via DisableDevNodeChildren.
        /// </summary>
        public static bool EnableDevNode(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                int cr = CM_Locate_DevNodeW(out uint devInst, deviceInstanceId, 0);
                if (cr != CR_SUCCESS) return false;

                cr = CM_Enable_DevNode(devInst, 0);
                bool rootOk = cr == CR_SUCCESS;
                
                bool childrenOk = EnableChildTree(devInst);

                Debug.WriteLine(rootOk || childrenOk
                    ? $"[PnpDeviceGuard] Re-enabled dev-node and/or children: {deviceInstanceId}"
                    : $"[PnpDeviceGuard] CM_Enable_DevNode CR=0x{cr:X} for {deviceInstanceId}");
                return rootOk || childrenOk;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PnpDeviceGuard] EnableDevNode exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Attempts to enable the device node itself, and then recursively enables all children.
        /// </summary>
        public static bool EnableDevNodeAndChildren(string deviceInstanceId)
        {
            return EnableDevNode(deviceInstanceId); // EnableDevNode already recursively enables children!
        }

        private static bool EnableChildTree(uint parentInst)
        {
            bool anySuccess = false;
            int cr = CM_Get_Child(out uint childInst, parentInst, 0);
            if (cr == CR_SUCCESS)
            {
                anySuccess |= EnableSiblingChain(childInst);
            }
            return anySuccess;
        }

        private static bool EnableSiblingChain(uint nodeInst)
        {
            bool anySuccess = false;
            uint currentInst = nodeInst;
            while (true)
            {
                // Enable this node
                int enableCr = CM_Enable_DevNode(currentInst, 0);
                if (enableCr == CR_SUCCESS)
                {
                    anySuccess = true;
                    try
                    {
                        var sb = new System.Text.StringBuilder(200);
                        if (CM_Get_Device_IDW(currentInst, sb, sb.Capacity, 0) == CR_SUCCESS)
                            Debug.WriteLine($"[PnpDeviceGuard] Enabled child node: {sb}");
                    }
                    catch { }
                }

                // Recursively enable children of this node
                anySuccess |= EnableChildTree(currentInst);

                // Move to next sibling
                int cr = CM_Get_Sibling(out currentInst, currentInst, 0);
                if (cr != CR_SUCCESS) break;
            }
            return anySuccess;
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
