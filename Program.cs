using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace USBGuardian
{
    class Program
    {
        [STAThread]
        static void Main()
        {
            ProgramBase.EnsureStartupSecurity();

            // Create console window
            AllocConsole();

            // Write welcome message
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@" 
╔════════════════════════════════════════════════════════════════╗
║                    USB GUARDIAN v1.0                           ║
║                  USB Device Control System                     ║
╠════════════════════════════════════════════════════════════════╣
║  Starting up... Monitoring for USB devices...                 ║
║  Press Ctrl+C to exit                                          ║
╚════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.WriteLine();

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try
            {
                Application.Run(new USBApplicationContext());
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[USB Guardian] Fatal startup error: {ex}");
                MessageBox.Show(
                    $"USB Guardian failed to start:\n\n{ex.Message}\n\nSee the debug output or event log for details.",
                    "USB Guardian — Startup Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AllocConsole();
    }

    class USBApplicationContext : ApplicationContext
    {
        private USBMessageWindow window;

        public USBApplicationContext()
        {
            window = new USBMessageWindow();
        }
    }

    // =============================
    // MAIN USB MESSAGE WINDOW
    // =============================
    class USBMessageWindow : NativeWindow
    {
        private const int WM_DEVICECHANGE = 0x0219;
        private const int DBT_DEVICEARRIVAL = 0x8000;
        private const int DBT_DEVTYP_DEVICEINTERFACE = 0x00000005;
        private const int DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000;
        private const int DIGCF_PRESENT = 0x00000002;
        private const int DIGCF_DEVICEINTERFACE = 0x00000010;
        private const int SPDRP_DEVICE_DESC = 0x00000000;
        private const int SPDRP_MFG = 0x0000000B;

        // ConfigFlags bits used when blocking a device per-instance
        // (same semantics as UsbStorageBlocker / UsbBlockingManager constants)
        private const int ConfigFlagDisabled  = 0x100;  // CONFIGFLAG_DISABLED
        private const int ConfigFlagReinstall = 0x40;   // CONFIGFLAG_REINSTALL

        // Race-window re-check delays (ms) applied after an immediate block to
        // re-assert ConfigFlags in case Windows re-enables the device node.
        private const int RaceWindowFirstRecheckMs  = 250;
        private const int RaceWindowSecondRecheckMs = 750;

        private static readonly Guid GUID_DEVINTERFACE_USB_DEVICE =
            new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED");

        private IntPtr notificationHandle;
        private DeviceIdentifier deviceIdentifier;
        private List<DeviceFingerprint> whitelist;
        private DeviceHistoryManager historyManager;
        private UsbGuardianCore guardianCore;
        private BlockedDeviceStore blockedDeviceStore;
        private UnblockManager unblockManager;
        private NotifyIcon trayIcon;
        private EmergencyRecoveryManager emergencyRecoveryManager;
        private IntelligentUsbBlocker intelligentUsbBlocker;

        public USBMessageWindow()
        {
            CreateHandle(new CreateParams());

            try
            {
                RegisterForUsbNotifications();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Startup] RegisterForUsbNotifications failed: {ex.Message}");
            }

            deviceIdentifier = new DeviceIdentifier();
            whitelist = LoadWhitelist();
            historyManager = new DeviceHistoryManager();
            deviceIdentifier.HistoryManager = historyManager;

            // Initialize the redesigned security engine core
            guardianCore = new UsbGuardianCore();
            _ = guardianCore.InitializeAsync();
            intelligentUsbBlocker = guardianCore.IntelligentUsbBlocker;

            // Initialize the blocked-device store and unblock manager
            blockedDeviceStore = new BlockedDeviceStore();
            unblockManager = new UnblockManager(blockedDeviceStore, guardianCore.EventLogger);

            // Wire the store into the blocking managers so every block is recorded
            guardianCore.BlockingManager.Store = blockedDeviceStore;

            // Initialize emergency recovery manager (shared backup manager, respects DryRun)
            emergencyRecoveryManager = new EmergencyRecoveryManager(
                guardianCore.EventLogger,
                new AllowedDevicesBackupManager(),
                dryRun: unblockManager.DryRun);

            // Set up system tray icon with context menu
            SetupTrayIcon();

            // Auto-whitelist built-in devices so they are never shown in the unknown-device dialog
            AutoWhitelistBuiltInDevices();

            // Verify all critical safety systems are working before accepting USB events
            RunStartupSafetyTests();

            // Check for legacy USBSTOR block left by older versions and warn the user
            CheckUsbStorStartupWarning();

            // Check for HID input device lockout and show emergency recovery UI if needed
            try
            {
                emergencyRecoveryManager.DetectAndShowRecoveryIfNeeded();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Startup] Emergency recovery check failed: {ex.Message}");
                guardianCore?.EventLogger?.LogWarning(0, "EmergencyRecoveryError",
                    $"Emergency recovery check failed at startup: {ex}");
            }

            Debug.WriteLine("USB Guardian Started - Monitoring for USB devices...");
        }

        /// <summary>
        /// Creates a system-tray icon with a context menu that provides access to
        /// the Unblock Devices form and an Exit option.
        /// </summary>
        private void SetupTrayIcon()
        {
            var menu = new ContextMenuStrip();

            var itemUnblock = new ToolStripMenuItem("🔓 Unblock Devices…");
            itemUnblock.Click += (_, _) =>
            {
                using var form = new UnblockDevicesForm(blockedDeviceStore, unblockManager);
                form.ShowDialog();
            };

            // "Restore USB Storage" item — visible only when a legacy USBSTOR block is detected.
            // Its visibility is refreshed on every tray menu open.
            var itemRestoreUsbStor = new ToolStripMenuItem("⚠ Restore USB Storage…")
            {
                ForeColor = Color.DarkRed,
                Font = new Font(SystemFonts.MenuFont, FontStyle.Bold)
            };
            itemRestoreUsbStor.Click += (_, _) =>
            {
                using var form = new LegacyStorageRecoveryForm(unblockManager);
                form.ShowDialog();
            };

            var itemExit = new ToolStripMenuItem("Exit USB Guardian");
            itemExit.Click += (_, _) => Application.Exit();

            // Emergency recovery item — always visible so users can access it even without a lockout
            var itemEmergency = new ToolStripMenuItem("🚨 Emergency Input Device Recovery…")
            {
                ForeColor = Color.DarkRed,
                Font = new Font(SystemFonts.MenuFont, FontStyle.Bold)
            };
            itemEmergency.Click += (_, _) => emergencyRecoveryManager.ShowRecoveryUI();

            menu.Items.Add(itemUnblock);
            menu.Items.Add(itemRestoreUsbStor);
            menu.Items.Add(itemEmergency);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(itemExit);

            // Refresh the "Restore USB Storage" visibility each time the menu opens
            menu.Opening += (_, _) =>
            {
                itemRestoreUsbStor.Visible = unblockManager.IsLegacyUsbStorBlock();
            };

            trayIcon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "USB Guardian",
                ContextMenuStrip = menu,
                Visible = true
            };

            trayIcon.DoubleClick += (_, _) =>
            {
                using var form = new UnblockDevicesForm(blockedDeviceStore, unblockManager);
                form.ShowDialog();
            };
        }

        /// <summary>
        /// Checks whether the USBSTOR service is globally disabled without a recorded
        /// previous value (legacy block).  If so, shows a tray balloon warning and logs
        /// a critical event so the user knows they should use "Restore USB Storage".
        /// </summary>
        private void CheckUsbStorStartupWarning()
        {
            try
            {
                if (BootRecoveryManager.IsPreBootLockPresent()) return;
                if (!unblockManager.IsLegacyUsbStorBlock()) return;

                guardianCore.EventLogger.LogCritical(0, "StartupWarning",
                    "USBSTOR service is disabled (Start=4) with no recorded previous value. " +
                    "USB storage devices will not work until restored. " +
                    "Use 'Restore USB Storage' from the tray menu.",
                    null);

                Debug.WriteLine("[StartupWarning] Legacy USBSTOR block detected — showing balloon tip");

                trayIcon.ShowBalloonTip(
                    8000,
                    "⚠ USB Storage is Disabled",
                    "USB storage was globally disabled by an older version of USB Guardian.\r\n" +
                    "Right-click the tray icon and choose \"Restore USB Storage\" to recover.",
                    ToolTipIcon.Warning);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[StartupWarning] Check failed: {ex.Message}");
            }
        }

        private void RegisterForUsbNotifications()
        {
            DEV_BROADCAST_DEVICEINTERFACE dbi = new DEV_BROADCAST_DEVICEINTERFACE
            {
                dbcc_size = Marshal.SizeOf(typeof(DEV_BROADCAST_DEVICEINTERFACE)),
                dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE,
                dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE
            };

            IntPtr buffer = Marshal.AllocHGlobal(dbi.dbcc_size);
            Marshal.StructureToPtr(dbi, buffer, false);

            notificationHandle = RegisterDeviceNotification(
                this.Handle,
                buffer,
                DEVICE_NOTIFY_WINDOW_HANDLE);

            Marshal.FreeHGlobal(buffer);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_DEVICECHANGE && m.WParam.ToInt32() == DBT_DEVICEARRIVAL)
            {
                Debug.WriteLine("\n=== USB INSERTION EVENT DETECTED ===");

                if (m.LParam != IntPtr.Zero)
                {
                    DEV_BROADCAST_DEVICEINTERFACE dbi =
                        Marshal.PtrToStructure<DEV_BROADCAST_DEVICEINTERFACE>(m.LParam);

                    if (dbi.dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
                    {
                        IntPtr namePtr = IntPtr.Add(
                            m.LParam,
                            Marshal.OffsetOf<DEV_BROADCAST_DEVICEINTERFACE>("dbcc_name").ToInt32()
                        );

                        string devicePath = Marshal.PtrToStringAuto(namePtr);
                        Debug.WriteLine($"Device Path: {devicePath}");

                        var (vid, pid, instanceId) = ExtractVidPidInstanceId(devicePath);

                        if (!string.IsNullOrEmpty(vid) && !string.IsNullOrEmpty(pid))
                        {
                            var timer = Stopwatch.StartNew();
                            ProcessUsbDevice(vid, pid, instanceId, devicePath, timer);
                        }
                    }
                }
            }

            base.WndProc(ref m);
        }
        private static string SafeGetString(ManagementObject obj, string propertyName)
        {
            try
            {
                object val = obj[propertyName];
                if (val == null)
                    return null;
                // If it's already a string, return it
                if (val is string s)
                    return s;
                // Otherwise, convert using ToString() (e.g., for numbers, DBNull, etc.)
                return val.ToString();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WMI] Error reading property '{propertyName}': {ex.Message}");
                return null;
            }
        }
        private (string vid, string pid, string instanceId) ExtractVidPidInstanceId(string path)
        {
            string vid = null;
            string pid = null;
            string instanceId = "Unknown";

            if (string.IsNullOrEmpty(path))
            {
                return (null, null, "Unknown");
            }

            int vidIndex = path.IndexOf("VID_", StringComparison.OrdinalIgnoreCase);
            int pidIndex = path.IndexOf("PID_", StringComparison.OrdinalIgnoreCase);

            if (vidIndex >= 0 && pidIndex >= 0)
            {
                vid = path.Substring(vidIndex + 4, 4);
                pid = path.Substring(pidIndex + 4, 4);
            }

            try
            {
                string[] parts = path.Split('#');
                if (parts.Length >= 3)
                {
                    instanceId = parts[2];
                    int braceIndex = instanceId.IndexOf('{');
                    if (braceIndex > 0)
                    {
                        instanceId = instanceId.Substring(0, braceIndex);
                    }
                }
            }
            catch { }

            return (vid, pid, instanceId);
        }


        private void ProcessUsbDevice(string vid, string pid, string instanceId, string devicePath, Stopwatch timer)
        {
            Debug.WriteLine("\n--- PROCESSING USB DEVICE ---");
            Debug.WriteLine($"VID: {vid}");
            Debug.WriteLine($"PID: {pid}");
            Debug.WriteLine($"InstanceId: {instanceId}");

            try
            {
                // EARLY BLOCK ─────────────────────────────────────────────────────────────
                // Apply ConfigFlags disable bits on the USB instance key right now, before
                // the slow fingerprint capture (WMI, SCSI IOCTL, USB hub IOCTLs) runs.
                // This shrinks the window during which an unapproved drive is mounted from
                // ~150–400 ms down to the few milliseconds it takes for a single registry
                // read/write + cfgmgr32 rescan.  The block is reversed automatically if the
                // full fingerprint later confirms the device is whitelisted.
                bool earlyBlockApplied = EarlyBlockUsbInstanceKey(vid, pid, instanceId);

                // Capture all identifiers
                DeviceFingerprint currentDevice = deviceIdentifier.CaptureAllIdentifiers(
                    devicePath, vid, pid, instanceId);

                // Stop timer and record timing fingerprint
                timer.Stop();
                currentDevice.EnumerationTimeMs = timer.ElapsedMilliseconds;
                Debug.WriteLine($"Enumeration time: {currentDevice.EnumerationTimeMs} ms");

                Debug.WriteLine($"Enumeration Time: {currentDevice.EnumerationTimeMs} ms");
                Debug.WriteLine($"Captured {currentDevice.IdentifierCount} identifiers for this device");

                // Log insertion event and retrieve history
                DeviceHistoryRecord history = historyManager.LogEvent(currentDevice, DeviceEventType.Insertion);

                // =============================================
                // REDESIGNED SECURITY ENGINE EVALUATION
                // =============================================
                DeviceEvaluationResult evalResult = guardianCore.EvaluateDevice(currentDevice);
                Debug.WriteLine($"[GuardianEngine] Threat={evalResult.OverallThreatLevel}, ShouldBlock={evalResult.ShouldBlock}");

                if (evalResult.ShouldBlock)
                {
                    Debug.WriteLine($"🚨 THREAT DETECTED - Blocking device: {evalResult.BlockReason}");
                    guardianCore.HandleThreat(currentDevice, evalResult);
                    historyManager.LogEvent(currentDevice, DeviceEventType.Blocked, evalResult.BlockReason);
                    ShowBalloonTip(
                        "⚠️ USB Threat Blocked",
                        $"Dangerous device blocked: {evalResult.BlockReason}");
                    return;
                }

                bool isAllowed = false;
                DeviceFingerprint matchedDevice = null;

                foreach (var whitelistedDevice in whitelist)
                {
                    if (currentDevice.Matches(whitelistedDevice))
                    {
                        isAllowed = true;
                        matchedDevice = whitelistedDevice;
                        break;
                    }
                }

                if (isAllowed)
                {
                    // If an early ConfigFlags block was applied before fingerprint capture,
                    // and the full fingerprint now confirms the device is whitelisted,
                    // clear the block bits so the drive becomes accessible again.
                    if (earlyBlockApplied)
                    {
                        try
                        {
                            string earlyRegPath =
                                $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                            using var earlyKey =
                                Registry.LocalMachine.OpenSubKey(earlyRegPath, writable: true);
                            if (earlyKey != null)
                            {
                                int cv = earlyKey.GetValue("ConfigFlags") is int f ? f : 0;
                                earlyKey.SetValue("ConfigFlags",
                                    cv & ~(ConfigFlagDisabled | ConfigFlagReinstall),
                                    RegistryValueKind.DWord);
                            }
                            TriggerRescanForBlock($"{vid}:{pid}");
                            Debug.WriteLine(
                                $"[EarlyBlock] Reversed early block for whitelisted device {vid}:{pid}");
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine(
                                $"[EarlyBlock] Failed to reverse early block for {vid}:{pid}: {ex.Message}");
                        }
                    }

                    Debug.WriteLine("✅ DEVICE ALLOWED - Found in whitelist");
                    matchedDevice.LastConnectedTime = DateTime.UtcNow;
                    SaveWhitelist();
                    if (UsbStorageBlocker.IsUsbStorageDevice(currentDevice))
                        guardianCore.TemporarilyEnableUsbStorage(currentDevice, 60);

                    historyManager.LogEvent(currentDevice, DeviceEventType.Whitelisted, "Matched existing whitelist entry");

                    ShowBalloonTip(
                        "USB Device Allowed",
                        $"{currentDevice.Description ?? "Unknown Device"} has been allowed.");
                }
                else
                {
                    if (guardianCore.IsWhitelisted(currentDevice))
                    {
                        if (UsbStorageBlocker.IsUsbStorageDevice(currentDevice))
                            guardianCore.TemporarilyEnableUsbStorage(currentDevice, 60);
                        historyManager.LogEvent(currentDevice, DeviceEventType.Whitelisted, "Matched security-engine VID:PID whitelist entry");
                        ShowBalloonTip(
                            "USB Device Allowed",
                            $"{currentDevice.Description ?? "Unknown Device"} has been allowed by security whitelist.");
                        return;
                    }

                    Debug.WriteLine("❌ DEVICE NOT IN WHITELIST");
                    HandleUnknownDevice(currentDevice, evalResult);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error processing USB device: {ex.Message}");
            }
        }

        private void HandleUnknownDevice(DeviceFingerprint device, DeviceEvaluationResult? evaluationResult = null)
        {
            LogUnknownDevice(device);

            // If this is definitely a built-in device, auto-allow and whitelist it silently.
            if (BuiltInDeviceSafetyChecker.IsDefinitelyBuiltIn(device))
            {
                Debug.WriteLine("✅ Auto-allowing built-in device (no dialog shown)");
                whitelist.Add(device);
                SaveWhitelist();
                historyManager.LogEvent(device, DeviceEventType.Whitelisted, "Auto-whitelisted as built-in device");
                return;
            }

            bool mightBeBuiltIn = BuiltInDeviceSafetyChecker.MightBeBuiltIn(device);

            // WHITELISTING ENFORCEMENT: immediately block unapproved USB storage devices
            // before the authorization dialog is shown so the device is disabled as soon
            // as possible (minimising the brief window where it may be accessible).
            // Devices that might be built-in are intentionally excluded from pre-blocking
            // to avoid locking out keyboards / trackpads.
            BlockedDeviceRecord? preBlockRecord = null;
            if (!mightBeBuiltIn && UsbStorageBlocker.IsUsbStorageDevice(device))
                preBlockRecord = ImmediateBlockForWhitelistEnforcement(device);

            if (mightBeBuiltIn)
            {
                var builtInResult = MessageBox.Show(
                    "This device might be an internal component.\n\n" +
                    "For safety, USB Guardian recommends allowing it unless you are certain it is external malicious hardware.\n\n" +
                    "Allow this device?",
                    "USB Guardian - Possible Built-In Device",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button1);

                if (builtInResult == DialogResult.Yes)
                {
                    if (UsbStorageBlocker.IsUsbStorageDevice(device))
                        guardianCore.TemporarilyEnableUsbStorage(device, 60);
                    historyManager.LogEvent(device, DeviceEventType.Whitelisted, "User allowed possible built-in device");
                }
                return;
            }

            var decision = intelligentUsbBlocker.EvaluateAndDecide(device, evaluationResult);

            if (decision.ShouldBlockImmediately ||
                decision.UserDecision?.Action == DeviceDecisionAction.Block)
            {
                if (preBlockRecord == null)
                    BlockDevice(device);
                historyManager.LogEvent(device, DeviceEventType.Blocked,
                    preBlockRecord != null
                        ? "User confirmed block of pre-blocked storage device"
                        : "User blocked unknown device");
                return;
            }

            if (decision.UserDecision?.Action == DeviceDecisionAction.Ignore)
            {
                historyManager.LogEvent(device, DeviceEventType.Insertion, "User ignored unknown-device prompt");
                ShowBalloonTip("USB Device Ignored", "No trust decision was saved.");
                return;
            }

            if (decision.UserDecision?.Action == DeviceDecisionAction.AllowOnce ||
                decision.UserDecision?.Action == DeviceDecisionAction.AllowAndWhitelist)
            {
                if (preBlockRecord != null)
                {
                    try { unblockManager.UnblockDevice(preBlockRecord); }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[HandleUnknownDevice] Pre-block reversal failed: {ex.Message}");
                    }
                }

                if (decision.ShouldPersistTrustDecision)
                {
                    whitelist.Add(device);
                    SaveWhitelist();
                    historyManager.LogEvent(device, DeviceEventType.Whitelisted, "User approved unknown device and saved trust decision");
                    ShowBalloonTip("Device Whitelisted", $"{device.Description} has been added to trusted devices.");
                }
                else
                {
                    historyManager.LogEvent(device, DeviceEventType.Whitelisted, "User allowed unknown device once");
                }

                if (UsbStorageBlocker.IsUsbStorageDevice(device))
                    guardianCore.TemporarilyEnableUsbStorage(device, 60);
            }
        }

        private string GetDeviceDetailsText(DeviceFingerprint device)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Description: {device.Description ?? "Unknown"}");
            sb.AppendLine($"Manufacturer: {device.Manufacturer ?? "Unknown"}");
            sb.AppendLine($"VID:PID: {device.Vid}:{device.Pid}");
            sb.AppendLine($"Device Class (string): {device.DeviceClass ?? "Unknown"}");
            sb.AppendLine($"USB Device Class: 0x{device.UsbDeviceClass:X2} ({(device.UsbDeviceClass == 0 ? "per-interface" : device.UsbDeviceClass.ToString())})");
            sb.AppendLine($"USB SubClass: 0x{device.UsbDeviceSubClass:X2}");
            sb.AppendLine($"USB Protocol: 0x{device.UsbDeviceProtocol:X2}");
            sb.AppendLine($"Service: {device.Service ?? "Unknown"}");
            sb.AppendLine($"Serial Number: {device.SerialNumber ?? "Not Available"}");
            sb.AppendLine($"Container ID: {device.ContainerId ?? "Not Available"}");
            sb.AppendLine($"ParentIdPrefix: {device.ParentIdPrefix ?? "Not Available"}");
            sb.AppendLine($"First Seen: {device.FirstInstallTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Enumeration Time: {device.EnumerationTimeMs} ms");
            sb.AppendLine($"Num Configurations: {device.NumConfigurations}");
            sb.AppendLine($"Num Interfaces: {device.NumInterfaces}");
            sb.AppendLine($"MaxPacketSize0: {device.MaxPacketSize0}");
            sb.AppendLine($"bcdUSB: 0x{device.BcdUSB:X4}");
            sb.AppendLine($"bcdDevice: 0x{device.BcdDevice:X4}");
            sb.AppendLine($"Descriptor Hash: {device.DescriptorHash ?? "N/A"}");
            sb.AppendLine($"Interface Hash: {device.InterfaceDescriptorHash ?? "N/A"}");
            sb.AppendLine($"Endpoint Hash: {device.EndpointDescriptorHash ?? "N/A"}");
            sb.AppendLine($"Confidence: {device.IdentifierCount} identifiers captured");
            sb.AppendLine($"\nFingerprint: {device.GenerateFingerprintHash()}");
            return sb.ToString();
        }

        private void BlockDevice(DeviceFingerprint device)
        {
            try
            {
                Debug.WriteLine("🔒 BLOCKING DEVICE - Running safety checks...");

                // SAFETY GATE #1: Definitely built-in device — show critical warning and abort
                if (BuiltInDeviceSafetyChecker.IsDefinitelyBuiltIn(device))
                {
                    var result = MessageBox.Show(
                        "🚨 CRITICAL WARNING 🚨\n\n" +
                        $"The device \"{device.Description ?? "Unknown"}\" appears to be a BUILT-IN component " +
                        "(e.g., internal keyboard, mouse, or trackpad).\n\n" +
                        "Blocking this device may render your computer UNUSABLE and require a reboot or external hardware to recover.\n\n" +
                        "Are you absolutely sure you want to block it?",
                        "CRITICAL WARNING - Built-in Device",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Stop,
                        MessageBoxDefaultButton.Button2);

                    if (result != DialogResult.Yes)
                    {
                        Debug.WriteLine("⛔ Block aborted by user (built-in device critical warning)");
                        return;
                    }
                }
                // SAFETY GATE #2: Possibly built-in — show a softer warning
                else if (BuiltInDeviceSafetyChecker.MightBeBuiltIn(device))
                {
                    var result = MessageBox.Show(
                        "⚠ WARNING\n\n" +
                        $"The device \"{device.Description ?? "Unknown"}\" might be an internal component " +
                        "(e.g., a built-in keyboard or mouse).\n\n" +
                        "Blocking it could cause input loss. Do you want to continue?",
                        "Warning - Possibly Built-in Device",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning,
                        MessageBoxDefaultButton.Button2);

                    if (result != DialogResult.Yes)
                    {
                        Debug.WriteLine("⛔ Block aborted by user (possible built-in device warning)");
                        return;
                    }
                }

                if (UsbStorageBlocker.IsUsbStorageDevice(device))
                {
                    // USB Mass Storage: eject mounted volumes and set registry block flags
                    Debug.WriteLine("🔒 Storage device detected — using UsbStorageBlocker");
                    var storageBlocker = new UsbStorageBlocker(guardianCore.EventLogger)
                    {
                        Store = blockedDeviceStore
                    };
                    storageBlocker.BlockUsbStorageDevice(device);
                }
                else if (UsbStorageBlocker.IsHidDevice(device))
                {
                    // HID device (keyboard/mouse): ConfigFlags |= 0x100 is sufficient
                    Debug.WriteLine("🔒 HID device detected — using ConfigFlags registry block");
                    string instancePath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                    var actions = new List<BlockActionRecord>();
                    SetDeviceConfigFlagsRecorded(instancePath, 0x100, "HID device", actions);

                    blockedDeviceStore.AddOrUpdate(new BlockedDeviceRecord
                    {
                        Vid = device.Vid ?? string.Empty,
                        Pid = device.Pid ?? string.Empty,
                        InstanceId = device.InstanceId ?? string.Empty,
                        SerialNumber = device.SerialNumber ?? string.Empty,
                        Description = device.Description ?? string.Empty,
                        BlockReason = "User blocked HID device",
                        Actions = actions
                    });
                }
                else
                {
                    // Unknown device type: disable via WMI Win32_PnPEntity and set registry flags
                    Debug.WriteLine("🔒 Unknown device type — disabling via WMI and setting registry flags");
                    var actions = new List<BlockActionRecord>();
                    try
                    {
                        string wmiQuery = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{device.Vid}&PID_{device.Pid}%'";
                        System.Management.ManagementObjectCollection wmiResults = null;
                        try
                        {
                            using var searcher = new System.Management.ManagementObjectSearcher(wmiQuery);
                            wmiResults = searcher.Get();
                            foreach (System.Management.ManagementObject obj in wmiResults)
                            {
                                obj.InvokeMethod("Disable", null);
                                Debug.WriteLine($"Unknown device disabled via WMI: {obj["DeviceID"]}");
                                actions.Add(new BlockActionRecord { ActionType = "WmiDisable" });
                                break;
                            }
                        }
                        finally
                        {
                            wmiResults?.Dispose();
                        }
                    }
                    catch (Exception wmiEx)
                    {
                        Debug.WriteLine($"WMI disable failed for unknown device: {wmiEx.Message}");
                    }

                    string unknownPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                    SetDeviceConfigFlagsRecorded(unknownPath, 0x100, "Unknown device", actions);

                    blockedDeviceStore.AddOrUpdate(new BlockedDeviceRecord
                    {
                        Vid = device.Vid ?? string.Empty,
                        Pid = device.Pid ?? string.Empty,
                        InstanceId = device.InstanceId ?? string.Empty,
                        SerialNumber = device.SerialNumber ?? string.Empty,
                        Description = device.Description ?? string.Empty,
                        BlockReason = "User blocked unknown device",
                        Actions = actions
                    });
                }

                ShowBalloonTip("USB Device Blocked",
                    $"Device {device.Description} has been blocked.");
                Debug.WriteLine("🔒 Device blocked successfully.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error blocking device: {ex.Message}");
            }
        }

        /// <summary>
        /// Opens the registry key at <paramref name="instancePath"/> under HKLM and ORs
        /// the given <paramref name="flags"/> into the ConfigFlags DWORD value.
        /// </summary>
        private static void SetDeviceConfigFlags(string instancePath, int flags, string deviceLabel)
        {
            using RegistryKey key = Registry.LocalMachine.OpenSubKey(instancePath, true);
            if (key != null)
            {
                int current = (int)(key.GetValue("ConfigFlags", 0) ?? 0);
                key.SetValue("ConfigFlags", current | flags, RegistryValueKind.DWord);
                Debug.WriteLine($"{deviceLabel} disabled via registry (ConfigFlags |= 0x{flags:X}): {instancePath}");
            }
            else
            {
                Debug.WriteLine($"Registry key not found for {deviceLabel}: {instancePath}");
            }
        }

        /// <summary>
        /// Same as <see cref="SetDeviceConfigFlags"/> but also appends a
        /// <see cref="BlockActionRecord"/> to <paramref name="actionLog"/> with the
        /// previous ConfigFlags value so the change can be reversed later.
        /// </summary>
        private static void SetDeviceConfigFlagsRecorded(
            string instancePath, int flags, string deviceLabel,
            List<BlockActionRecord> actionLog)
        {
            using RegistryKey key = Registry.LocalMachine.OpenSubKey(instancePath, true);
            if (key != null)
            {
                int previous = (int)(key.GetValue("ConfigFlags", 0) ?? 0);
                key.SetValue("ConfigFlags", previous | flags, RegistryValueKind.DWord);
                Debug.WriteLine($"{deviceLabel} disabled via registry (ConfigFlags |= 0x{flags:X}): {instancePath}");
                // Record the true pre-Guardian state: strip Guardian's own bits before
                // saving so that the rollback target is correct even when an early-block
                // step has already applied those bits before this call runs.
                actionLog.Add(new BlockActionRecord
                {
                    ActionType = "ConfigFlags",
                    RegistryPath = instancePath,
                    PreviousConfigFlags = previous & ~(ConfigFlagDisabled | ConfigFlagReinstall)
                });
            }
            else
            {
                Debug.WriteLine($"Registry key not found for {deviceLabel}: {instancePath}");
            }
        }

        /// <summary>
        /// Re-applies ConfigFlags disable bits on <paramref name="instancePath"/> without
        /// creating a new action record.  Used by the race-window re-check to re-assert
        /// a block that Windows may have cleared during device enumeration.
        /// </summary>
        private static void SetDeviceConfigFlagsRaw(string instancePath, int flags)
        {
            try
            {
                using RegistryKey key = Registry.LocalMachine.OpenSubKey(instancePath, true);
                if (key != null)
                {
                    int current = (int)(key.GetValue("ConfigFlags", 0) ?? 0);
                    key.SetValue("ConfigFlags", current | flags, RegistryValueKind.DWord);
                    Debug.WriteLine($"[WhitelistEnforcement] Race-window re-apply ConfigFlags 0x{flags:X} on {instancePath}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WhitelistEnforcement] SetDeviceConfigFlagsRaw failed on {instancePath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Disables a device via WMI Win32_PnPEntity, targeting the exact device instance
        /// first (by DeviceId / PnpDeviceId) and falling back to a VID/PID LIKE query.
        /// All matching nodes that have not yet been seen are disabled.
        /// </summary>
        private static void DisableStorageDeviceViaWmi(DeviceFingerprint device,
            List<BlockActionRecord> actions)
        {
            // Build queries from most-precise to least-precise
            var queries = new List<string>();

            // Exact match on USBSTOR\... DeviceId (WMI DeviceID, backslashes doubled for WQL)
            if (!string.IsNullOrEmpty(device.DeviceId))
            {
                string escapedDeviceId = device.DeviceId.Replace("\\", "\\\\").Replace("'", "\\'");
                queries.Add($"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{escapedDeviceId}'");
            }

            // Exact match on USB\VID_...\InstanceId
            if (!string.IsNullOrEmpty(device.InstanceId) && device.InstanceId != "Unknown")
            {
                string usbPath       = $@"USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                string escapedUsbPath = usbPath.Replace("\\", "\\\\").Replace("'", "\\'");
                queries.Add($"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '{escapedUsbPath}'");
            }

            // Broad VID/PID LIKE fallback (catches composite device + storage child)
            queries.Add($"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{device.Vid}&PID_{device.Pid}%'");

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string wql in queries)
            {
                ManagementObjectCollection results = null;
                try
                {
                    using var searcher = new ManagementObjectSearcher(wql);
                    results = searcher.Get();
                    foreach (ManagementObject obj in results)
                    {
                        if (obj == null) continue;
                        string devId = obj["DeviceID"]?.ToString() ?? string.Empty;
                        if (!seen.Add(devId)) continue;

                        try
                        {
                            obj.InvokeMethod("Disable", null);
                            actions.Add(new BlockActionRecord { ActionType = "WmiDisable" });
                            Debug.WriteLine($"[WhitelistEnforcement] WMI disabled: {devId}");
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"[WhitelistEnforcement] WMI Disable failed for {devId}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[WhitelistEnforcement] WMI query failed ({wql}): {ex.Message}");
                }
                finally
                {
                    results?.Dispose();
                }
            }
        }

        /// <summary>
        /// Triggers a root-level cfgmgr32 re-enumeration so Windows drops the device
        /// node that was just blocked via ConfigFlags, reducing the time the device
        /// node is visible to the OS.
        /// </summary>
        private void TriggerRescanForBlock(string vidPid)
        {
            try
            {
                int cr = CM_Locate_DevNodeW(out uint rootInst, null, CM_LOCATE_DEVNODE_NORMAL_WL);
                if (cr == CM_CR_SUCCESS)
                {
                    CM_Reenumerate_DevNode(rootInst, CM_REENUMERATE_NORMAL_WL);
                    Debug.WriteLine($"[WhitelistEnforcement] Triggered cfgmgr32 rescan for {vidPid}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WhitelistEnforcement] cfgmgr32 rescan failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Applies ConfigFlags disable bits on the USB device-instance registry key and
        /// triggers a cfgmgr32 hardware rescan as early as possible — BEFORE the slow
        /// fingerprint capture and 6-layer evaluation run.
        ///
        /// This significantly reduces the window during which an unapproved USB storage
        /// device is mounted and readable.  Windows mounts the volume before the
        /// WM_DEVICECHANGE message is delivered, so complete zero-latency prevention is
        /// only achievable with a kernel filter driver; this is the best user-mode effort.
        ///
        /// Only fires when all of the following are true:
        ///   1. The device's registry Service value is "usbstor" or "disk".
        ///   2. No whitelist entry already carries this VID/PID — if the VID/PID is
        ///      known the full fingerprint-based Matches() check decides admission and
        ///      we avoid a spurious block on a legitimate re-insertion.
        ///   3. The device registry key is present and writable.
        ///
        /// Returns true if the early block was applied so the caller can reverse it
        /// when the full fingerprint confirms the device is whitelisted.
        /// </summary>
        private bool EarlyBlockUsbInstanceKey(string vid, string pid, string instanceId)
        {
            try
            {
                string regPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";

                string serviceName;
                using (var key = Registry.LocalMachine.OpenSubKey(regPath))
                {
                    if (key == null)
                        return false;
                    serviceName = key.GetValue("Service")?.ToString();
                }

                bool isStorage =
                    string.Equals(serviceName, "usbstor", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(serviceName, "disk",    StringComparison.OrdinalIgnoreCase);

                if (!isStorage)
                    return false;

                // If any whitelist entry shares this VID/PID, skip the early block and let
                // the full fingerprint-based Matches() decide — avoids briefly blocking a
                // re-inserted device that is already whitelisted.
                bool vidPidKnown = whitelist.Any(w =>
                    string.Equals(w.Vid, vid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(w.Pid, pid, StringComparison.OrdinalIgnoreCase));

                if (vidPidKnown)
                    return false;

                // Apply ConfigFlags disable bits immediately (single registry write).
                using (var key = Registry.LocalMachine.OpenSubKey(regPath, writable: true))
                {
                    if (key == null)
                        return false;

                    int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                    key.SetValue("ConfigFlags",
                        current | ConfigFlagDisabled | ConfigFlagReinstall,
                        RegistryValueKind.DWord);
                }

                // Ask Windows to drop the now-disabled device node without waiting for a replug.
                TriggerRescanForBlock($"{vid}:{pid}");

                guardianCore?.EventLogger?.LogCritical(0, "EarlyBlock",
                    $"Early ConfigFlags block applied for unknown storage device " +
                    $"VID_{vid}&PID_{pid} (InstanceId={instanceId}) before fingerprint capture. " +
                    "Block will be reversed automatically if the device is subsequently whitelisted.",
                    $"{vid}:{pid}");

                Debug.WriteLine(
                    $"[EarlyBlock] ConfigFlags + rescan applied for {vid}:{pid} at {DateTime.UtcNow:o}");

                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[EarlyBlock] EarlyBlockUsbInstanceKey failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Immediately blocks an unapproved USB storage device by applying per-device
        /// ConfigFlags (disable bits), WMI Disable (exact instance), and a cfgmgr32
        /// re-enumeration to drop the device node as early as possible.
        ///
        /// A race-window mitigation re-checks and re-applies the block at 250 ms and
        /// 750 ms in case Windows re-enumerates the device node during driver binding.
        ///
        /// NOTE: This is a best-effort user-mode enforcement.  True zero-time mount
        /// prevention requires a kernel filter driver.  If the device was briefly
        /// enumerated before this method ran, a critical event is logged for audit.
        ///
        /// Returns the <see cref="BlockedDeviceRecord"/> that was persisted so the
        /// caller can reverse the block if the user subsequently allows the device.
        /// </summary>
        private BlockedDeviceRecord ImmediateBlockForWhitelistEnforcement(DeviceFingerprint device)
        {
            string vidPid    = $"{device.Vid}:{device.Pid}";
            string timestamp = DateTime.UtcNow.ToString("o");

            guardianCore.EventLogger.LogCritical(0, "WhitelistEnforcement",
                $"[{timestamp}] Unapproved USB storage device detected — applying immediate block. " +
                $"Device: {device.Description ?? vidPid} ({vidPid}, InstanceId={device.InstanceId}). " +
                "NOTE: device may have been briefly enumerated before this block was applied " +
                "(user-mode enforcement limitation — a kernel filter driver is required for " +
                "guaranteed zero-time mount prevention).",
                vidPid);

            Debug.WriteLine($"[WhitelistEnforcement] Immediately blocking unapproved storage {vidPid} at {timestamp}");

            var actions = new List<BlockActionRecord>();

            // 0. Eject any already-mounted volumes immediately to close the Rubberducky
            //    attack window: the device may have been briefly accessible during the
            //    ~795 ms Windows enumeration delay, but we dismount it as fast as possible.
            var storageBlocker = new UsbStorageBlocker(guardianCore.EventLogger);
            bool ejected = storageBlocker.EjectUsbVolume(device.Vid, device.Pid);
            Debug.WriteLine($"[WhitelistEnforcement] Volume eject attempt: {(ejected ? "succeeded" : "not mounted or failed")}");

            // 1. Per-device ConfigFlags on the USB instance key
            string usbInstancePath =
                $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
            SetDeviceConfigFlagsRecorded(usbInstancePath, ConfigFlagDisabled | ConfigFlagReinstall,
                "unapproved USB storage (whitelist enforcement)", actions);

            // 2. Per-device ConfigFlags on the USBSTOR child key (if available)
            if (!string.IsNullOrEmpty(device.DeviceId) &&
                device.DeviceId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase))
            {
                string usbStorPath =
                    $@"SYSTEM\CurrentControlSet\Enum\{device.DeviceId.Replace('/', '\\')}";
                SetDeviceConfigFlagsRecorded(usbStorPath, ConfigFlagDisabled | ConfigFlagReinstall,
                    "unapproved USBSTOR child (whitelist enforcement)", actions);
            }

            // 3. WMI Disable by exact device ID (most precise targeting)
            DisableStorageDeviceViaWmi(device, actions);

            // 4. cfgmgr32 rescan — ask Windows to drop the device node now
            TriggerRescanForBlock(vidPid);

            // Persist record so the caller can call UnblockDevice if the user allows the device
            var record = new BlockedDeviceRecord
            {
                Vid          = device.Vid          ?? string.Empty,
                Pid          = device.Pid          ?? string.Empty,
                InstanceId   = device.InstanceId   ?? string.Empty,
                SerialNumber = device.SerialNumber ?? string.Empty,
                Description  = device.Description  ?? string.Empty,
                PnpDeviceId  = device.DeviceId     ?? string.Empty,
                BlockReason  =
                    $"Whitelist enforcement: unapproved storage device blocked at detection ({timestamp})",
                Actions = actions
            };
            blockedDeviceStore.AddOrUpdate(record);

            // 5. Race-window mitigation: re-check and re-assert block in background
            Task.Run(async () =>
            {
                foreach (int delayMs in new[] { RaceWindowFirstRecheckMs, RaceWindowSecondRecheckMs })
                {
                    await Task.Delay(delayMs).ConfigureAwait(false);
                    try
                    {
                        if (!guardianCore.BlockingManager.IsDeviceBlocked(
                                device.Vid, device.Pid, device.InstanceId))
                        {
                            guardianCore.EventLogger.LogCritical(0, "WhitelistEnforcement",
                                $"Race window: re-applying block for {vidPid} after {delayMs} ms — " +
                                "Windows re-enabled the device node.",
                                vidPid);
                            Debug.WriteLine(
                                $"[WhitelistEnforcement] Race-window re-apply at {delayMs} ms for {vidPid}");

                            SetDeviceConfigFlagsRaw(usbInstancePath, ConfigFlagDisabled | ConfigFlagReinstall);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(
                            $"[WhitelistEnforcement] Race-window re-check failed at {delayMs} ms: {ex.Message}");
                    }
                }
            });

            ShowBalloonTip(
                "⚠ Unapproved Storage Device Blocked",
                $"USB storage device blocked pending authorization: {device.Description ?? vidPid}");

            return record;
        }

        private void LogUnknownDevice(DeviceFingerprint device)
        {
            try
            {
                string logPath = Path.Combine(Application.StartupPath, "unknown_devices.log");
                string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {device.Vid}:{device.Pid} - {device.Description} - {device.GenerateFingerprintHash()}";
                File.AppendAllText(logPath, logEntry + Environment.NewLine);
            }
            catch { }
        }

        private void ShowBalloonTip(string title, string text)
        {
            try
            {
                using (var notifyIcon = new NotifyIcon())
                {
                    notifyIcon.Icon = SystemIcons.Information;
                    notifyIcon.Visible = true;
                    notifyIcon.ShowBalloonTip(3000, title, text, ToolTipIcon.Info);
                }
            }
            catch { }
        }

        private List<DeviceFingerprint> LoadWhitelist()
        {
            var list = new List<DeviceFingerprint>();
            try
            {
                string path = Path.Combine(Application.StartupPath, "whitelist.xml");
                if (File.Exists(path))
                {
                    XmlSerializer serializer = new XmlSerializer(typeof(List<DeviceFingerprint>));
                    using (FileStream fs = new FileStream(path, FileMode.Open))
                    {
                        list = (List<DeviceFingerprint>)serializer.Deserialize(fs);
                    }
                    Debug.WriteLine($"Loaded {list.Count} devices from whitelist");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading whitelist: {ex.Message}");
            }
            return list;
        }

        private void SaveWhitelist()
        {
            try
            {
                string path = Path.Combine(Application.StartupPath, "whitelist.xml");
                XmlSerializer serializer = new XmlSerializer(typeof(List<DeviceFingerprint>));
                using (FileStream fs = new FileStream(path, FileMode.Create))
                {
                    serializer.Serialize(fs, whitelist);
                }
                Debug.WriteLine($"Saved {whitelist.Count} devices to whitelist");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving whitelist: {ex.Message}");
            }
        }

        /// <summary>
        /// Creates placeholder whitelist entries for known built-in device types so they are
        /// never shown in the unknown-device dialog on first boot.
        /// </summary>
        private void AutoWhitelistBuiltInDevices()
        {
            bool changed = false;

            var builtInEntries = new[]
            {
                new DeviceFingerprint
                {
                    Vid = "BUILTIN",
                    Pid = "KEYBOARD",
                    Service = "kbdhid",
                    Description = "Built-in Keyboard (auto-whitelisted)",
                    DeviceClass = "HIDClass"
                },
                new DeviceFingerprint
                {
                    Vid = "BUILTIN",
                    Pid = "MOUSE",
                    Service = "mouhid",
                    Description = "Built-in Mouse/Trackpad (auto-whitelisted)",
                    DeviceClass = "HIDClass"
                },
                new DeviceFingerprint
                {
                    Vid = "ACPI",
                    Pid = "BUTTON",
                    Service = "acpibtn",
                    Description = "ACPI Button Device (auto-whitelisted)",
                    DeviceClass = "System"
                },
            };

            foreach (var entry in builtInEntries)
            {
                bool alreadyPresent = whitelist.Any(w =>
                    string.Equals(w.Vid, entry.Vid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(w.Pid, entry.Pid, StringComparison.OrdinalIgnoreCase));

                if (!alreadyPresent)
                {
                    whitelist.Add(entry);
                    Debug.WriteLine($"Auto-whitelisted built-in device: {entry.Description}");
                    changed = true;
                }
            }

            if (changed)
                SaveWhitelist();
        }

        /// <summary>
        /// Runs 5 startup safety tests to verify all critical subsystems are operational.
        /// Shows a critical error dialog and halts if any test fails.
        /// </summary>
        private void RunStartupSafetyTests()
        {
            var failures = new List<string>();

            // TEST 1: Built-in device detection self-test
            try
            {
                if (!BuiltInDeviceSafetyChecker.RunSelfTest())
                    failures.Add("TEST 1 FAILED: Built-in device detection self-test did not pass.");
                else
                    Debug.WriteLine("[StartupTest] TEST 1 PASSED: Built-in device detection");
            }
            catch (Exception ex)
            {
                failures.Add($"TEST 1 EXCEPTION: Built-in device detection: {ex.Message}");
            }

            // TEST 2: Whitelist loading verification
            try
            {
                if (whitelist == null)
                    failures.Add("TEST 2 FAILED: Whitelist is null after loading.");
                else
                    Debug.WriteLine($"[StartupTest] TEST 2 PASSED: Whitelist loaded ({whitelist.Count} entries)");
            }
            catch (Exception ex)
            {
                failures.Add($"TEST 2 EXCEPTION: Whitelist validation: {ex.Message}");
            }

            // TEST 3: History manager initialization check
            try
            {
                if (historyManager == null)
                    failures.Add("TEST 3 FAILED: History manager is not initialized.");
                else
                    Debug.WriteLine("[StartupTest] TEST 3 PASSED: History manager initialized");
            }
            catch (Exception ex)
            {
                failures.Add($"TEST 3 EXCEPTION: History manager check: {ex.Message}");
            }

            // TEST 4: Guardian core initialization check
            try
            {
                if (guardianCore == null)
                    failures.Add("TEST 4 FAILED: Guardian core is not initialized.");
                else
                    Debug.WriteLine("[StartupTest] TEST 4 PASSED: Guardian core initialized");
            }
            catch (Exception ex)
            {
                failures.Add($"TEST 4 EXCEPTION: Guardian core check: {ex.Message}");
            }

            // TEST 5: File system write permissions
            try
            {
                string testFile = Path.Combine(Application.StartupPath, ".startup_test");
                File.WriteAllText(testFile, "ok");
                File.Delete(testFile);
                Debug.WriteLine("[StartupTest] TEST 5 PASSED: File system write permissions");
            }
            catch (Exception ex)
            {
                failures.Add($"TEST 5 FAILED: File system write permissions: {ex.Message}");
            }

            // TEST 6: Blocked-device store JSON persistence self-test
            try
            {
                if (!BlockedDeviceStore.RunSelfTest())
                    failures.Add("TEST 6 FAILED: Blocked-device store persistence self-test did not pass.");
                else
                    Debug.WriteLine("[StartupTest] TEST 6 PASSED: Blocked-device store self-test");
            }
            catch (Exception ex)
            {
                failures.Add($"TEST 6 EXCEPTION: Blocked-device store self-test: {ex.Message}");
            }

            if (failures.Count > 0)
            {
                string message = "🚨 CRITICAL: USB Guardian startup safety tests FAILED:\n\n" +
                                 string.Join("\n", failures) +
                                 "\n\nThe application may not operate safely. Please check your installation.";
                Debug.WriteLine(message);
                MessageBox.Show(message, "USB Guardian - Startup Safety Test Failure",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                Debug.WriteLine("[StartupTest] All 6 startup safety tests PASSED.");
            }

            // Non-fatal check: detect an orphaned USBSTOR disable that USB Guardian did not record.
            // This can happen if a previous version blocked without recording, or if the record was lost.
            CheckOrphanedUsbStorDisable();
        }

        /// <summary>
        /// Checks whether the USBSTOR service is currently disabled (Start=4) without a
        /// corresponding <see cref="BlockedDeviceRecord"/> that explains it.
        /// If so, surfaces a tray balloon warning so the user is not silently bricked.
        /// This check is non-fatal and does not prevent the application from starting.
        /// </summary>
        private void CheckOrphanedUsbStorDisable()
        {
            try
            {
                if (BootRecoveryManager.IsPreBootLockPresent()) return;
                using var svcKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\usbstor");
                if (svcKey == null) return;

                int startValue = svcKey.GetValue("Start") is int sv ? sv : -1;
                if (startValue != 4) return; // USBSTOR is not disabled — nothing to warn about

                // USBSTOR is disabled: check whether any blocked-device record explains it
                bool guardianCausedIt = blockedDeviceStore
                    .GetAll()
                    .Any(record => record.Actions.Any(a =>
                        a.ActionType == "ServiceStart" &&
                        string.Equals(a.ServiceName, "usbstor", StringComparison.OrdinalIgnoreCase)));

                if (!guardianCausedIt)
                {
                    const string warning =
                        "⚠ CRITICAL: The USB Mass Storage driver (USBSTOR) is currently DISABLED " +
                        "(registry Start=4), but USB Guardian has no record of disabling it.\n\n" +
                        "USB storage devices will not work until the service is restored.\n\n" +
                        "Open the 'Unblock Devices' window from the tray icon to review blocked records, " +
                        "or restore manually:\n" +
                        @"  HKLM\SYSTEM\CurrentControlSet\Services\usbstor → Start = 3";

                    Debug.WriteLine($"[StartupCheck] CRITICAL: Orphaned USBSTOR disable detected!");
                    Debug.WriteLine(warning);

                    guardianCore?.EventLogger?.LogCritical(
                        0, "OrphanedUsbStorDisable", warning, "usbstor");

                    // Surface a prominent tray balloon notification
                    trayIcon?.ShowBalloonTip(
                        30_000,
                        "⚠ USB Guardian — Warning",
                        "USB storage is GLOBALLY DISABLED and no block record was found. " +
                        "Open 'Unblock Devices' from the tray icon to investigate or restore manually.",
                        ToolTipIcon.Error);
                }
                else
                {
                    Debug.WriteLine("[StartupCheck] USBSTOR Start=4 is covered by a blocked-device record — OK.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[StartupCheck] USBSTOR orphan check error: {ex.Message}");
            }
        }

        // =============================
        // P/INVOKE STRUCTURES
        // =============================
        [StructLayout(LayoutKind.Sequential)]
        private struct DEV_BROADCAST_DEVICEINTERFACE
        {
            public int dbcc_size;
            public int dbcc_devicetype;
            public int dbcc_reserved;
            public Guid dbcc_classguid;
            public short dbcc_name;
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr RegisterDeviceNotification(
            IntPtr hRecipient,
            IntPtr NotificationFilter,
            int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            string Enumerator,
            IntPtr hwndParent,
            uint Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(
            IntPtr DeviceInfoSet);

        // cfgmgr32 — used to trigger device re-enumeration after immediate block
        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string? pDeviceID, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Reenumerate_DevNode(uint dnDevInst, uint ulFlags);

        private const int  CM_CR_SUCCESS               = 0;
        private const uint CM_LOCATE_DEVNODE_NORMAL_WL = 0;
        private const uint CM_REENUMERATE_NORMAL_WL    = 0;


        public class DeviceIdentifier
        {
            /// <summary>
            /// Optional reference to the device history manager. When set,
            /// <see cref="DisplayIdentifiersTable"/> will show forensic history.
            /// </summary>
            public DeviceHistoryManager? HistoryManager { get; set; }

            private string GetVolumeSerialForDevice(string vid, string pid, string instanceId)
            {
                try
                {
                    // Step 1: Find the physical drive that matches VID/PID
                    string physicalDrive = null;
                    ManagementObjectCollection diskResults = null;
                    try
                    {
                        using var searcher = new ManagementObjectSearcher(
                            "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                        diskResults = searcher.Get();
                        foreach (ManagementObject disk in diskResults)
                        {
                            string pnpDeviceId = SafeGetString(disk, "PNPDeviceID");
                            if (!string.IsNullOrEmpty(pnpDeviceId) && pnpDeviceId.Contains($"VID_{vid}&PID_{pid}"))
                            {
                                physicalDrive = SafeGetString(disk, "DeviceID"); // e.g., \\.\PHYSICALDRIVE1
                                break;
                            }
                        }
                    }
                    finally
                    {
                        diskResults?.Dispose();
                    }

                    if (string.IsNullOrEmpty(physicalDrive))
                        return null;

                    // Step 2: Get the disk drive's partitions
                    ManagementObjectCollection partResults = null;
                    try
                    {
                        using var partitionSearcher = new ManagementObjectSearcher(
                            $"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{physicalDrive}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                        partResults = partitionSearcher.Get();
                        foreach (ManagementObject partition in partResults)
                        {
                            string partitionDeviceId = SafeGetString(partition, "DeviceID");
                            if (string.IsNullOrEmpty(partitionDeviceId))
                                continue;

                            // Step 3: Get logical disks from partition
                            ManagementObjectCollection logicalResults = null;
                            try
                            {
                                using var logicalSearcher = new ManagementObjectSearcher(
                                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partitionDeviceId}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");
                                logicalResults = logicalSearcher.Get();
                                foreach (ManagementObject logical in logicalResults)
                                {
                                    string volumeSerial = SafeGetString(logical, "VolumeSerialNumber");
                                    if (!string.IsNullOrEmpty(volumeSerial))
                                        return volumeSerial;
                                }
                            }
                            finally
                            {
                                logicalResults?.Dispose();
                            }
                        }
                    }
                    finally
                    {
                        partResults?.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[GetVolumeSerialForDevice] Error: {ex.Message}");
                }
                return null;
            }

            private string GetPhysicalDrivePath(string vid, string pid)
            {
                ManagementObjectCollection results = null;
                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                    results = searcher.Get();
                    foreach (ManagementObject disk in results)
                    {
                        string pnpDeviceId = SafeGetString(disk, "PNPDeviceID");
                        Debug.WriteLine($"[GetPhysicalDrivePath] Checking disk: {pnpDeviceId}");
                        if (!string.IsNullOrEmpty(pnpDeviceId) && pnpDeviceId.Contains($"VID_{vid}&PID_{pid}"))
                        {
                            string deviceId = SafeGetString(disk, "DeviceID");
                            Debug.WriteLine($"[GetPhysicalDrivePath] Found: {deviceId}");
                            return deviceId; // e.g., \\.\PHYSICALDRIVE1
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[GetPhysicalDrivePath] Error: {ex.Message}");
                }
                finally
                {
                    results?.Dispose();
                }
                return null;
            }
            private (int hub, int port) GetHubAndPort(string vid, string pid, string instanceId)
            {
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";

                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string location = key.GetValue("LocationInformation")?.ToString();

                            if (!string.IsNullOrEmpty(location))
                            {
                                int hub = -1;
                                int port = -1;

                                var parts = location.Split('.');

                                foreach (var part in parts)
                                {
                                    if (part.StartsWith("Hub_#"))
                                        hub = int.Parse(part.Substring(5));

                                    if (part.StartsWith("Port_#"))
                                        port = int.Parse(part.Substring(6));
                                }

                                return (hub, port);
                            }
                        }
                    }
                }
                catch { }

                return (-1, -1);
            }
            public DeviceFingerprint CaptureAllIdentifiers(string devicePath, string vid, string pid, string instanceId)
            {

                var fingerprint = new DeviceFingerprint
                {
                    Vid = vid,
                    Pid = pid,
                    InstanceId = instanceId,
                    DevicePath = devicePath,
                    CaptureTime = DateTime.UtcNow
                };

                Debug.WriteLine($"\n=== CAPTURING ALL POSSIBLE IDENTIFIERS FOR {vid}:{pid} ===");

                // Get registry identifiers
                CaptureRegistryIdentifiers(fingerprint);

                // Get timestamps
                CaptureTimestamps(fingerprint);

                // Get serial number
                fingerprint.SerialNumber = GetSerialNumber(vid, pid, instanceId);

                // Get ContainerId
                fingerprint.ContainerId = GetContainerId(vid, pid, instanceId);

                // Get ParentIdPrefix
                fingerprint.ParentIdPrefix = GetParentIdPrefix(vid, pid);

                // Get service and hardware IDs
                fingerprint.Service = GetServiceName(vid, pid, instanceId);
                fingerprint.HardwareIds = GetHardwareIds(vid, pid, instanceId);
                fingerprint.HardwareIdHash = GenerateHash(fingerprint.HardwareIds);


                // Determine high‑level device class (string)
                fingerprint.DeviceClass = DetermineDeviceClass(fingerprint.Service, fingerprint.HardwareIds);

                
                

                // Get compatible IDs
                fingerprint.CompatibleIds = GetCompatibleIds(vid, pid, instanceId);
                fingerprint.CompatibleIdHash = GenerateHash(fingerprint.CompatibleIds);

                // Get description and manufacturer
                fingerprint.Description = GetDeviceDescription(vid, pid, instanceId);
                fingerprint.Manufacturer = GetManufacturer(vid, pid, instanceId);


                if (fingerprint.DeviceClass.Contains("Storage") || fingerprint.Service == "usbstor")
                {
                    Debug.WriteLine("Storage device detected.");

                    fingerprint.VolumeSerialNumber = GetVolumeSerialForDevice(fingerprint.Vid, fingerprint.Pid, fingerprint.InstanceId);
                    Debug.WriteLine($"VolumeSerialNumber = {fingerprint.VolumeSerialNumber ?? "null"}");

                    string physicalDrive = GetPhysicalDrivePath(fingerprint.Vid, fingerprint.Pid);
                    Debug.WriteLine($"PhysicalDrive = {physicalDrive ?? "null"}");

                    if (!string.IsNullOrEmpty(physicalDrive))
                    {
                        if (ScsiInquiryReader.ReadScsiInquiry(physicalDrive, out string v, out string p, out string r))
                        {
                            fingerprint.ScsiVendor = v;
                            fingerprint.ScsiProduct = p;
                            fingerprint.ScsiRevision = r;
                            Debug.WriteLine($"SCSI: Vendor={v}, Product={p}, Rev={r}");
                        }
                        else
                        {
                            Debug.WriteLine("SCSI inquiry failed.");
                        }
                    }
                }

                // Get interface number and count
                fingerprint.InterfaceNumber = GetInterfaceNumber(devicePath);
                fingerprint.InterfaceCount = GetInterfaceCount(devicePath);

                // ===== ENHANCED DESCRIPTOR READING =====
                // Try to read real USB descriptors (requires admin rights)
                bool descriptorsRead = USBDescriptorReader.ReadDescriptors(fingerprint);
                if (!descriptorsRead)
                {
                    Debug.WriteLine("Falling back to simulated descriptor fingerprint.");
                    fingerprint.DescriptorHash = GenerateFallbackDescriptorHash(fingerprint);
                }

                // Derive interface numbers from USB descriptor (more accurate than device path)
                if (fingerprint.AllInterfaces != null && fingerprint.AllInterfaces.Count > 0)
                {
                    var nums = fingerprint.AllInterfaces
                        .Select(i => i.InterfaceNumber.ToString())
                        .Distinct()
                        .OrderBy(n => n);
                    fingerprint.InterfaceNumbers = string.Join(", ", nums);
                }
                else if (fingerprint.InterfaceNumber != null)
                {
                    fingerprint.InterfaceNumbers = fingerprint.InterfaceNumber;
                }

                // ===== EXTENDED DEVICE INFO =====
                CaptureExtendedDeviceInfo(fingerprint);

                // ===== HID DEVICE CLASSIFICATION =====
                // Classify device types using interface descriptors (populated by USBDescriptorReader)
                if (fingerprint.AllInterfaces != null && fingerprint.AllInterfaces.Count > 0)
                {
                    List<string> types = HIDClassifier.DetectDeviceTypes(fingerprint.AllInterfaces);
                    fingerprint.DeviceTypes = types.Count > 0 ? string.Join(" + ", types) : null;
                }
                else if (fingerprint.InterfaceClass > 0)
                {
                    // Fall back to single interface classification
                    string singleType = HIDClassifier.ClassifyInterface(
                        fingerprint.InterfaceClass,
                        fingerprint.InterfaceSubClass,
                        fingerprint.InterfaceProtocol);
                    fingerprint.DeviceTypes = singleType;
                }

                Debug.WriteLine($"Device Types: {fingerprint.DeviceTypes ?? "Unknown"}");

                Debug.WriteLine($"DevicePath: {devicePath}");
                Debug.WriteLine($"InstanceID: {instanceId}");
                Console.WriteLine($"Running as admin: {new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)}");
                // Count identifiers AFTER everything is filled
                fingerprint.IdentifierCount = CountIdentifiers(fingerprint);

                Debug.WriteLine($"\n✓ CAPTURED {fingerprint.IdentifierCount} IDENTIFIERS FOR THIS DEVICE");



                string vendor;
                string product;
                string revision;

              

                



                // Display the beautiful table
                DisplayIdentifiersTable(fingerprint);


                return fingerprint;
            }
            


            private string GenerateFallbackDescriptorHash(DeviceFingerprint f)
            {
                string combined = $"{f.Vid}|{f.Pid}|{f.InterfaceCount}|{f.Service}|{f.DeviceClass}";
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(combined));
                    return Convert.ToBase64String(hash).Substring(0, 16);
                }
            }

            /// <summary>
            /// Reads extended device information from the registry and WMI:
            /// friendly name, driver version, bus type, location, capabilities, storage size, etc.
            /// </summary>
            private void CaptureExtendedDeviceInfo(DeviceFingerprint fingerprint)
            {
                try
                {
                    string regPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{fingerprint.Vid}&PID_{fingerprint.Pid}\{fingerprint.InstanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath))
                    {
                        if (key != null)
                        {
                            fingerprint.FriendlyName  = key.GetValue("FriendlyName")?.ToString();
                            fingerprint.ClassGuid      = key.GetValue("ClassGUID")?.ToString();
                            fingerprint.DriverKeyName  = key.GetValue("Driver")?.ToString();
                            fingerprint.LocationInfo   = key.GetValue("LocationInformation")?.ToString();
                            fingerprint.Enumerator     = key.GetValue("EnumeratorName")?.ToString();

                            object addrObj = key.GetValue("Address");
                            if (addrObj != null)
                                fingerprint.Address = addrObj.ToString();

                            object capsObj = key.GetValue("Capabilities");
                            if (capsObj is int caps)
                                fingerprint.Capabilities = (uint)caps;

                            // Full device instance ID for the child (e.g. USBSTOR\...)
                            // Read from the child device if available; otherwise use the USB-level key
                            fingerprint.DeviceId = $@"USB\VID_{fingerprint.Vid}&PID_{fingerprint.Pid}\{fingerprint.InstanceId}";
                        }
                    }

                    // Driver info from the class registry key
                    if (!string.IsNullOrEmpty(fingerprint.DriverKeyName))
                    {
                        string driverPath = $@"SYSTEM\CurrentControlSet\Control\Class\{fingerprint.DriverKeyName}";
                        using (RegistryKey driverKey = Registry.LocalMachine.OpenSubKey(driverPath))
                        {
                            if (driverKey != null)
                            {
                                fingerprint.DriverName    = driverKey.GetValue("DriverDesc")?.ToString();
                                fingerprint.DriverVersion = driverKey.GetValue("DriverVersion")?.ToString();
                                fingerprint.DriverDate    = driverKey.GetValue("DriverDate")?.ToString();

                                string infPath = driverKey.GetValue("InfPath")?.ToString();
                                if (!string.IsNullOrEmpty(infPath) && string.IsNullOrEmpty(fingerprint.KernelName))
                                    fingerprint.KernelName = infPath;
                            }
                        }
                    }

                    // Win32 name and storage size via WMI (storage devices)
                    if (fingerprint.DeviceClass?.Contains("Storage") == true ||
                        fingerprint.Service?.Equals("usbstor", StringComparison.OrdinalIgnoreCase) == true ||
                        fingerprint.Service?.Equals("disk", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        ManagementObjectCollection diskResults = null;
                        try
                        {
                            using var searcher = new ManagementObjectSearcher(
                                "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                            diskResults = searcher.Get();
                            foreach (ManagementObject disk in diskResults)
                            {
                                string pnpDeviceId = SafeGetString(disk, "PNPDeviceID");
                                if (!string.IsNullOrEmpty(pnpDeviceId) &&
                                    pnpDeviceId.IndexOf($"VID_{fingerprint.Vid}&PID_{fingerprint.Pid}", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    fingerprint.Win32Name = SafeGetString(disk, "DeviceID");

                                    object sizeObj = disk["Size"];
                                    if (sizeObj != null && long.TryParse(sizeObj.ToString(), out long sz))
                                        fingerprint.StorageTotalBytes = sz;

                                    // Kernel name from PNP device ID e.g. USBSTOR\DISK -> disk.sys
                                    string caption = SafeGetString(disk, "Caption");
                                    if (!string.IsNullOrEmpty(fingerprint.Service) && string.IsNullOrEmpty(fingerprint.KernelName))
                                        fingerprint.KernelName = fingerprint.Service + ".sys";

                                    // Full device ID for storage child (USBSTOR\DISK&VEN_...)
                                    if (!string.IsNullOrEmpty(pnpDeviceId))
                                        fingerprint.DeviceId = pnpDeviceId;

                                    break;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"[CaptureExtendedDeviceInfo] WMI disk error: {ex.Message}");
                        }
                        finally
                        {
                            diskResults?.Dispose();
                        }
                    }
                    else if (!string.IsNullOrEmpty(fingerprint.Service) && string.IsNullOrEmpty(fingerprint.KernelName))
                    {
                        fingerprint.KernelName = fingerprint.Service + ".sys";
                    }

                    // Power state: default to D0 (active – device just inserted)
                    fingerprint.PowerState = "D0";

                    // Enhanced power management flag from registry properties
                    try
                    {
                        string propPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{fingerprint.Vid}&PID_{fingerprint.Pid}\{fingerprint.InstanceId}\Device Parameters";
                        using (RegistryKey propKey = Registry.LocalMachine.OpenSubKey(propPath))
                        {
                            if (propKey != null)
                            {
                                object epm = propKey.GetValue("EnhancedPowerManagementEnabled");
                                fingerprint.EnhancedPowerManagementEnabled = epm is int i && i != 0;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[CaptureExtendedDeviceInfo] EPM registry error: {ex.Message}");
                    }

                    // Bus type string
                    if (!string.IsNullOrEmpty(fingerprint.Service))
                    {
                        fingerprint.BusType = fingerprint.Service.Equals("usbstor", StringComparison.OrdinalIgnoreCase)
                            ? "USB (USBSTOR)"
                            : "USB";
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[CaptureExtendedDeviceInfo] Error: {ex.Message}");
                }
            }

            private string GenerateHash(List<string> values)
            {
                if (values == null || values.Count == 0)
                    return null;

                string combined = string.Join("|", values);
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(combined));
                    return Convert.ToBase64String(hash).Substring(0, 16);
                }
            }

            private int GetInterfaceCount(string devicePath)
            {
                try
                {
                    int count = 1;
                    int index = devicePath.IndexOf("&MI_", StringComparison.OrdinalIgnoreCase);
                    if (index >= 0)
                        count++;
                    return count;
                }
                catch
                {
                    return 1;
                }
            }

            public void DisplayIdentifiersTable(DeviceFingerprint fingerprint)
            {
                try
                {
                    Console.Clear();

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("╔════════════════════════════════════════════════════════════════════════════╗");
                    Console.WriteLine("║                    USB DEVICE IDENTIFIERS REPORT                          ║");
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.ResetColor();

                    // ── BASIC INFORMATION ──────────────────────────────────────
                    Console.WriteLine($"║ 📋 BASIC INFORMATION                                                        ║");
                    Console.WriteLine($"║   VID:................ {PadRight(fingerprint.Vid ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   PID:................ {PadRight(fingerprint.Pid ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Instance ID:........ {PadRight(TruncateString(fingerprint.InstanceId ?? "N/A", 40), 40)} ║");
                    Console.WriteLine($"║   Device Class (str):. {PadRight(fingerprint.DeviceClass ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Service:............ {PadRight(fingerprint.Service ?? "N/A", 40)} ║");

                    // ── PRIMARY IDENTIFIERS ────────────────────────────────────
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ 🔑 PRIMARY IDENTIFIERS                                                     ║");

                    string serialDisplay = !string.IsNullOrEmpty(fingerprint.SerialNumber)
                        ? $"✅ {TruncateString(fingerprint.SerialNumber, 37)}"
                        : "❌ Not Available";
                    ConsoleColor serialColor = !string.IsNullOrEmpty(fingerprint.SerialNumber) ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"║   Serial Number:...... ");
                    Console.ForegroundColor = serialColor;
                    Console.Write(PadRight(serialDisplay, 40));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    string containerDisplay = !string.IsNullOrEmpty(fingerprint.ContainerId)
                        ? $"✅ {TruncateString(fingerprint.ContainerId, 37)}"
                        : "❌ Not Available";
                    ConsoleColor containerColor = !string.IsNullOrEmpty(fingerprint.ContainerId) ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"║   Container ID:....... ");
                    Console.ForegroundColor = containerColor;
                    Console.Write(PadRight(containerDisplay, 40));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    string parentDisplay = !string.IsNullOrEmpty(fingerprint.ParentIdPrefix)
                        ? $"✅ {TruncateString(fingerprint.ParentIdPrefix, 37)}"
                        : "❌ Not Available";
                    ConsoleColor parentColor = !string.IsNullOrEmpty(fingerprint.ParentIdPrefix) ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"║   Parent ID Prefix:... ");
                    Console.ForegroundColor = parentColor;
                    Console.Write(PadRight(parentDisplay, 40));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    // ── DEVICE INFORMATION ────────────────────────────────────
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ 🖥️  DEVICE INFORMATION                                                      ║");
                    Console.WriteLine($"║   Description:........ {PadRight(TruncateString(fingerprint.Description ?? "N/A", 40), 40)} ║");
                    Console.WriteLine($"║   Manufacturer:....... {PadRight(TruncateString(fingerprint.Manufacturer ?? "N/A", 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.FriendlyName))
                        Console.WriteLine($"║   Friendly Name:...... {PadRight(TruncateString(fingerprint.FriendlyName, 40), 40)} ║");
                    Console.WriteLine($"║   Device Path:........ {PadRight(TruncateString(fingerprint.DevicePath ?? "N/A", 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.Win32Name))
                        Console.WriteLine($"║   Win32 Name:......... {PadRight(TruncateString(fingerprint.Win32Name, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.KernelName))
                        Console.WriteLine($"║   Kernel Module:...... {PadRight(TruncateString(fingerprint.KernelName, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.DeviceId))
                        Console.WriteLine($"║   Device ID:.......... {PadRight(TruncateString(fingerprint.DeviceId, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.ClassGuid))
                        Console.WriteLine($"║   Class GUID:......... {PadRight(TruncateString(fingerprint.ClassGuid, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.DriverName))
                        Console.WriteLine($"║   Driver Name:........ {PadRight(TruncateString(fingerprint.DriverName, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.DriverVersion))
                    {
                        string driverInfo = fingerprint.DriverVersion +
                            (!string.IsNullOrEmpty(fingerprint.DriverDate) ? $" ({fingerprint.DriverDate})" : "");
                        Console.WriteLine($"║   Driver Version:..... {PadRight(TruncateString(driverInfo, 40), 40)} ║");
                    }
                    if (!string.IsNullOrEmpty(fingerprint.BusType))
                        Console.WriteLine($"║   Bus Type:........... {PadRight(TruncateString(fingerprint.BusType, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.LocationInfo))
                        Console.WriteLine($"║   Location Info:...... {PadRight(TruncateString(fingerprint.LocationInfo, 40), 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.Address))
                        Console.WriteLine($"║   Address:............ {PadRight(fingerprint.Address, 40)} ║");
                    Console.WriteLine($"║   Service:............ {PadRight(fingerprint.Service ?? "N/A", 40)} ║");
                    if (!string.IsNullOrEmpty(fingerprint.Enumerator))
                        Console.WriteLine($"║   Enumerator:......... {PadRight(fingerprint.Enumerator, 40)} ║");
                    if (fingerprint.Capabilities != 0)
                    {
                        string capsStr = $"0x{fingerprint.Capabilities:X2} ({DecodeCapabilities(fingerprint.Capabilities)})";
                        Console.WriteLine($"║   Capabilities:....... {PadRight(TruncateString(capsStr, 40), 40)} ║");
                    }
                    if (!string.IsNullOrEmpty(fingerprint.PowerState))
                        Console.WriteLine($"║   Power State:........ {PadRight(GetPowerStateDescription(fingerprint.PowerState), 40)} ║");
                    if (fingerprint.StorageTotalBytes > 0)
                    {
                        string sizeStr = FormatStorageSize(fingerprint.StorageTotalBytes);
                        Console.WriteLine($"║   Size:............... {PadRight(TruncateString(sizeStr, 40), 40)} ║");
                    }

                    string firstTimeStr = fingerprint.FirstInstallTime != DateTime.MinValue
                        ? fingerprint.FirstInstallTime.ToString("yyyy-MM-dd HH:mm:ss")
                        : "N/A";
                    string lastTimeStr = fingerprint.LastConnectedTime != DateTime.MinValue
                        ? fingerprint.LastConnectedTime.ToString("yyyy-MM-dd HH:mm:ss")
                        : "N/A";
                    Console.WriteLine($"║   First Install Date:. {PadRight(firstTimeStr, 40)} ║");
                    Console.WriteLine($"║   Last Arrival Date:.. {PadRight(lastTimeStr, 40)} ║");
                    Console.WriteLine($"║   Enhanced Power Mgmt: {PadRight(fingerprint.EnhancedPowerManagementEnabled ? "Enabled" : "Disabled", 40)} ║");

                    // ── USB DESCRIPTORS ───────────────────────────────────────
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ 🔌 USB DESCRIPTORS                                                          ║");
                    {
                        string usbClassDesc = fingerprint.UsbDeviceClass == 0x00
                            ? "Generic/Composite - see interfaces"
                            : fingerprint.UsbDeviceClass.ToString();
                        Console.WriteLine($"║   USB Device Class:... 0x{fingerprint.UsbDeviceClass:X2} ({PadRight(usbClassDesc, 30)}) ║");
                        Console.WriteLine($"║   USB SubClass:....... 0x{fingerprint.UsbDeviceSubClass:X2}                                       ║");
                        Console.WriteLine($"║   USB Protocol:....... 0x{fingerprint.UsbDeviceProtocol:X2}                                       ║");

                        string ifClassName  = HIDClassifier.GetClassName(fingerprint.InterfaceClass);
                        string ifSubCls     = HIDClassifier.GetSubClassName(fingerprint.InterfaceClass, fingerprint.InterfaceSubClass);
                        string ifProto      = HIDClassifier.GetProtocolName(fingerprint.InterfaceClass, fingerprint.InterfaceSubClass, fingerprint.InterfaceProtocol);
                        Console.WriteLine($"║   Interface Class:.... 0x{fingerprint.InterfaceClass:X2} ({PadRight(ifClassName, 30)}) ║");
                        Console.WriteLine($"║   Interface SubClass:. 0x{fingerprint.InterfaceSubClass:X2} ({PadRight(ifSubCls, 30)}) ║");
                        Console.WriteLine($"║   Interface Protocol:. 0x{fingerprint.InterfaceProtocol:X2} ({PadRight(ifProto, 30)}) ║");
                    }
                    Console.WriteLine($"║   Interface Numbers:.. {PadRight(fingerprint.InterfaceNumbers ?? fingerprint.InterfaceNumber ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Max Packet Size 0:.. {PadRight(fingerprint.MaxPacketSize0.ToString(), 40)} ║");
                    Console.WriteLine($"║   bcdUSB:............. 0x{fingerprint.BcdUSB:X4} ({GetUsbVersionString(fingerprint.BcdUSB),-31}) ║");
                    Console.WriteLine($"║   bcdDevice:.......... 0x{fingerprint.BcdDevice:X4}                                       ║");
                    Console.WriteLine($"║   Num Configurations:. {PadRight(fingerprint.NumConfigurations.ToString(), 40)} ║");
                    Console.WriteLine($"║   Num Interfaces:..... {PadRight(fingerprint.NumInterfaces.ToString(), 40)} ║");
                    {
                        string attrDesc = (fingerprint.ConfigurationAttributes & 0xC0) switch
                        {
                            0xC0 => "Self Powered",
                            0xE0 => "Self Powered + Remote Wakeup",
                            _    => "Bus Powered"
                        };
                        Console.WriteLine($"║   Config Attributes:.. 0x{fingerprint.ConfigurationAttributes:X2} ({PadRight(attrDesc, 31)}) ║");
                    }
                    Console.WriteLine($"║   Max Power (mA):..... {PadRight((fingerprint.MaxPower * 2).ToString(), 40)} ║");

                    // ── HASH INFORMATION ──────────────────────────────────────
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"║ 🔐 HASH INFORMATION & SECURITY                                             ║");
                    Console.ResetColor();
                    Console.WriteLine($"║   Descriptor Hash:.... {PadRight(fingerprint.DescriptorHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║     └─ Device descriptor + Config + Interfaces + Endpoints              ║");
                    Console.WriteLine($"║   Interface Hash:..... {PadRight(fingerprint.InterfaceDescriptorHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║     └─ Interface Class/SubClass/Protocol details                        ║");
                    Console.WriteLine($"║   Endpoint Hash:...... {PadRight(fingerprint.EndpointDescriptorHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║     └─ All endpoint addresses, types, max packet sizes                  ║");
                    if (!string.IsNullOrEmpty(fingerprint.BosHash))
                    {
                        Console.WriteLine($"║   BOS Hash:........... {PadRight(TruncateString(fingerprint.BosHash, 40), 40)} ║");
                        Console.WriteLine($"║     └─ USB 3.0+ device capabilities                                  ║");
                    }
                    Console.WriteLine($"║   HWID Hash:.......... {PadRight(fingerprint.HardwareIdHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Compatible Hash:.... {PadRight(fingerprint.CompatibleIdHash ?? "N/A", 40)} ║");

                    // ── FORENSIC HISTORY ──────────────────────────────────────
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"║ 📊 FORENSIC HISTORY                                                        ║");
                        Console.ResetColor();

                        DeviceHistoryRecord history = HistoryManager?.GetHistory(fingerprint);
                        if (history != null)
                        {
                            Console.WriteLine($"║   First Observed:..... {PadRight(history.FirstObservedTime ?? "N/A", 40)} ║");
                            Console.WriteLine($"║   Last Observed:...... {PadRight(history.LastObservedTime ?? "N/A", 40)} ║");
                            Console.WriteLine($"║   Total Observations: {PadRight(history.TotalObservations.ToString(), 40)} ║");

                            string statusText = history.IsWhitelisted
                                ? $"WHITELISTED (at {history.WhitelistedAt})"
                                : "Not whitelisted";
                            ConsoleColor statusColor = history.IsWhitelisted ? ConsoleColor.Green : ConsoleColor.Yellow;
                            Console.Write($"║   Whitelisted:........ ");
                            Console.ForegroundColor = statusColor;
                            Console.Write(PadRight(statusText, 40));
                            Console.ResetColor();
                            Console.WriteLine(" ║");

                            if (history.Events?.Count > 0)
                            {
                                var eventSummary = string.Join(", ", history.Events
                                    .GroupBy(e => e.EventType)
                                    .Select(g => g.Count() == 1 ? g.Key : $"{g.Key} x{g.Count()}"));
                                Console.WriteLine($"║   Events Logged:...... {PadRight(TruncateString(eventSummary, 40), 40)} ║");
                            }
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"║   ⭐ First time this device has been seen.                          ║");
                            Console.ResetColor();
                        }
                    }

                    // ── DEVICE CLASSIFICATION ─────────────────────────────────
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"║ 🎯 DEVICE CLASSIFICATION                                                   ║");
                        Console.ResetColor();

                        string deviceTypes = fingerprint.DeviceTypes ?? "Unknown / Not classified";
                        Console.WriteLine($"║   Device Type:........ {PadRight(deviceTypes, 40)} ║");

                        var allIfaces = fingerprint.AllInterfaces;
                        if (allIfaces != null && allIfaces.Count > 0)
                        {
                            var warnings = HIDClassifier.DetectSuspiciousCombinations(allIfaces);
                            if (warnings.Count > 0)
                            {
                                foreach (var (severity, message) in warnings)
                                {
                                    string[] lines = message.Split('\n');
                                    if (severity == "CRITICAL")
                                    {
                                        Console.ForegroundColor = ConsoleColor.Red;
                                        Console.WriteLine($"║ 🚨 CRITICAL: {PadRight(lines[0], 50)} ║");
                                        for (int li = 1; li < lines.Length; li++)
                                            Console.WriteLine($"║   {PadRight(lines[li].TrimStart(), 56)} ║");
                                    }
                                    else
                                    {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                        Console.WriteLine($"║ ⚠️  WARNING: {PadRight(lines[0], 51)} ║");
                                        for (int li = 1; li < lines.Length; li++)
                                            Console.WriteLine($"║   {PadRight(lines[li].TrimStart(), 56)} ║");
                                    }
                                    Console.ResetColor();
                                }
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"║   ✅ No suspicious interface combinations detected.              ║");
                                Console.ResetColor();
                            }
                        }
                    }

                    // ── HARDWARE IDs ──────────────────────────────────────────
                    if (fingerprint.HardwareIds?.Any() == true)
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 🔧 HARDWARE IDs ({fingerprint.HardwareIds.Count})                                                     ║");
                        for (int i = 0; i < Math.Min(fingerprint.HardwareIds.Count, 3); i++)
                            Console.WriteLine($"║   {i + 1}. {PadRight(TruncateString(fingerprint.HardwareIds[i], 46), 46)} ║");
                        if (fingerprint.HardwareIds.Count > 3)
                            Console.WriteLine($"║   ... and {fingerprint.HardwareIds.Count - 3} more                                           ║");
                    }

                    // ── STORAGE INFORMATION ───────────────────────────────────
                    if (fingerprint.VolumeSerialNumber?.Any() == true || fingerprint.StorageTotalBytes > 0)
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 💾 STORAGE INFORMATION                                                    ║");
                        if (!string.IsNullOrEmpty(fingerprint.VolumeSerialNumber))
                            Console.WriteLine($"║   Volume Serial:..... {PadRight(fingerprint.VolumeSerialNumber, 40)} ║");
                        if (fingerprint.StorageTotalBytes > 0)
                            Console.WriteLine($"║   Capacity:.......... {PadRight(TruncateString(FormatStorageSize(fingerprint.StorageTotalBytes), 40), 40)} ║");
                    }

                    // ── SCSI INQUIRY ──────────────────────────────────────────
                    if (fingerprint.ScsiVendor?.Any() == true)
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 🔧 SCSI INQUIRY DATA                                                       ║");
                        Console.WriteLine($"║   Vendor:............ {PadRight(fingerprint.ScsiVendor ?? "N/A", 40)} ║");
                        Console.WriteLine($"║   Product:........... {PadRight(fingerprint.ScsiProduct ?? "N/A", 40)} ║");
                        Console.WriteLine($"║   Revision:.......... {PadRight(fingerprint.ScsiRevision ?? "N/A", 40)} ║");
                    }

                    // ── TIMESTAMP INFORMATION ─────────────────────────────────
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ ⏰ TIMESTAMP INFORMATION                                                   ║");
                    Console.WriteLine($"║   First Install Time:. {PadRight(firstTimeStr, 40)} ║");
                    Console.WriteLine($"║   Last Connected Time: {PadRight(lastTimeStr, 40)} ║");
                    Console.WriteLine($"║   Enumeration Time:... {PadRight(fingerprint.EnumerationTimeMs + " ms", 40)} ║");

                    // ── FINGERPRINT & SCORE ───────────────────────────────────
                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    string fingerprintHash = fingerprint.GenerateFingerprintHash();
                    Console.Write($"║ 🆔 FINGERPRINT: ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write(PadRight(fingerprintHash, 44));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    Console.Write($"║   Generated from ");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{fingerprint.IdentifierCount}".PadRight(3));
                    Console.ResetColor();
                    Console.WriteLine($" identifiers                                               ║");

                    int reliabilityScore = CalculateReliabilityScore(fingerprint);
                    string reliabilityBar = GetReliabilityBar(reliabilityScore);
                    Console.Write($"║   Reliability:........ ");
                    if (reliabilityScore >= 80)
                        Console.ForegroundColor = ConsoleColor.Green;
                    else if (reliabilityScore >= 50)
                        Console.ForegroundColor = ConsoleColor.Yellow;
                    else
                        Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write(reliabilityBar);
                    Console.ResetColor();
                    Console.Write($" {reliabilityScore}%");
                    Console.WriteLine("                                          ║");

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("╚════════════════════════════════════════════════════════════════════════════╝");
                    Console.ResetColor();
                    Console.WriteLine();

                    LogTableToFile(fingerprint);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error displaying table: {ex.Message}");
                }
            }

            // ── DISPLAY HELPER METHODS ────────────────────────────────────────

            private static string GetUsbVersionString(ushort bcdUsb) =>
                bcdUsb switch
                {
                    0x0110 => "USB 1.1",
                    0x0200 => "USB 2.0",
                    0x0300 => "USB 3.0",
                    0x0310 => "USB 3.1",
                    0x0320 => "USB 3.2",
                    0x0400 => "USB 4.0",
                    _ => $"v{(bcdUsb >> 8) & 0xFF}.{(bcdUsb >> 4) & 0xF}{bcdUsb & 0xF}"
                };

            private static string FormatStorageSize(long bytes)
            {
                const long BytesPerGb  = 1_000_000_000L;
                const long BytesPerGib = 1024L * 1024L * 1024L;
                double gb  = bytes / (double)BytesPerGb;
                double gib = bytes / (double)BytesPerGib;
                return $"{gb:F1} GB / {gib:F1} GiB ({bytes:N0} Bytes)";
            }

            private static string GetPowerStateDescription(string state) =>
                state switch
                {
                    "D0" => "D0 (Full Power)",
                    "D1" => "D1 (Low Power)",
                    "D2" => "D2 (Low Power)",
                    "D3" => "D3 (Off / Suspended)",
                    _    => state
                };

            private static string DecodeCapabilities(uint caps)
            {
                var flags = new List<string>();
                if ((caps & 0x0001) != 0) flags.Add("Lockable");
                if ((caps & 0x0002) != 0) flags.Add("EjectSupported");
                if ((caps & 0x0004) != 0) flags.Add("Removable");
                if ((caps & 0x0008) != 0) flags.Add("DockDevice");
                if ((caps & 0x0010) != 0) flags.Add("UniqueID");
                if ((caps & 0x0020) != 0) flags.Add("SilentInstall");
                if ((caps & 0x0040) != 0) flags.Add("RawDeviceOk");
                if ((caps & 0x0080) != 0) flags.Add("SurpriseRemovalOk");
                return flags.Count > 0 ? string.Join(", ", flags) : "None";
            }

            // ===== HELPER METHODS =====
            private string PadRight(string text, int totalWidth)
            {
                if (string.IsNullOrEmpty(text)) text = "N/A";
                if (text.Length > totalWidth) text = text.Substring(0, totalWidth - 3) + "...";
                return text.PadRight(totalWidth);
            }

            private string TruncateString(string text, int maxLength)
            {
                if (string.IsNullOrEmpty(text)) return "N/A";
                return text.Length <= maxLength ? text : text.Substring(0, maxLength - 3) + "...";
            }

            private void LogTableToFile(DeviceFingerprint fingerprint)
            {
                try
                {
                    string logPath = Path.Combine(Application.StartupPath, "device_log.txt");
                    using (StreamWriter writer = new StreamWriter(logPath, true))
                    {
                        writer.WriteLine($"\n{DateTime.Now:yyyy-MM-dd HH:mm:ss} - DEVICE CONNECTED");
                        writer.WriteLine($"VID:PID: {fingerprint.Vid}:{fingerprint.Pid}");
                        writer.WriteLine($"Description: {fingerprint.Description ?? "Unknown"}");
                        writer.WriteLine($"Manufacturer: {fingerprint.Manufacturer ?? "Unknown"}");
                        writer.WriteLine($"Serial: {fingerprint.SerialNumber ?? "NOT AVAILABLE"}");
                        writer.WriteLine($"ContainerId: {fingerprint.ContainerId ?? "NOT AVAILABLE"}");
                        writer.WriteLine($"ParentIdPrefix: {fingerprint.ParentIdPrefix ?? "NOT AVAILABLE"}");
                        writer.WriteLine($"First Install: {fingerprint.FirstInstallTime:yyyy-MM-dd HH:mm:ss}");
                        writer.WriteLine($"Class (str): {fingerprint.DeviceClass ?? "Unknown"}");
                        writer.WriteLine($"USB Class: 0x{fingerprint.UsbDeviceClass:X2}");
                        writer.WriteLine($"Interface Class: 0x{fingerprint.InterfaceClass:X2} ({HIDClassifier.GetClassName(fingerprint.InterfaceClass)})");
                        writer.WriteLine($"Interface SubClass: 0x{fingerprint.InterfaceSubClass:X2} ({HIDClassifier.GetSubClassName(fingerprint.InterfaceClass, fingerprint.InterfaceSubClass)})");
                        writer.WriteLine($"Interface Protocol: 0x{fingerprint.InterfaceProtocol:X2} ({HIDClassifier.GetProtocolName(fingerprint.InterfaceClass, fingerprint.InterfaceSubClass, fingerprint.InterfaceProtocol)})");
                        writer.WriteLine($"Device Types: {fingerprint.DeviceTypes ?? "Unknown"}");
                        writer.WriteLine($"Service: {fingerprint.Service ?? "Unknown"}");
                        writer.WriteLine($"Descriptor Hash: {fingerprint.DescriptorHash ?? "N/A"}");
                        writer.WriteLine($"Fingerprint: {fingerprint.GenerateFingerprintHash()}");
                        writer.WriteLine($"Reliability: {CalculateReliabilityScore(fingerprint)}%");
                        writer.WriteLine(new string('-', 60));
                    }
                }
                catch { }
            }

            private int CalculateReliabilityScore(DeviceFingerprint f)
            {
                int score = 0;
                if (!string.IsNullOrEmpty(f.SerialNumber)) score += 40;
                if (!string.IsNullOrEmpty(f.ContainerId)) score += 30;
                if (!string.IsNullOrEmpty(f.ParentIdPrefix)) score += 20;
                if (f.FirstInstallTime != DateTime.MinValue) score += 15;
                if (!string.IsNullOrEmpty(f.VolumeSerialNumber)) score += 10;
                if (f.HardwareIds?.Any() == true) score += 5;
                if (f.RegistryKeys?.Count > 1) score += 5;
                if (!string.IsNullOrEmpty(f.DescriptorHash)) score += 10;
                return Math.Min(score, 100);
            }

            private string GetReliabilityBar(int score)
            {
                int barLength = score / 10;
                string bar = new string('█', barLength);
                string empty = new string('░', 10 - barLength);
                return $"[{bar}{empty}]";
            }

            private void CaptureRegistryIdentifiers(DeviceFingerprint fingerprint)
            {
                fingerprint.RegistryKeys = new List<string>();

                // Enumerate ALL device keys under USB, not just 4 hardcoded paths
                string usbBase = @"SYSTEM\CurrentControlSet\Enum\USB";
                using (RegistryKey usbRoot = Registry.LocalMachine.OpenSubKey(usbBase))
                {
                    if (usbRoot != null)
                    {
                        foreach (string deviceKey in usbRoot.GetSubKeyNames())
                        {
                            if (deviceKey.StartsWith($"VID_{fingerprint.Vid}&PID_{fingerprint.Pid}", StringComparison.OrdinalIgnoreCase))
                            {
                                using (RegistryKey vidPidKey = usbRoot.OpenSubKey(deviceKey))
                                {
                                    foreach (string instanceKey in vidPidKey.GetSubKeyNames())
                                    {
                                        string fullPath = $@"{usbBase}\{deviceKey}\{instanceKey}";
                                        fingerprint.RegistryKeys.Add(fullPath);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            private void CaptureTimestamps(DeviceFingerprint fingerprint)
            {
                string[] timestampProps = new[] { "0064", "0065", "0066", "0067" };
                Guid propertyGuid = new Guid("83da6326-97a6-4088-9453-a1923f573b29");
                foreach (string regPath in fingerprint.RegistryKeys)
                {
                    string propPath = $@"{regPath}\Properties\{{{propertyGuid}}}";
                    Debug.WriteLine($"Checking timestamps at: {propPath}");
                    try
                    {
                        using (RegistryKey propKey = Registry.LocalMachine.OpenSubKey(propPath))
                        {
                            if (propKey != null)
                            {
                                foreach (string prop in timestampProps)
                                {
                                    byte[] timestampData = propKey.GetValue(prop) as byte[];
                                    if (timestampData?.Length == 8)
                                    {
                                        long fileTime = BitConverter.ToInt64(timestampData, 0);
                                        DateTime timestamp = DateTime.FromFileTime(fileTime);
                                        switch (prop)
                                        {
                                            case "0064": fingerprint.FirstInstallTime = timestamp; break;
                                            case "0066": fingerprint.LastConnectedTime = timestamp; break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (SecurityException ex)
                    {
                        Debug.WriteLine($"Registry access denied (run as admin to fix): {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error reading timestamps: {ex.Message}");
                    }
                }
            }

            private string GetSerialNumber(string vid, string pid, string instanceId)
            {
                try
                {
                    if (!string.IsNullOrEmpty(instanceId) && instanceId != "Unknown" &&
                        !instanceId.Contains("&") && !instanceId.Contains("#") && instanceId.Length > 5)
                        return instanceId;

                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string serial = key.GetValue("SerialNumber")?.ToString();
                            if (!string.IsNullOrEmpty(serial)) return serial;
                        }
                    }
                }
                catch { }
                return null;
            }

            private string GetContainerId(string vid, string pid, string instanceId)
            {
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";

                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            object value = key.GetValue("ContainerID");

                            if (value is string s)
                                return s;

                            if (value is byte[] bytes && bytes.Length == 16)
                                return new Guid(bytes).ToString();
                        }
                    }
                }
                catch { }

                return null;
            }

            private string GetParentIdPrefix(string vid, string pid)
            {
                try
                {
                    string basePath = @"SYSTEM\CurrentControlSet\Enum\USB";
                    string vidPid = $"VID_{vid}&PID_{pid}";

                    using (RegistryKey usbRoot = Registry.LocalMachine.OpenSubKey(basePath))
                    {
                        foreach (string deviceKey in usbRoot.GetSubKeyNames())
                        {
                            if (!deviceKey.StartsWith(vidPid, StringComparison.OrdinalIgnoreCase))
                                continue;

                            Debug.WriteLine($"Found matching device key: {deviceKey}");
                            using (RegistryKey vidPidKey = usbRoot.OpenSubKey(deviceKey))
                            {
                                foreach (string instance in vidPidKey.GetSubKeyNames())
                                {
                                    Debug.WriteLine($"Checking instance: {instance}");
                                    using (RegistryKey instanceKey = vidPidKey.OpenSubKey(instance))
                                    {
                                        string parent = instanceKey?.GetValue("ParentIdPrefix")?.ToString();
                                        if (!string.IsNullOrEmpty(parent))
                                        {
                                            Debug.WriteLine($"ParentIdPrefix FOUND: {parent}");
                                            return parent;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"ParentIdPrefix error: {ex.Message}");
                }
                Debug.WriteLine("ParentIdPrefix NOT FOUND for this device.");
                return null;
            }

            private string GetServiceName(string vid, string pid, string instanceId)
            {
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                            return key.GetValue("Service")?.ToString();
                    }
                }
                catch { }
                return null;
            }

            private List<string> GetHardwareIds(string vid, string pid, string instanceId)
            {
                var ids = new List<string>();
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string[] hardwareIds = key.GetValue("HardwareID") as string[];
                            if (hardwareIds != null) ids.AddRange(hardwareIds);
                        }
                    }
                }
                catch { }
                return ids;
            }

            private List<string> GetCompatibleIds(string vid, string pid, string instanceId)
            {
                var ids = new List<string>();
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string[] compatibleIds = key.GetValue("CompatibleIDs") as string[];
                            if (compatibleIds != null) ids.AddRange(compatibleIds);
                        }
                    }
                }
                catch { }
                return ids;
            }

            private string GetDeviceDescription(string vid, string pid, string instanceId)
            {
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string desc = key.GetValue("DeviceDesc")?.ToString();
                            if (!string.IsNullOrEmpty(desc))
                            {
                                int semicolon = desc.IndexOf(';');
                                if (semicolon >= 0) return desc.Substring(semicolon + 1);
                                return desc;
                            }
                        }
                    }
                }
                catch { }
                return null;
            }

            private string GetManufacturer(string vid, string pid, string instanceId)
            {
                try
                {
                    string path = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string mfg = key.GetValue("Mfg")?.ToString();
                            if (!string.IsNullOrEmpty(mfg))
                            {
                                int semicolon = mfg.IndexOf(';');
                                if (semicolon >= 0) return mfg.Substring(semicolon + 1);
                                return mfg;
                            }
                        }
                    }
                }
                catch { }
                return null;
            }

            private string GetVolumeSerialNumber()
            {
                ManagementObjectCollection results = null;
                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=2");
                    results = searcher.Get();
                    foreach (ManagementObject disk in results)
                    {
                        string volumeSerial = disk["VolumeSerialNumber"]?.ToString();
                        if (!string.IsNullOrEmpty(volumeSerial)) return volumeSerial;
                    }
                }
                catch { }
                finally
                {
                    results?.Dispose();
                }
                return null;
            }

            private string GetInterfaceNumber(string devicePath)
            {
                int miIndex = devicePath.IndexOf("&MI_", StringComparison.OrdinalIgnoreCase);
                if (miIndex > 0 && miIndex + 5 < devicePath.Length)
                    return devicePath.Substring(miIndex + 4, 2);
                return null;
            }

            private string DetermineDeviceClass(string service, List<string> hardwareIds)
            {
                service = service?.ToLower();
                if (service == "kbdhid") return "Keyboard";
                if (service == "mouhid") return "Mouse";
                if (service == "hidusb") return "HID Device";
                if (service == "usbstor") return "Mass Storage";
                if (service == "usbrndis6") return "USB Network";
                if (service == "wudfwpdmtp") return "Mobile Device";
                if (service == "usbvideo") return "Camera";
                if (service == "usbprint") return "Printer";

                if (hardwareIds != null)
                {
                    foreach (var id in hardwareIds)
                    {
                        string lower = id.ToLower();
                        if (lower.Contains("kbd")) return "Keyboard";
                        if (lower.Contains("mouse") || lower.Contains("mou")) return "Mouse";
                        if (lower.Contains("storage") || lower.Contains("disk")) return "Mass Storage";
                    }
                }
                return "Other USB Device";
            }

            private int CountIdentifiers(DeviceFingerprint f)
            {
                int count = 0;
                if (!string.IsNullOrEmpty(f.Vid)) count++;
                if (!string.IsNullOrEmpty(f.Pid)) count++;
                if (!string.IsNullOrEmpty(f.SerialNumber)) count++;
                if (!string.IsNullOrEmpty(f.ContainerId)) count++;
                if (!string.IsNullOrEmpty(f.ParentIdPrefix)) count++;
                if (f.FirstInstallTime != DateTime.MinValue) count++;
                if (!string.IsNullOrEmpty(f.Service)) count++;
                if (f.HardwareIds?.Any() == true) count += f.HardwareIds.Count;
                if (!string.IsNullOrEmpty(f.Description)) count++;
                if (!string.IsNullOrEmpty(f.Manufacturer)) count++;
                if (!string.IsNullOrEmpty(f.DescriptorHash)) count++;
                if (!string.IsNullOrEmpty(f.HardwareIdHash)) count++;
                if (!string.IsNullOrEmpty(f.CompatibleIdHash)) count++;
                if (!string.IsNullOrEmpty(f.InterfaceDescriptorHash)) count++;
                if (!string.IsNullOrEmpty(f.EndpointDescriptorHash)) count++;
                if (f.InterfaceCount > 0) count++;
                if (f.NumConfigurations > 0) count++;
                if (f.NumInterfaces > 0) count++;
                return count;
            }
        }
    }

    // =============================
    // DEVICE FINGERPRINT CLASS
    // =============================
    public class DeviceFingerprint
    {
        // Basic identifiers
        public string VolumeSerialNumber { get; set; }
        public string ScsiVendor { get; set; }
        public string ScsiProduct { get; set; }
        public string ScsiRevision { get; set; }
        public string BosHash { get; set; }
        public string Vid { get; set; }
        public string Pid { get; set; }
        public string InstanceId { get; set; }
        public string DevicePath { get; set; }
        public string SerialNumber { get; set; }
        public string ContainerId { get; set; }
        public string ParentIdPrefix { get; set; }
        public string DeviceClass { get; set; }          // high‑level string (e.g., "Mass Storage")
        public string Service { get; set; }

        // USB descriptor fields (numeric)
        public byte UsbDeviceClass { get; set; }
        public byte UsbDeviceSubClass { get; set; }
        public byte UsbDeviceProtocol { get; set; }
        public byte MaxPacketSize0 { get; set; }
        public ushort BcdUSB { get; set; }
        public ushort BcdDevice { get; set; }
        public byte NumConfigurations { get; set; }
        public int NumInterfaces { get; set; }
        public byte ConfigurationAttributes { get; set; }
        public byte MaxPower { get; set; }
        public string InterfaceDescriptorHash { get; set; }
        public string EndpointDescriptorHash { get; set; }
        public string DescriptorHash { get; set; }

        // Interface descriptor fields (first interface, or most representative)
        public byte InterfaceClass { get; set; }
        public byte InterfaceSubClass { get; set; }
        public byte InterfaceProtocol { get; set; }

        // All interface class/subclass/protocol tuples for multi-interface devices
        [System.Xml.Serialization.XmlIgnore]
        public List<HIDClassifier.InterfaceInfo> AllInterfaces { get; set; }

        // HID device type classification (e.g., "🖱️ Mouse + ⌨️ Keyboard")
        public string DeviceTypes { get; set; }

        // Timestamps
        public DateTime FirstInstallTime { get; set; }
        public DateTime LastConnectedTime { get; set; }

        // Registry and hardware lists
        public List<string> RegistryKeys { get; set; }
        public List<string> HardwareIds { get; set; }
        public List<string> CompatibleIds { get; set; }

        // Descriptive info
        public string Description { get; set; }
        public string Manufacturer { get; set; }
        public string InterfaceNumber { get; set; }

        // Extended device information
        public string InterfaceNumbers { get; set; }           // Interface numbers from USB descriptor, e.g. "0" or "0, 1, 2"
        public string FriendlyName { get; set; }               // Windows friendly name
        public string Win32Name { get; set; }                  // Physical drive path e.g. \\.\PHYSICALDRIVE1
        public string KernelName { get; set; }                 // Kernel driver module e.g. disk.sys
        public string DeviceId { get; set; }                   // Full device instance ID (USBSTOR\DISK&VEN_...)
        public string ClassGuid { get; set; }                  // Device class GUID e.g. {4d36e967-...}
        public string DriverKeyName { get; set; }              // Registry driver key e.g. {GUID}\0001
        public string DriverName { get; set; }                 // Driver description
        public string DriverVersion { get; set; }              // Driver version string
        public string DriverDate { get; set; }                 // Driver date string
        public string BusType { get; set; }                    // Legacy bus type e.g. "USB"
        public string LocationInfo { get; set; }               // Location information e.g. "Port_#0019.Hub_#0001"
        public string Address { get; set; }                    // USB port address
        public string Enumerator { get; set; }                 // Enumerator name e.g. "USB" or "USBSTOR"
        public uint Capabilities { get; set; }                 // Device capabilities bitmask
        public string PowerState { get; set; }                 // Power state e.g. "D0"
        public bool EnhancedPowerManagementEnabled { get; set; } // Enhanced power management flag
        public long StorageTotalBytes { get; set; }            // Total storage capacity in bytes (storage devices)

        // Timing
        public long InsertionTimeMs { get; set; }
        public long EnumerationTimeMs { get; set; }

        // Hashes
        public string HardwareIdHash { get; set; }
        public string CompatibleIdHash { get; set; }

        // Interface count & volume serial
        public int InterfaceCount { get; set; }
       

        // Metadata
        public DateTime CaptureTime { get; set; }
        public int IdentifierCount { get; set; }

        public DeviceFingerprint()
        {
            RegistryKeys = new List<string>();
            HardwareIds = new List<string>();
            CompatibleIds = new List<string>();
            AllInterfaces = new List<HIDClassifier.InterfaceInfo>();
        }

        public string GenerateFingerprintHash()
        {
            var components = new List<string>();

            components.Add($"{Vid}:{Pid}");

            if (!string.IsNullOrEmpty(SerialNumber))
                components.Add($"SERIAL:{SerialNumber}");

            if (!string.IsNullOrEmpty(ContainerId))
                components.Add($"CID:{ContainerId}");

            if (!string.IsNullOrEmpty(ParentIdPrefix))
                components.Add($"PREFIX:{ParentIdPrefix}");

            if (FirstInstallTime != DateTime.MinValue)
                components.Add($"FIRST:{FirstInstallTime.Ticks}");

            if (!string.IsNullOrEmpty(DeviceClass))
                components.Add($"CLASS:{DeviceClass}");

            if (!string.IsNullOrEmpty(Service))
                components.Add($"SERVICE:{Service}");

            if (HardwareIds?.Any() == true)
                components.Add($"HW:{string.Join("|", HardwareIds)}");

            if (!string.IsNullOrEmpty(VolumeSerialNumber))
                components.Add($"VOL:{VolumeSerialNumber}");

            if (!string.IsNullOrEmpty(HardwareIdHash))
                components.Add($"HWHASH:{HardwareIdHash}");

            if (!string.IsNullOrEmpty(CompatibleIdHash))
                components.Add($"COMPHASH:{CompatibleIdHash}");

            components.Add($"IFACE:{InterfaceCount}");

            if (EnumerationTimeMs > 0)
                components.Add($"ENUM:{EnumerationTimeMs}");

            // USB descriptor components
            if (!string.IsNullOrEmpty(DescriptorHash))
                components.Add($"DESC:{DescriptorHash}");
            if (!string.IsNullOrEmpty(InterfaceDescriptorHash))
                components.Add($"IFACEHASH:{InterfaceDescriptorHash}");
            if (!string.IsNullOrEmpty(EndpointDescriptorHash))
                components.Add($"EPHASH:{EndpointDescriptorHash}");
            if (NumConfigurations > 0)
                components.Add($"NUMCFG:{NumConfigurations}");
            if (MaxPacketSize0 > 0)
                components.Add($"MPS:{MaxPacketSize0}");

            string combined = string.Join("||", components);

            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(combined));
                return Convert.ToBase64String(hash).Substring(0, 32);
            }
        }

        public bool Matches(DeviceFingerprint other)
        {
            if (other == null) return false;

            int matchCount = 0;
            int totalPossible = 0;

            if (!string.IsNullOrEmpty(this.SerialNumber) && !string.IsNullOrEmpty(other.SerialNumber))
            {
                totalPossible++;
                if (this.SerialNumber == other.SerialNumber) matchCount++;
            }

            if (!string.IsNullOrEmpty(this.ContainerId) && !string.IsNullOrEmpty(other.ContainerId))
            {
                totalPossible++;
                if (this.ContainerId == other.ContainerId) matchCount++;
            }

            if (!string.IsNullOrEmpty(this.ParentIdPrefix) && !string.IsNullOrEmpty(other.ParentIdPrefix))
            {
                totalPossible++;
                if (this.ParentIdPrefix == other.ParentIdPrefix) matchCount++;
            }

            if (this.FirstInstallTime != DateTime.MinValue && other.FirstInstallTime != DateTime.MinValue)
            {
                totalPossible++;
                if (this.FirstInstallTime == other.FirstInstallTime) matchCount++;
            }

            if (!string.IsNullOrEmpty(this.VolumeSerialNumber) && !string.IsNullOrEmpty(other.VolumeSerialNumber))
            {
                totalPossible++;
                if (this.VolumeSerialNumber == other.VolumeSerialNumber) matchCount++;
            }

            if (this.HardwareIds?.Any() == true && other.HardwareIds?.Any() == true)
            {
                totalPossible++;
                if (this.HardwareIds.Intersect(other.HardwareIds).Any()) matchCount++;
            }

            if (this.EnumerationTimeMs > 0 && other.EnumerationTimeMs > 0)
            {
                totalPossible++;
                long diff = Math.Abs(this.EnumerationTimeMs - other.EnumerationTimeMs);
                if (diff < 200) matchCount++;
            }

            // Compare descriptor hash if both exist
            if (!string.IsNullOrEmpty(this.DescriptorHash) && !string.IsNullOrEmpty(other.DescriptorHash))
            {
                totalPossible++;
                if (this.DescriptorHash == other.DescriptorHash) matchCount++;
            }

            return totalPossible >= 2 && matchCount >= 2;
        }
    }
}
