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
            Application.Run(new USBApplicationContext());
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

        private static readonly Guid GUID_DEVINTERFACE_USB_DEVICE =
            new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED");

        private IntPtr notificationHandle;
        private DeviceIdentifier deviceIdentifier;
        private List<DeviceFingerprint> whitelist;
        private DeviceHistoryManager historyManager;
        private UsbGuardianCore guardianCore;

        public USBMessageWindow()
        {
            CreateHandle(new CreateParams());
            RegisterForUsbNotifications();
            deviceIdentifier = new DeviceIdentifier();
            whitelist = LoadWhitelist();
            historyManager = new DeviceHistoryManager();
            deviceIdentifier.HistoryManager = historyManager;

            // Initialize the 6-layer defense core
            guardianCore = new UsbGuardianCore();
            _ = guardianCore.InitializeAsync();

            // Auto-whitelist built-in devices so they are never shown in the unknown-device dialog
            AutoWhitelistBuiltInDevices();

            // Verify all critical safety systems are working before accepting USB events
            RunStartupSafetyTests();

            Debug.WriteLine("USB Guardian Started - Monitoring for USB devices...");
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
                // 6-LAYER SECURITY EVALUATION
                // =============================================
                DeviceEvaluationResult evalResult = guardianCore.EvaluateDevice(currentDevice);
                Debug.WriteLine($"[6-Layer] Threat={evalResult.OverallThreatLevel}, ShouldBlock={evalResult.ShouldBlock}");

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
                    Debug.WriteLine("✅ DEVICE ALLOWED - Found in whitelist");
                    matchedDevice.LastConnectedTime = DateTime.UtcNow;
                    SaveWhitelist();

                    historyManager.LogEvent(currentDevice, DeviceEventType.Whitelisted, "Matched existing whitelist entry");

                    ShowBalloonTip(
                        "USB Device Allowed",
                        $"{currentDevice.Description ?? "Unknown Device"} has been allowed.");
                }
                else
                {
                    Debug.WriteLine("❌ DEVICE NOT IN WHITELIST");
                    HandleUnknownDevice(currentDevice);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error processing USB device: {ex.Message}");
            }
        }

        private void HandleUnknownDevice(DeviceFingerprint device)
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

            using (var form = new Form())
            {
                form.Text = "USB Guardian - Unknown Device Detected";
                form.Size = new Size(500, mightBeBuiltIn ? 440 : 400);
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;

                string titleText = mightBeBuiltIn
                    ? "⚠ Possibly Built-In Device Detected"
                    : "⚠ Unknown USB Device Detected";

                var lblTitle = new Label
                {
                    Text = titleText,
                    Font = new Font("Arial", 12, FontStyle.Bold),
                    ForeColor = mightBeBuiltIn ? Color.DarkOrange : SystemColors.ControlText,
                    Location = new Point(20, 20),
                    Size = new Size(450, 30),
                    TextAlign = ContentAlignment.MiddleCenter
                };

                int detailsTop = 60;
                int detailsHeight = 200;

                Label lblWarning = null;
                if (mightBeBuiltIn)
                {
                    lblWarning = new Label
                    {
                        Text = "⚠ WARNING: This device may be an internal laptop component (keyboard, mouse, or trackpad). " +
                               "Blocking it could render your device unusable.",
                        Font = new Font("Arial", 9, FontStyle.Bold),
                        ForeColor = Color.DarkOrange,
                        BackColor = Color.LightYellow,
                        Location = new Point(20, 55),
                        Size = new Size(450, 50),
                        TextAlign = ContentAlignment.MiddleLeft
                    };
                    detailsTop = 115;
                    detailsHeight = 170;
                }

                var txtDetails = new TextBox
                {
                    Location = new Point(20, detailsTop),
                    Size = new Size(450, detailsHeight),
                    Multiline = true,
                    ReadOnly = true,
                    ScrollBars = ScrollBars.Vertical,
                    Text = GetDeviceDetailsText(device)
                };

                int btnTop = detailsTop + detailsHeight + 20;

                var btnAllow = new Button
                {
                    Text = "Allow This Device",
                    Location = new Point(20, btnTop),
                    Size = new Size(140, 40),
                    BackColor = Color.LightGreen
                };

                var btnBlock = new Button
                {
                    Text = "Block Device",
                    Location = new Point(180, btnTop),
                    Size = new Size(140, 40),
                    BackColor = Color.LightCoral,
                    Enabled = !mightBeBuiltIn
                };

                var btnAllowAlways = new Button
                {
                    Text = "Allow & Add to Whitelist",
                    Location = new Point(340, btnTop),
                    Size = new Size(140, 40),
                    BackColor = Color.LightBlue
                };

                var chkRemember = new CheckBox
                {
                    Text = "Remember this device (add to whitelist)",
                    Location = new Point(20, btnTop + 50),
                    Size = new Size(300, 30),
                    Checked = true
                };

                btnAllow.Click += (s, e) =>
                {
                    if (chkRemember.Checked)
                    {
                        whitelist.Add(device);
                        SaveWhitelist();
                        historyManager.LogEvent(device, DeviceEventType.Whitelisted, "User chose Allow & Remember");
                        ShowBalloonTip("Device Whitelisted",
                            $"{device.Description} has been added to the whitelist.");
                    }
                    form.DialogResult = DialogResult.OK;
                    form.Close();
                };

                btnBlock.Click += (s, e) =>
                {
                    BlockDevice(device);
                    historyManager.LogEvent(device, DeviceEventType.Blocked, "User manually blocked device");
                    form.DialogResult = DialogResult.No;
                    form.Close();
                };

                btnAllowAlways.Click += (s, e) =>
                {
                    whitelist.Add(device);
                    SaveWhitelist();
                    historyManager.LogEvent(device, DeviceEventType.Whitelisted, "User chose Allow & Add to Whitelist");
                    ShowBalloonTip("Device Whitelisted",
                        $"{device.Description} has been added to the whitelist.");
                    form.DialogResult = DialogResult.Yes;
                    form.Close();
                };

                var controls = new List<Control> { lblTitle, txtDetails, btnAllow, btnBlock, btnAllowAlways, chkRemember };
                if (lblWarning != null)
                    controls.Add(lblWarning);

                form.Controls.AddRange(controls.ToArray());

                form.ShowDialog();
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
                    var storageBlocker = new UsbStorageBlocker(guardianCore.EventLogger);
                    storageBlocker.BlockUsbStorageDevice(device);
                }
                else if (UsbStorageBlocker.IsHidDevice(device))
                {
                    // HID device (keyboard/mouse): ConfigFlags |= 0x100 is sufficient
                    Debug.WriteLine("🔒 HID device detected — using ConfigFlags registry block");
                    string instancePath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                    SetDeviceConfigFlags(instancePath, 0x100, "HID device");
                }
                else
                {
                    // Unknown device type: disable via WMI Win32_PnPEntity and set registry flags
                    Debug.WriteLine("🔒 Unknown device type — disabling via WMI and setting registry flags");
                    try
                    {
                        string wmiQuery = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{device.Vid}&PID_{device.Pid}%'";
                        using var searcher = new System.Management.ManagementObjectSearcher(wmiQuery);
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            obj.InvokeMethod("Disable", null);
                            Debug.WriteLine($"Unknown device disabled via WMI: {obj["DeviceID"]}");
                            break;
                        }
                    }
                    catch (Exception wmiEx)
                    {
                        Debug.WriteLine($"WMI disable failed for unknown device: {wmiEx.Message}");
                    }

                    string unknownPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                    SetDeviceConfigFlags(unknownPath, 0x100, "Unknown device");
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
                Debug.WriteLine("[StartupTest] All 5 startup safety tests PASSED.");
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

        // =============================
        // DEVICE IDENTIFIER CLASS
        // =============================
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
                    using (var searcher = new ManagementObjectSearcher(
                        "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'"))
                    {
                        foreach (ManagementObject disk in searcher.Get())
                        {
                            string pnpDeviceId = SafeGetString(disk, "PNPDeviceID");
                            if (!string.IsNullOrEmpty(pnpDeviceId) && pnpDeviceId.Contains($"VID_{vid}&PID_{pid}"))
                            {
                                physicalDrive = SafeGetString(disk, "DeviceID"); // e.g., \\.\PHYSICALDRIVE1
                                break;
                            }
                        }
                    }

                    if (string.IsNullOrEmpty(physicalDrive))
                        return null;

                    // Step 2: Get the disk drive's partitions
                    using (var partitionSearcher = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{physicalDrive}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))
                    {
                        foreach (ManagementObject partition in partitionSearcher.Get())
                        {
                            string partitionDeviceId = SafeGetString(partition, "DeviceID");
                            if (string.IsNullOrEmpty(partitionDeviceId))
                                continue;

                            // Step 3: Get logical disks from partition
                            using (var logicalSearcher = new ManagementObjectSearcher(
                                $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partitionDeviceId}'}} WHERE AssocClass=Win32_LogicalDiskToPartition"))
                            {
                                foreach (ManagementObject logical in logicalSearcher.Get())
                                {
                                    string volumeSerial = SafeGetString(logical, "VolumeSerialNumber");
                                    if (!string.IsNullOrEmpty(volumeSerial))
                                        return volumeSerial;
                                }
                            }
                        }
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
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'"))
                    {
                        foreach (ManagementObject disk in searcher.Get())
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
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[GetPhysicalDrivePath] Error: {ex.Message}");
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
                        try
                        {
                            using (var searcher = new ManagementObjectSearcher(
                                "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'"))
                            {
                                foreach (ManagementObject disk in searcher.Get())
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
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"[CaptureExtendedDeviceInfo] WMI disk error: {ex.Message}");
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
                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=2"))
                    {
                        foreach (ManagementObject disk in searcher.Get())
                        {
                            string volumeSerial = disk["VolumeSerialNumber"]?.ToString();
                            if (!string.IsNullOrEmpty(volumeSerial)) return volumeSerial;
                        }
                    }
                }
                catch { }
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