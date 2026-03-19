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

        public USBMessageWindow()
        {
            CreateHandle(new CreateParams());
            RegisterForUsbNotifications();
            deviceIdentifier = new DeviceIdentifier();
            whitelist = LoadWhitelist();
            historyManager = new DeviceHistoryManager();
            deviceIdentifier.HistoryManager = historyManager;
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

            using (var form = new Form())
            {
                form.Text = "USB Guardian - Unknown Device Detected";
                form.Size = new Size(500, 400);
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;

                var lblTitle = new Label
                {
                    Text = "⚠ Unknown USB Device Detected",
                    Font = new Font("Arial", 12, FontStyle.Bold),
                    Location = new Point(20, 20),
                    Size = new Size(450, 30),
                    TextAlign = ContentAlignment.MiddleCenter
                };

                var txtDetails = new TextBox
                {
                    Location = new Point(20, 60),
                    Size = new Size(450, 200),
                    Multiline = true,
                    ReadOnly = true,
                    ScrollBars = ScrollBars.Vertical,
                    Text = GetDeviceDetailsText(device)
                };

                var btnAllow = new Button
                {
                    Text = "Allow This Device",
                    Location = new Point(20, 280),
                    Size = new Size(140, 40),
                    BackColor = Color.LightGreen
                };

                var btnBlock = new Button
                {
                    Text = "Block Device",
                    Location = new Point(180, 280),
                    Size = new Size(140, 40),
                    BackColor = Color.LightCoral
                };

                var btnAllowAlways = new Button
                {
                    Text = "Allow & Add to Whitelist",
                    Location = new Point(340, 280),
                    Size = new Size(140, 40),
                    BackColor = Color.LightBlue
                };

                var chkRemember = new CheckBox
                {
                    Text = "Remember this device (add to whitelist)",
                    Location = new Point(20, 330),
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

                form.Controls.AddRange(new Control[] {
                    lblTitle, txtDetails, btnAllow, btnBlock, btnAllowAlways, chkRemember
                });

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
                Debug.WriteLine("🔒 BLOCKING DEVICE...");

                string instancePath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(instancePath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("ConfigFlags", 4, RegistryValueKind.DWord);
                        Debug.WriteLine("Device disabled via registry");
                    }
                }

                ShowBalloonTip("USB Device Blocked",
                    $"Unauthorized device {device.Description} has been blocked.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error blocking device: {ex.Message}");
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

                    Console.WriteLine($"║ 📋 BASIC INFORMATION                                                        ║");
                    Console.WriteLine($"║   VID:................ {PadRight(fingerprint.Vid ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   PID:................ {PadRight(fingerprint.Pid ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Instance ID:........ {PadRight(TruncateString(fingerprint.InstanceId ?? "N/A", 40), 40)} ║");
                    Console.WriteLine($"║   Device Class (str):. {PadRight(fingerprint.DeviceClass ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Service:............ {PadRight(fingerprint.Service ?? "N/A", 40)} ║");

                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ 🔑 PRIMARY IDENTIFIERS                                                     ║");

                    // Serial Number
                    string serialDisplay = !string.IsNullOrEmpty(fingerprint.SerialNumber)
                        ? $"✅ {TruncateString(fingerprint.SerialNumber, 38)}"
                        : "❌ Not Available";
                    ConsoleColor serialColor = !string.IsNullOrEmpty(fingerprint.SerialNumber) ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"║   Serial Number:...... ");
                    Console.ForegroundColor = serialColor;
                    Console.Write(PadRight(serialDisplay, 40));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    // Container ID
                    string containerDisplay = !string.IsNullOrEmpty(fingerprint.ContainerId)
                        ? $"✅ {TruncateString(fingerprint.ContainerId, 38)}"
                        : "❌ Not Available";
                    ConsoleColor containerColor = !string.IsNullOrEmpty(fingerprint.ContainerId) ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"║   Container ID:....... ");
                    Console.ForegroundColor = containerColor;
                    Console.Write(PadRight(containerDisplay, 40));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    // Parent ID Prefix
                    string parentDisplay = !string.IsNullOrEmpty(fingerprint.ParentIdPrefix)
                        ? $"✅ {TruncateString(fingerprint.ParentIdPrefix, 38)}"
                        : "❌ Not Available";
                    ConsoleColor parentColor = !string.IsNullOrEmpty(fingerprint.ParentIdPrefix) ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"║   Parent ID Prefix:... ");
                    Console.ForegroundColor = parentColor;
                    Console.Write(PadRight(parentDisplay, 40));
                    Console.ResetColor();
                    Console.WriteLine(" ║");

                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ 📝 DEVICE INFORMATION                                                      ║");
                    Console.WriteLine($"║   Description:........ {PadRight(TruncateString(fingerprint.Description ?? "N/A", 40), 40)} ║");
                    Console.WriteLine($"║   Manufacturer:....... {PadRight(TruncateString(fingerprint.Manufacturer ?? "N/A", 40), 40)} ║");
                    Console.WriteLine($"║   Interface Number:... {PadRight(fingerprint.InterfaceNumber ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Interface Count:.... {PadRight(fingerprint.InterfaceCount.ToString(), 40)} ║");
                    Console.WriteLine($"║   HWID Hash:.......... {PadRight(fingerprint.HardwareIdHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Compatible Hash:.... {PadRight(fingerprint.CompatibleIdHash ?? "N/A", 40)} ║");

                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ 🔌 USB DESCRIPTORS                                                          ║");
                    Console.WriteLine($"║   USB Device Class:... 0x{fingerprint.UsbDeviceClass:X2} ({fingerprint.UsbDeviceClass})           ║");
                    Console.WriteLine($"║   USB SubClass:....... 0x{fingerprint.UsbDeviceSubClass:X2}              ║");
                    Console.WriteLine($"║   USB Protocol:....... 0x{fingerprint.UsbDeviceProtocol:X2}              ║");
                    {
                        string ifClassName  = HIDClassifier.GetClassName(fingerprint.InterfaceClass);
                        string ifSubCls     = HIDClassifier.GetSubClassName(fingerprint.InterfaceClass, fingerprint.InterfaceSubClass);
                        string ifProto      = HIDClassifier.GetProtocolName(fingerprint.InterfaceClass, fingerprint.InterfaceSubClass, fingerprint.InterfaceProtocol);
                        Console.WriteLine($"║   Interface Class:.... 0x{fingerprint.InterfaceClass:X2} ({PadRight(ifClassName, 29)}) ║");
                        Console.WriteLine($"║   Interface SubClass:. 0x{fingerprint.InterfaceSubClass:X2} ({PadRight(ifSubCls, 29)}) ║");
                        Console.WriteLine($"║   Interface Protocol:. 0x{fingerprint.InterfaceProtocol:X2} ({PadRight(ifProto, 29)}) ║");
                    }
                    Console.WriteLine($"║   Max Packet Size 0:... {fingerprint.MaxPacketSize0}                      ║");
                    Console.WriteLine($"║   bcdUSB:.............. 0x{fingerprint.BcdUSB:X4}                         ║");
                    Console.WriteLine($"║   bcdDevice:........... 0x{fingerprint.BcdDevice:X4}                      ║");
                    Console.WriteLine($"║   Num Configurations:.. {fingerprint.NumConfigurations}                   ║");
                    Console.WriteLine($"║   Num Interfaces:...... {fingerprint.NumInterfaces}                        ║");
                    Console.WriteLine($"║   Config Attributes:... 0x{fingerprint.ConfigurationAttributes:X2}        ║");
                    Console.WriteLine($"║   Max Power (mA):...... {fingerprint.MaxPower * 2}                        ║");
                    Console.WriteLine($"║   Interface Hash:...... {PadRight(fingerprint.InterfaceDescriptorHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Endpoint Hash:....... {PadRight(fingerprint.EndpointDescriptorHash ?? "N/A", 40)} ║");
                    Console.WriteLine($"║   Descriptor Hash:..... {PadRight(fingerprint.DescriptorHash ?? "N/A", 40)} ║");

                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                    Console.WriteLine($"║ ⏰ TIMESTAMP INFORMATION                                                   ║");

                    string firstTime = fingerprint.FirstInstallTime != DateTime.MinValue
                        ? fingerprint.FirstInstallTime.ToString("yyyy-MM-dd HH:mm:ss")
                        : "N/A";
                    string lastTime = fingerprint.LastConnectedTime != DateTime.MinValue
                        ? fingerprint.LastConnectedTime.ToString("yyyy-MM-dd HH:mm:ss")
                        : "N/A";

                    Console.WriteLine($"║   First Install Time:. {PadRight(firstTime, 40)} ║");
                    Console.WriteLine($"║   Last Connected Time: {PadRight(lastTime, 40)} ║");
                    Console.WriteLine($"║   Enumeration Time:... {PadRight(fingerprint.EnumerationTimeMs + " ms", 40)} ║");

                    // Hardware IDs
                    if (fingerprint.HardwareIds?.Any() == true)
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 🔧 HARDWARE IDs ({fingerprint.HardwareIds.Count})                                                     ║");
                        for (int i = 0; i < Math.Min(fingerprint.HardwareIds.Count, 3); i++)
                        {
                            Console.WriteLine($"║   {i + 1}. {PadRight(TruncateString(fingerprint.HardwareIds[i], 46), 46)} ║");
                        }
                        if (fingerprint.HardwareIds.Count > 3)
                        {
                            Console.WriteLine($"║   ... and {fingerprint.HardwareIds.Count - 3} more                                           ║");
                        }
                    }

                    // Volume Info
                    // Volume Serial
                    if (fingerprint.VolumeSerialNumber? .Any() == true)
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 💾 STORAGE INFORMATION                                                    ║");
                        Console.WriteLine($"║   Volume Serial:..... {PadRight(fingerprint.VolumeSerialNumber, 40)} ║");
                    }

                    // SCSI Inquiry
                    if (fingerprint.ScsiVendor?.Any() == true) 
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 🔧 SCSI INQUIRY DATA                                                       ║");
                        Console.WriteLine($"║   Vendor:............ {PadRight(fingerprint.ScsiVendor ?? "N/A", 40)} ║");
                        Console.WriteLine($"║   Product:........... {PadRight(fingerprint.ScsiProduct ?? "N/A", 40)} ║");
                        Console.WriteLine($"║   Revision:.......... {PadRight(fingerprint.ScsiRevision ?? "N/A", 40)} ║");
                    }

                    // Registry Keys
                    if (fingerprint.RegistryKeys?.Any() == true)
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.WriteLine($"║ 📂 REGISTRY LOCATIONS ({fingerprint.RegistryKeys.Count})                                                ║");
                        foreach (string key in fingerprint.RegistryKeys.Take(2))
                        {
                            Console.WriteLine($"║   {PadRight(TruncateString(key, 52), 52)} ║");
                        }
                        if (fingerprint.RegistryKeys.Count > 2)
                        {
                            Console.WriteLine($"║   ... and {fingerprint.RegistryKeys.Count - 2} more                                           ║");
                        }
                    }

                    // ──────────────────────────────────────────
                    // DEVICE CLASSIFICATION
                    // ──────────────────────────────────────────
                    {
                        Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"║ 🎯 DEVICE CLASSIFICATION                                                   ║");
                        Console.ResetColor();

                        string deviceTypes = fingerprint.DeviceTypes ?? "Unknown / Not classified";
                        Console.WriteLine($"║   Device Type:........ {PadRight(deviceTypes, 40)} ║");

                        // Suspicious combination detection
                        var interfaces = fingerprint.AllInterfaces;
                        if (interfaces != null && interfaces.Count > 0)
                        {
                            var warnings = HIDClassifier.DetectSuspiciousCombinations(interfaces);
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

                    // ──────────────────────────────────────────
                    // FORENSIC HISTORY
                    // ──────────────────────────────────────────
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
                            Console.Write($"║   Status:............. ");
                            Console.ForegroundColor = statusColor;
                            Console.Write(PadRight(statusText, 40));
                            Console.ResetColor();
                            Console.WriteLine(" ║");
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"║   ⭐ First time this device has been seen.                          ║");
                            Console.ResetColor();
                        }
                    }

                    Console.WriteLine("╠════════════════════════════════════════════════════════════════════════════╣");

                    // Fingerprint and Score
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

                    // Reliability Score
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