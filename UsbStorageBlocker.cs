using System;
using System.Diagnostics;
using System.Management;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Handles blocking of USB Mass Storage devices by safely ejecting volumes
    /// and setting registry flags that prevent re-enumeration.
    /// </summary>
    public class UsbStorageBlocker
    {
        // ConfigFlags bit values used to prevent Windows from re-enumerating the device
        private const int ConfigFlagDisabled = 0x100;   // CONFIGFLAG_DISABLED
        private const int ConfigFlagReinstall = 0x40;   // CONFIGFLAG_REINSTALL (prevents auto re-install)
        private const int ServiceDisabled = 4;           // SERVICE_DISABLED

        private readonly SecurityEventLogger _logger;

        public UsbStorageBlocker(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Determines whether a device fingerprint represents a USB Mass Storage device.
        /// </summary>
        public static bool IsUsbStorageDevice(DeviceFingerprint device)
        {
            return device.DeviceClass?.Contains("Storage", StringComparison.OrdinalIgnoreCase) == true
                || string.Equals(device.Service, "usbstor", StringComparison.OrdinalIgnoreCase)
                || string.Equals(device.Service, "disk", StringComparison.OrdinalIgnoreCase)
                || device.UsbDeviceClass == 0x08
                || device.InterfaceClass == 0x08;
        }

        /// <summary>
        /// Determines whether a device fingerprint represents a HID device (keyboard/mouse).
        /// </summary>
        public static bool IsHidDevice(DeviceFingerprint device)
        {
            return device.DeviceClass?.Contains("HID", StringComparison.OrdinalIgnoreCase) == true
                || string.Equals(device.Service, "kbdhid", StringComparison.OrdinalIgnoreCase)
                || string.Equals(device.Service, "mouhid", StringComparison.OrdinalIgnoreCase)
                || string.Equals(device.Service, "hidusb", StringComparison.OrdinalIgnoreCase)
                || device.UsbDeviceClass == 0x03
                || device.InterfaceClass == 0x03;
        }

        /// <summary>
        /// Fully blocks a USB Mass Storage device: ejects mounted volumes,
        /// dismounts the volume, and sets registry flags to prevent re-enumeration.
        /// Returns true if at least the eject or registry step succeeded.
        /// </summary>
        public bool BlockUsbStorageDevice(DeviceFingerprint device)
        {
            string vidPid = $"{device.Vid}:{device.Pid}";
            bool anySuccess = false;

            try
            {
                _logger.LogAttack(0, "StorageBlock", $"Blocking USB storage device {vidPid}", vidPid);

                // Step 1: Find and eject the drive letter(s) associated with this device
                bool ejected = EjectUsbVolume(device.Vid, device.Pid);
                if (ejected)
                {
                    anySuccess = true;
                    Debug.WriteLine($"[UsbStorageBlocker] Volume ejected for {vidPid}");
                }
                else
                {
                    Debug.WriteLine($"[UsbStorageBlocker] Eject did not complete for {vidPid} — continuing with registry block");
                }

                // Step 2: Set registry flags to prevent re-enumeration
                bool flagged = SetPermanentBlockFlags(device);
                if (flagged)
                {
                    anySuccess = true;
                    Debug.WriteLine($"[UsbStorageBlocker] Registry block flags set for {vidPid}");
                }

                _logger.LogCritical(0, "StorageBlock", $"USB storage block complete for {vidPid}: eject={ejected}, registry={flagged}", vidPid);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] BlockUsbStorageDevice failed: {ex.Message}");
            }

            return anySuccess;
        }

        /// <summary>
        /// Finds the logical drive letter(s) for the given VID/PID and ejects them
        /// using the WMI Win32_Volume Dismount method, then uses PowerShell as a fallback.
        /// Returns true if at least one volume was successfully ejected.
        /// </summary>
        public bool EjectUsbVolume(string vid, string pid)
        {
            bool ejected = false;
            try
            {
                // Resolve the physical drive associated with this VID/PID
                string physicalDrive = FindPhysicalDrive(vid, pid);
                if (string.IsNullOrEmpty(physicalDrive))
                {
                    Debug.WriteLine($"[UsbStorageBlocker] No physical drive found for VID_{vid}&PID_{pid}");
                    return false;
                }

                Debug.WriteLine($"[UsbStorageBlocker] Physical drive: {physicalDrive}");

                // Walk partitions → logical disks to get drive letters
                string partitionQuery = $"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{physicalDrive}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition";
                using var partSearcher = new ManagementObjectSearcher(partitionQuery);
                foreach (ManagementObject partition in partSearcher.Get())
                {
                    string partId = partition["DeviceID"]?.ToString();
                    if (string.IsNullOrEmpty(partId)) continue;

                    string logicalQuery = $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partId}'}} WHERE AssocClass=Win32_LogicalDiskToPartition";
                    using var logSearcher = new ManagementObjectSearcher(logicalQuery);
                    foreach (ManagementObject logical in logSearcher.Get())
                    {
                        string driveLetter = logical["DeviceID"]?.ToString(); // e.g., "F:"
                        if (string.IsNullOrEmpty(driveLetter)) continue;

                        Debug.WriteLine($"[UsbStorageBlocker] Attempting to dismount {driveLetter}");

                        // Try WMI Win32_Volume Dismount first
                        if (DismountVolumeWmi(driveLetter))
                        {
                            ejected = true;
                            Debug.WriteLine($"[UsbStorageBlocker] WMI dismount succeeded for {driveLetter}");
                        }
                        else
                        {
                            // Fallback: PowerShell dismount
                            if (DismountVolumePs(driveLetter))
                            {
                                ejected = true;
                                Debug.WriteLine($"[UsbStorageBlocker] PowerShell dismount succeeded for {driveLetter}");
                            }
                            else
                            {
                                Debug.WriteLine($"[UsbStorageBlocker] Both WMI and PowerShell dismount failed for {driveLetter}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] EjectUsbVolume error: {ex.Message}");
            }
            return ejected;
        }

        /// <summary>
        /// Dismounts a volume (by drive letter, e.g. "F:") using WMI Win32_Volume.Dismount().
        /// Returns true on success.
        /// </summary>
        public bool DismountVolumeWmi(string driveLetter)
        {
            try
            {
                // Normalize: ensure trailing backslash for Win32_Volume Name
                string volumeName = driveLetter.TrimEnd('\\') + "\\";
                string query = $"SELECT * FROM Win32_Volume WHERE Name='{volumeName.Replace("\\", "\\\\")}'";
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject vol in searcher.Get())
                {
                    // Dismount(ForceDismount=false) — safe eject
                    var inParams = vol.GetMethodParameters("Dismount");
                    inParams["Force"] = false;
                    inParams["Permanent"] = false;
                    var outParams = vol.InvokeMethod("Dismount", inParams, null);
                    uint returnValue = (uint)(outParams["ReturnValue"] ?? 0u);
                    if (returnValue == 0)
                        return true;
                    Debug.WriteLine($"[UsbStorageBlocker] Win32_Volume.Dismount returned {returnValue} for {driveLetter}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] DismountVolumeWmi error for {driveLetter}: {ex.Message}");
            }
            return false;
        }

        /// <summary>
        /// Dismounts a volume (by drive letter, e.g. "F:") using PowerShell as a fallback.
        /// Returns true on success.
        /// </summary>
        public bool DismountVolumePs(string driveLetter)
        {
            try
            {
                // Use PowerShell to remove the drive letter assignment, which effectively dismounts
                string letter = driveLetter.TrimEnd('\\', ':');
                // Build the script and pass it via -EncodedCommand to avoid shell escaping issues
                string script = $"$vol = Get-WmiObject -Class Win32_Volume -Filter \"DriveLetter='{letter}:'\"; if ($vol) {{ $vol.DriveLetter = $null; $vol.Put() | Out-Null }}";
                string encodedCommand = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encodedCommand}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc != null)
                {
                    proc.WaitForExit(10_000);
                    return proc.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] DismountVolumePs error for {driveLetter}: {ex.Message}");
            }
            return false;
        }

        /// <summary>
        /// Sets registry flags on the USB device and USBSTOR entries to prevent
        /// Windows from re-enumerating and re-mounting the device.
        /// Returns true if at least one registry key was updated.
        /// </summary>
        public bool SetPermanentBlockFlags(DeviceFingerprint device)
        {
            bool success = false;
            try
            {
                // 1. Set ConfigFlags on the USB\VID_...\PID_... instance key
                string usbInstancePath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                using (var key = Registry.LocalMachine.OpenSubKey(usbInstancePath, writable: true))
                {
                    if (key != null)
                    {
                        int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                        key.SetValue("ConfigFlags", current | ConfigFlagDisabled | ConfigFlagReinstall, RegistryValueKind.DWord);
                        success = true;
                        Debug.WriteLine($"[UsbStorageBlocker] Set ConfigFlags on {usbInstancePath}");
                    }
                }

                // 2. Disable the usbstor service start type to prevent driver from loading on rescan
                string svcPath = @"SYSTEM\CurrentControlSet\Services\usbstor";
                using (var svcKey = Registry.LocalMachine.OpenSubKey(svcPath, writable: true))
                {
                    if (svcKey != null)
                    {
                        svcKey.SetValue("Start", ServiceDisabled, RegistryValueKind.DWord);
                        success = true;
                        Debug.WriteLine($"[UsbStorageBlocker] Disabled usbstor service");
                    }
                }

                // 3. Try to set ConfigFlags on USBSTOR\DISK&... instance if available
                if (!string.IsNullOrEmpty(device.DeviceId))
                {
                    // DeviceId may be like "USBSTOR\DISK&VEN_...&PROD_...&REV_...\...", normalize for registry
                    string usbStorPath = $@"SYSTEM\CurrentControlSet\Enum\{device.DeviceId.Replace('/', '\\')}";
                    using var storKey = Registry.LocalMachine.OpenSubKey(usbStorPath, writable: true);
                    if (storKey != null)
                    {
                        int current = storKey.GetValue("ConfigFlags") is int sf ? sf : 0;
                        storKey.SetValue("ConfigFlags", current | ConfigFlagDisabled | ConfigFlagReinstall, RegistryValueKind.DWord);
                        success = true;
                        Debug.WriteLine($"[UsbStorageBlocker] Set ConfigFlags on USBSTOR path: {usbStorPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] SetPermanentBlockFlags error: {ex.Message}");
            }
            return success;
        }

        // -------------------------------------------------------------------------
        // Private helpers
        // -------------------------------------------------------------------------

        private static string FindPhysicalDrive(string vid, string pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                foreach (ManagementObject disk in searcher.Get())
                {
                    string pnpId = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
                    if (pnpId.IndexOf($"VID_{vid}&PID_{pid}", StringComparison.OrdinalIgnoreCase) >= 0)
                        return disk["DeviceID"]?.ToString();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] FindPhysicalDrive error: {ex.Message}");
            }
            return null;
        }
    }
}
