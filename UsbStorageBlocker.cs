using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
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

        // cfgmgr32 constants for device re-enumeration (_WL = Windows-standard flag value of zero)
        private const int  CM_CR_SUCCESS              = 0;
        private const uint CM_LOCATE_DEVNODE_NORMAL   = 0;
        private const uint CM_REENUMERATE_NORMAL      = 0;

        // Time to wait after triggering cfgmgr32 re-enumeration before attempting eject.
        // Windows needs ~500–800 ms to process the ConfigFlags disable bits and tear down
        // the device node; 600 ms is a safe middle-ground that avoids the re-mount race.
        private const int ReEnumerationDelayMs = 600;

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string? pDeviceID, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Reenumerate_DevNode(uint dnDevInst, uint ulFlags);

        private readonly SecurityEventLogger _logger;

        /// <summary>
        /// Optional persistent store for blocked-device records.
        /// When set, <see cref="BlockUsbStorageDevice"/> writes a
        /// <see cref="BlockedDeviceRecord"/> so the block can be reversed later.
        /// </summary>
        public BlockedDeviceStore? Store { get; set; }

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
        /// If <see cref="Store"/> is configured, persists a <see cref="BlockedDeviceRecord"/>
        /// so the block can be reversed later via the Unblock Devices UI.
        /// Returns true if at least the eject or registry step succeeded.
        /// </summary>
        public bool BlockUsbStorageDevice(DeviceFingerprint device)
        {
            string vidPid = $"{device.Vid}:{device.Pid}";
            bool anySuccess = false;
            var actions = new List<BlockActionRecord>();
            var deviceInfo = new DeviceInformationCollector().Collect(device);

            try
            {
                _logger.LogAttack(0, "StorageBlock", $"Blocking USB storage device {vidPid}", vidPid);
                _logger.LogCritical(0, "StorageBlockInfo",
                    $"Preparing per-device block for {deviceInfo.VidPid} " +
                    $"(Manufacturer={deviceInfo.Manufacturer}, Product={deviceInfo.ProductName}, Serial={deviceInfo.SerialNumber ?? "N/A"}, " +
                    $"DescriptorHash={deviceInfo.DescriptorHash}). Global USBSTOR service is not disabled.",
                    vidPid);

                // Step 1: Set registry flags FIRST to prevent re-enumeration.
                // ConfigFlags must be written before Windows re-enumerates so that
                // when the re-enumeration trigger (Step 2) fires, the OS sees the
                // disabled bits and does NOT re-mount the volume.
                bool flagged = SetPermanentBlockFlags(device, actions);
                if (flagged)
                {
                    anySuccess = true;
                    Debug.WriteLine($"[UsbStorageBlocker] Registry block flags set for {vidPid}");
                }

                // Step 2: Trigger cfgmgr32 re-enumeration so Windows processes the
                // disable bits we just wrote.  This closes the race window where
                // Windows would otherwise re-mount the volume before seeing ConfigFlags.
                TriggerReEnumeration(vidPid);

                // Step 3: Wait for Windows to process the re-enumeration and apply the
                // ConfigFlags, giving the OS time to tear down the device node.
                Thread.Sleep(ReEnumerationDelayMs);

                // Step 4: Eject any still-mounted volumes (the drive may already be gone
                // because ConfigFlags prevented re-mount, so a failure here is expected
                // and does not indicate an overall block failure).
                bool ejected = EjectUsbVolume(device.Vid, device.Pid);
                if (ejected)
                {
                    Debug.WriteLine($"[UsbStorageBlocker] Volume ejected for {vidPid}");
                }
                else
                {
                    Debug.WriteLine($"[UsbStorageBlocker] Eject did not complete for {vidPid} — drive may already be gone due to ConfigFlags");
                }

                _logger.LogCritical(0, "StorageBlock", $"USB storage block complete for {vidPid}: eject={ejected}, registry={flagged}", vidPid);

                // Persist the record for later reversal
                Store?.AddOrUpdate(new BlockedDeviceRecord
                {
                    Vid = device.Vid ?? string.Empty,
                    Pid = device.Pid ?? string.Empty,
                    InstanceId = device.InstanceId ?? string.Empty,
                    SerialNumber = device.SerialNumber ?? string.Empty,
                    Description = device.Description ?? string.Empty,
                    PnpDeviceId = device.DeviceId ?? string.Empty,
                    BlockReason = "USB Mass Storage blocked",
                    Actions = actions
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] BlockUsbStorageDevice failed: {ex.Message}");
            }

            return anySuccess;
        }

        /// <summary>
        /// Finds the logical drive letter(s) for the given VID/PID and ejects them.
        /// First tries a soft dismount (Force=false); if that fails, retries with Force=true.
        /// After each successful dismount, waits up to 2 seconds to verify the drive letter
        /// disappears from the filesystem before returning.
        /// Returns true if at least one volume was successfully ejected and confirmed gone.
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
                ManagementObjectCollection partitionResults = null;
                try
                {
                    using var partSearcher = new ManagementObjectSearcher(partitionQuery);
                    partitionResults = partSearcher.Get();
                    foreach (ManagementObject partition in partitionResults)
                    {
                        string partId = partition["DeviceID"]?.ToString();
                        if (string.IsNullOrEmpty(partId)) continue;

                        string logicalQuery = $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partId}'}} WHERE AssocClass=Win32_LogicalDiskToPartition";
                        ManagementObjectCollection logicalResults = null;
                        try
                        {
                            using var logSearcher = new ManagementObjectSearcher(logicalQuery);
                            logicalResults = logSearcher.Get();
                            foreach (ManagementObject logical in logicalResults)
                            {
                                string driveLetter = logical["DeviceID"]?.ToString(); // e.g., "F:"
                                if (string.IsNullOrEmpty(driveLetter)) continue;

                                Debug.WriteLine($"[UsbStorageBlocker] Attempting to dismount {driveLetter}");

                                bool thisVolumeEjected = false;

                                // Step 1: Soft dismount (Force=false) — safe eject
                                if (DismountVolumeWmi(driveLetter, force: false))
                                {
                                    thisVolumeEjected = true;
                                    Debug.WriteLine($"[UsbStorageBlocker] Soft WMI dismount succeeded for {driveLetter}");
                                }
                                else
                                {
                                    // Step 2: Force dismount (Force=true) — ejects even if files are open
                                    Debug.WriteLine($"[UsbStorageBlocker] Soft dismount failed for {driveLetter}, retrying with Force=true");
                                    if (DismountVolumeWmi(driveLetter, force: true))
                                    {
                                        thisVolumeEjected = true;
                                        Debug.WriteLine($"[UsbStorageBlocker] Force WMI dismount succeeded for {driveLetter}");
                                    }
                                    else
                                    {
                                        // Step 3: PowerShell fallback
                                        if (DismountVolumePs(driveLetter))
                                        {
                                            thisVolumeEjected = true;
                                            Debug.WriteLine($"[UsbStorageBlocker] PowerShell dismount succeeded for {driveLetter}");
                                        }
                                        else
                                        {
                                            Debug.WriteLine($"[UsbStorageBlocker] All dismount methods failed for {driveLetter}");
                                        }
                                    }
                                }

                                if (thisVolumeEjected)
                                {
                                    // Wait up to 2 seconds for the drive letter to disappear
                                    bool confirmed = WaitForDriveLetterGone(driveLetter, timeoutMs: 2000);
                                    if (confirmed)
                                    {
                                        Debug.WriteLine($"[UsbStorageBlocker] Drive letter {driveLetter} confirmed gone");
                                        ejected = true;
                                    }
                                    else
                                    {
                                        // Drive letter still present after dismount — log but treat as ejected
                                        // since the dismount call succeeded; Windows may take extra time.
                                        Debug.WriteLine($"[UsbStorageBlocker] Drive letter {driveLetter} still visible after dismount (OS may need extra time)");
                                        ejected = true;
                                    }
                                }
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
                    partitionResults?.Dispose();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] EjectUsbVolume error: {ex.Message}");
            }
            return ejected;
        }

        /// <summary>
        /// Returns true if the specified drive letter (e.g. "F:" or "F:\") currently
        /// refers to a ready drive in the filesystem.
        /// </summary>
        public static bool IsDriveLetterPresent(string driveLetter)
        {
            try
            {
                // Normalize to a consistent "X:\" root path regardless of how the
                // drive letter was passed in (e.g. "F", "F:", "F:\", "f:").
                if (string.IsNullOrEmpty(driveLetter))
                    return false;
                char letter = char.ToUpperInvariant(driveLetter[0]);
                string root = $"{letter}:\\";
                return System.IO.Directory.Exists(root);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Waits until the given drive letter disappears from the filesystem,
        /// polling every 200 ms up to <paramref name="timeoutMs"/> milliseconds.
        /// Returns true if the drive is gone within the timeout.
        /// </summary>
        private static bool WaitForDriveLetterGone(string driveLetter, int timeoutMs)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                if (!IsDriveLetterPresent(driveLetter))
                    return true;
                System.Threading.Thread.Sleep(200);
            }
            return !IsDriveLetterPresent(driveLetter);
        }

        /// <summary>
        /// Dismounts a volume (by drive letter, e.g. "F:") using WMI Win32_Volume.Dismount().
        /// When <paramref name="force"/> is true the dismount is forced even if files are open.
        /// Returns true on success.
        /// </summary>
        public bool DismountVolumeWmi(string driveLetter, bool force = false)
        {
            ManagementObjectCollection results = null;
            try
            {
                // Normalize: ensure trailing backslash for Win32_Volume Name
                string volumeName = driveLetter.TrimEnd('\\') + "\\";
                string query = $"SELECT * FROM Win32_Volume WHERE Name='{volumeName.Replace("\\", "\\\\")}'";
                using var searcher = new ManagementObjectSearcher(query);
                results = searcher.Get();
                foreach (ManagementObject vol in results)
                {
                    var inParams = vol.GetMethodParameters("Dismount");
                    inParams["Force"] = force;
                    inParams["Permanent"] = false;
                    var outParams = vol.InvokeMethod("Dismount", inParams, null);
                    uint returnValue = (uint)(outParams["ReturnValue"] ?? 0u);
                    if (returnValue == 0)
                        return true;
                    Debug.WriteLine($"[UsbStorageBlocker] Win32_Volume.Dismount(Force={force}) returned {returnValue} for {driveLetter}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] DismountVolumeWmi error for {driveLetter}: {ex.Message}");
            }
            finally
            {
                results?.Dispose();
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
        /// Sets per-device registry ConfigFlags on the USB and USBSTOR instance keys to
        /// prevent Windows from re-enumerating and re-mounting the specific device.
        /// Captures the previous values of every key/value changed into
        /// <paramref name="actionLog"/> so the changes can be reversed later.
        ///
        /// NOTE: This method intentionally does NOT disable the global USBSTOR service.
        /// Disabling the service would brick all USB storage, not just the target device.
        /// USB Guardian is a whitelisting product; per-device ConfigFlags are the correct
        /// per-instance enforcement mechanism.
        ///
        /// Returns true if at least one registry key was updated.
        /// </summary>
        public bool SetPermanentBlockFlags(DeviceFingerprint device,
            List<BlockActionRecord>? actionLog = null)
        {
            bool success = false;
            try
            {
                // 1. Set ConfigFlags on the USB\VID_...\PID_... instance key (per-device disable)
                string usbInstancePath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                using (var key = Registry.LocalMachine.OpenSubKey(usbInstancePath, writable: true))
                {
                    if (key != null)
                    {
                        int previous = key.GetValue("ConfigFlags") is int f ? f : 0;
                        key.SetValue("ConfigFlags", previous | ConfigFlagDisabled | ConfigFlagReinstall, RegistryValueKind.DWord);
                        success = true;
                        Debug.WriteLine($"[UsbStorageBlocker] Set ConfigFlags on {usbInstancePath}");

                        // Strip Guardian's own bits so the rollback target is the true
                        // pre-Guardian state even if an early-block step ran first.
                        actionLog?.Add(new BlockActionRecord
                        {
                            ActionType = "ConfigFlags",
                            RegistryPath = usbInstancePath,
                            PreviousConfigFlags = previous & ~(ConfigFlagDisabled | ConfigFlagReinstall)
                        });
                    }
                }

                // 2. Try to set ConfigFlags on USBSTOR\DISK&... instance if available (per-device)
                if (!string.IsNullOrEmpty(device.DeviceId))
                {
                    // DeviceId may be like "USBSTOR\DISK&VEN_...&PROD_...&REV_...\...", normalize for registry
                    string usbStorPath = $@"SYSTEM\CurrentControlSet\Enum\{device.DeviceId.Replace('/', '\\')}";
                    using var storKey = Registry.LocalMachine.OpenSubKey(usbStorPath, writable: true);
                    if (storKey != null)
                    {
                        int previous = storKey.GetValue("ConfigFlags") is int sf ? sf : 0;
                        storKey.SetValue("ConfigFlags", previous | ConfigFlagDisabled | ConfigFlagReinstall, RegistryValueKind.DWord);
                        success = true;
                        Debug.WriteLine($"[UsbStorageBlocker] Set ConfigFlags on USBSTOR path: {usbStorPath}");

                        // Strip Guardian's own bits so the rollback target is the true
                        // pre-Guardian state even if an early-block step ran first.
                        actionLog?.Add(new BlockActionRecord
                        {
                            ActionType = "ConfigFlags",
                            RegistryPath = usbStorPath,
                            PreviousConfigFlags = previous & ~(ConfigFlagDisabled | ConfigFlagReinstall)
                        });
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

        /// <summary>
        /// Triggers a root-level cfgmgr32 re-enumeration so Windows processes the
        /// ConfigFlags disable bits that were just written to the registry.
        /// This forces Windows to see the disabled state and prevents the device
        /// from being re-mounted after the block operation.
        /// </summary>
        private void TriggerReEnumeration(string vidPid)
        {
            try
            {
                int cr = CM_Locate_DevNodeW(out uint rootInst, null, CM_LOCATE_DEVNODE_NORMAL);
                if (cr == CM_CR_SUCCESS)
                {
                    CM_Reenumerate_DevNode(rootInst, CM_REENUMERATE_NORMAL);
                    Debug.WriteLine($"[UsbStorageBlocker] Triggered cfgmgr32 re-enumeration for {vidPid}");
                }
                else
                {
                    Debug.WriteLine($"[UsbStorageBlocker] CM_Locate_DevNodeW failed (cr={cr}) for {vidPid}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbStorageBlocker] TriggerReEnumeration failed: {ex.Message}");
            }
        }

        private static string FindPhysicalDrive(string vid, string pid)
        {
            ManagementObjectCollection results = null;
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                results = searcher.Get();
                foreach (ManagementObject disk in results)
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
            finally
            {
                results?.Dispose();
            }
            return null;
        }
    }
}
