using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using Microsoft.Win32;

namespace USBGuardian
{
    public class BlockingResult
    {
        public bool Success { get; set; }
        public string Method { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class UsbBlockingManager
    {
        // ConfigFlags bit values set by USB Guardian when blocking
        private const int ConfigFlagDisabled  = 0x100;   // CONFIGFLAG_DISABLED
        private const int ConfigFlagReinstall = 0x40;    // CONFIGFLAG_REINSTALL

        private readonly SecurityEventLogger _logger;

        /// <summary>
        /// Optional persistent store for blocked-device records.
        /// When set, <see cref="BlockDevice"/> writes a <see cref="BlockedDeviceRecord"/>
        /// containing enough information to reverse every action taken.
        /// </summary>
        public BlockedDeviceStore? Store { get; set; }

        public UsbBlockingManager(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public BlockingResult DisableDeviceWMI(DeviceFingerprint device)
        {
            var result = new BlockingResult { Method = "WMI" };
            try
            {
                string query = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{device.Vid}&PID_{device.Pid}%'";
                ManagementObjectCollection results = null;
                try
                {
                    var searcher = new ManagementObjectSearcher(query);
                    results = searcher.Get();
                    foreach (ManagementObject obj in results)
                    {
                        obj.InvokeMethod("Disable", null);
                        result.Success = true;
                        result.Message = $"Disabled via WMI: {obj["DeviceID"]}";
                        _logger.LogCritical(0, "DeviceBlocked", $"WMI disable: {device.Vid}:{device.Pid} — {result.Message}", $"{device.Vid}:{device.Pid}");
                        return result;
                    }
                }
                finally
                {
                    results?.Dispose();
                }
                result.Message = "Device not found via WMI";
            }
            catch (Exception ex)
            {
                result.Message = $"WMI disable failed: {ex.Message}";
                Debug.WriteLine($"[UsbBlockingManager] {result.Message}");
            }
            return result;
        }

        /// <summary>
        /// Applies registry block flags (ConfigFlags disabled bit + optional service disable)
        /// and returns a list of <see cref="BlockActionRecord"/> entries describing what was
        /// changed and what the previous values were (needed for rollback).
        /// </summary>
        public BlockingResult BlockDeviceRegistry(DeviceFingerprint device,
            List<BlockActionRecord>? actionLog = null)
        {
            var result = new BlockingResult { Method = "Registry" };
            try
            {
                string subKeyPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: true);
                if (key != null)
                {
                    // Capture previous ConfigFlags BEFORE we modify it (needed for rollback)
                    int previousFlags = key.GetValue("ConfigFlags") is int flagVal ? flagVal : 0;
                    key.SetValue("ConfigFlags", previousFlags | ConfigFlagDisabled, RegistryValueKind.DWord);
                    result.Success = true;
                    result.Message = $"Set ConfigFlags disabled on {subKeyPath}";

                    // Strip Guardian's own bits before recording so that the rollback
                    // target is the true pre-Guardian state, even if an early-block step
                    // already applied these flags before this call ran.
                    actionLog?.Add(new BlockActionRecord
                    {
                        ActionType = "ConfigFlags",
                        RegistryPath = subKeyPath,
                        PreviousConfigFlags = previousFlags & ~(ConfigFlagDisabled | ConfigFlagReinstall)
                    });
                }
                else
                {
                    result.Message = $"Registry key not found: {subKeyPath}";
                }

                // Also try disabling the service — but record the previous Start value
                if (!string.IsNullOrEmpty(device.Service))
                {
                    string svcPath = $@"SYSTEM\CurrentControlSet\Services\{device.Service}";
                    using var svcKey = Registry.LocalMachine.OpenSubKey(svcPath, writable: true);
                    if (svcKey != null)
                    {
                        int previousStart = svcKey.GetValue("Start") is int sv ? sv : 3;
                        svcKey.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = Disabled
                        result.Message += $"; Disabled service {device.Service}";

                        actionLog?.Add(new BlockActionRecord
                        {
                            ActionType = "ServiceStart",
                            RegistryPath = svcPath,
                            ServiceName = device.Service,
                            PreviousServiceStart = previousStart
                        });
                    }
                }

                _logger.LogCritical(0, "DeviceBlocked", $"Registry block: {device.Vid}:{device.Pid} — {result.Message}", $"{device.Vid}:{device.Pid}");
            }
            catch (Exception ex)
            {
                result.Message = $"Registry block failed: {ex.Message}";
                Debug.WriteLine($"[UsbBlockingManager] {result.Message}");
            }
            return result;
        }

        public BlockingResult EnableDeviceWMI(DeviceFingerprint device)
        {
            var result = new BlockingResult { Method = "WMI-Enable" };
            try
            {
                string query = $"SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%VID_{device.Vid}&PID_{device.Pid}%'";
                ManagementObjectCollection results = null;
                try
                {
                    var searcher = new ManagementObjectSearcher(query);
                    results = searcher.Get();
                    foreach (ManagementObject obj in results)
                    {
                        obj.InvokeMethod("Enable", null);
                        result.Success = true;
                        result.Message = $"Enabled via WMI: {obj["DeviceID"]}";
                        _logger.LogInfo(0, "DeviceEnabled", $"WMI enable: {device.Vid}:{device.Pid}", $"{device.Vid}:{device.Pid}");
                        return result;
                    }
                }
                finally
                {
                    results?.Dispose();
                }
                result.Message = "Device not found via WMI";
            }
            catch (Exception ex)
            {
                result.Message = $"WMI enable failed: {ex.Message}";
                Debug.WriteLine($"[UsbBlockingManager] {result.Message}");
            }
            return result;
        }

        /// <summary>
        /// Blocks a device via WMI and registry, then persists a <see cref="BlockedDeviceRecord"/>
        /// in the <see cref="Store"/> (if configured) so the block can be reversed later.
        /// </summary>
        public void BlockDevice(DeviceFingerprint device, string reason)
        {
            try
            {
                string vidPid = $"{device.Vid}:{device.Pid}";
                _logger.LogAttack(0, "BlockDevice", $"Blocking device {vidPid}: {reason}", vidPid);

                var actions = new List<BlockActionRecord>();

                var wmiResult = DisableDeviceWMI(device);
                if (wmiResult.Success)
                    actions.Add(new BlockActionRecord { ActionType = "WmiDisable" });

                var regResult = BlockDeviceRegistry(device, actions);

                Debug.WriteLine($"[UsbBlockingManager] Block results — WMI: {wmiResult.Success} ({wmiResult.Message}), Registry: {regResult.Success} ({regResult.Message})");

                // Persist the record so it can be reversed via the Unblock Devices UI
                Store?.AddOrUpdate(new BlockedDeviceRecord
                {
                    Vid = device.Vid ?? string.Empty,
                    Pid = device.Pid ?? string.Empty,
                    InstanceId = device.InstanceId ?? string.Empty,
                    SerialNumber = device.SerialNumber ?? string.Empty,
                    Description = device.Description ?? string.Empty,
                    BlockReason = reason,
                    Actions = actions
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbBlockingManager] BlockDevice failed: {ex.Message}");
            }
        }

        public bool IsDeviceBlocked(string vid, string pid, string instanceId)
        {
            try
            {
                string subKeyPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}\{instanceId}";
                using var key = Registry.LocalMachine.OpenSubKey(subKeyPath);
                if (key?.GetValue("ConfigFlags") is int flags && (flags & ConfigFlagDisabled) != 0)
                    return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbBlockingManager] IsDeviceBlocked check failed: {ex.Message}");
            }
            return false;
        }
    }
}
