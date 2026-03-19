using System;
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
        private readonly SecurityEventLogger _logger;

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
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    obj.InvokeMethod("Disable", null);
                    result.Success = true;
                    result.Message = $"Disabled via WMI: {obj["DeviceID"]}";
                    _logger.LogCritical(0, "DeviceBlocked", $"WMI disable: {device.Vid}:{device.Pid} — {result.Message}", $"{device.Vid}:{device.Pid}");
                    return result;
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

        public BlockingResult BlockDeviceRegistry(DeviceFingerprint device)
        {
            var result = new BlockingResult { Method = "Registry" };
            try
            {
                string subKeyPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
                using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: true);
                if (key != null)
                {
                    // ConfigFlags bit 0x100 = disabled
                    int currentFlags = key.GetValue("ConfigFlags") is int flagVal ? flagVal : 0;
                    key.SetValue("ConfigFlags", currentFlags | 0x100, RegistryValueKind.DWord);
                    result.Success = true;
                    result.Message = $"Set ConfigFlags disabled on {subKeyPath}";
                }
                else
                {
                    result.Message = $"Registry key not found: {subKeyPath}";
                }

                // Also try disabling the service
                if (!string.IsNullOrEmpty(device.Service))
                {
                    string svcPath = $@"SYSTEM\CurrentControlSet\Services\{device.Service}";
                    using var svcKey = Registry.LocalMachine.OpenSubKey(svcPath, writable: true);
                    if (svcKey != null)
                    {
                        svcKey.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = Disabled
                        result.Message += $"; Disabled service {device.Service}";
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
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    obj.InvokeMethod("Enable", null);
                    result.Success = true;
                    result.Message = $"Enabled via WMI: {obj["DeviceID"]}";
                    _logger.LogInfo(0, "DeviceEnabled", $"WMI enable: {device.Vid}:{device.Pid}", $"{device.Vid}:{device.Pid}");
                    return result;
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

        public void BlockDevice(DeviceFingerprint device, string reason)
        {
            try
            {
                string vidPid = $"{device.Vid}:{device.Pid}";
                _logger.LogAttack(0, "BlockDevice", $"Blocking device {vidPid}: {reason}", vidPid);

                var wmiResult = DisableDeviceWMI(device);
                var regResult = BlockDeviceRegistry(device);

                Debug.WriteLine($"[UsbBlockingManager] Block results — WMI: {wmiResult.Success} ({wmiResult.Message}), Registry: {regResult.Success} ({regResult.Message})");
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
                if (key?.GetValue("ConfigFlags") is int flags && (flags & 0x100) != 0)
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
