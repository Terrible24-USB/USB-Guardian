using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Win32;

namespace USBGuardian
{
    public class KernelSecurityStatus
    {
        public bool ASLREnabled { get; set; }
        public string WindowsUpdatesStatus { get; set; } = "Unknown";
        public List<string> SuspiciousKernelEvents { get; set; } = new();
        public string OverallStatus { get; set; } = "Unknown";
    }

    public class KernelHardeningMonitor
    {
        private readonly SecurityEventLogger _logger;
        private KernelSecurityStatus? _cachedStatus;
        private DateTime _lastCheck = DateTime.MinValue;
        private readonly TimeSpan _refreshInterval = TimeSpan.FromMinutes(5);
        private readonly object _lock = new();

        public KernelHardeningMonitor(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public KernelSecurityStatus CheckKernelSecurity()
        {
            lock (_lock)
            {
                if (_cachedStatus != null && (DateTime.UtcNow - _lastCheck) < _refreshInterval)
                    return _cachedStatus;

                var status = new KernelSecurityStatus();

                try
                {
                    status.ASLREnabled = CheckASLR();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[KernelHardeningMonitor] ASLR check failed: {ex.Message}");
                }

                try
                {
                    status.WindowsUpdatesStatus = CheckWindowsUpdateStatus();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[KernelHardeningMonitor] WU check failed: {ex.Message}");
                    status.WindowsUpdatesStatus = "Unknown";
                }

                // Determine overall status
                bool healthy = status.ASLREnabled && status.WindowsUpdatesStatus == "Automatic";
                status.OverallStatus = healthy ? "Hardened" : "Needs Attention";

                bool changed = _cachedStatus == null || _cachedStatus.OverallStatus != status.OverallStatus;
                if (changed)
                {
                    var msg = $"Kernel security: ASLR={status.ASLREnabled}, WindowsUpdate={status.WindowsUpdatesStatus}, Status={status.OverallStatus}";
                    if (!healthy)
                        _logger.LogWarning(6, "KernelHardening", msg);
                    else
                        _logger.LogInfo(6, "KernelHardening", msg);
                }

                _cachedStatus = status;
                _lastCheck = DateTime.UtcNow;
                return status;
            }
        }

        public void MonitorUsbKernelEvent(DeviceFingerprint fingerprint)
        {
            try
            {
                string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
                string msg = $"USB kernel event: {fingerprint.Description ?? vidPid} (class=0x{fingerprint.UsbDeviceClass:X2}, interfaces={fingerprint.NumInterfaces})";
                _logger.LogInfo(6, "UsbKernelEvent", msg, vidPid);

                lock (_lock)
                {
                    if (_cachedStatus?.SuspiciousKernelEvents is { } events)
                    {
                        if (events.Count >= 500)
                            events.RemoveAt(0);
                        events.Add($"[{DateTime.UtcNow:HH:mm:ss}] {msg}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[KernelHardeningMonitor] MonitorUsbKernelEvent failed: {ex.Message}");
            }
        }

        private static bool CheckASLR()
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
            var val = key?.GetValue("EnableForceRelocateImages");
            return val is int i && i == 1;
        }

        private static string CheckWindowsUpdateStatus()
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update");
            var val = key?.GetValue("AUOptions");
            return val is int auOpt ? auOpt switch
            {
                1 => "Disabled",
                2 => "Notify",
                3 => "AutoDownload",
                4 => "Automatic",
                _ => $"Unknown({auOpt})"
            } : "Unknown";
        }
    }
}
