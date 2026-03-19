using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Win32;

namespace USBGuardian
{
    public class DMAProtectionStatus
    {
        public bool KernelDMAProtectionEnabled { get; set; }
        public bool IOMMUPresent { get; set; }
        public bool BitLockerEnabled { get; set; }
        public string OverallProtectionLevel { get; set; } = "Unknown";
        public List<string> Recommendations { get; set; } = new();
    }

    public class DMAProtectionChecker
    {
        private readonly SecurityEventLogger _logger;
        private DMAProtectionStatus? _cachedStatus;
        private readonly object _lock = new();

        public DMAProtectionChecker(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public DMAProtectionStatus CheckProtection()
        {
            lock (_lock)
            {
                var status = new DMAProtectionStatus();

                try
                {
                    status.KernelDMAProtectionEnabled = CheckKernelDMAProtection();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[DMAProtectionChecker] KernelDMA check failed: {ex.Message}");
                }

                try
                {
                    status.IOMMUPresent = CheckIOMMU();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[DMAProtectionChecker] IOMMU check failed: {ex.Message}");
                }

                try
                {
                    status.BitLockerEnabled = CheckBitLocker();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[DMAProtectionChecker] BitLocker check failed: {ex.Message}");
                }

                // Determine overall protection level
                int score = 0;
                if (status.KernelDMAProtectionEnabled) score++;
                if (status.IOMMUPresent) score++;
                if (status.BitLockerEnabled) score++;

                status.OverallProtectionLevel = score switch
                {
                    3 => "High",
                    2 => "Medium",
                    _ => "Low"
                };

                // Recommendations
                if (!status.KernelDMAProtectionEnabled)
                    status.Recommendations.Add("Enable Kernel DMA Protection (requires Secure Boot + UEFI)");
                if (!status.IOMMUPresent)
                    status.Recommendations.Add("Enable IOMMU/VT-d in BIOS and enable Virtualization Based Security");
                if (!status.BitLockerEnabled)
                    status.Recommendations.Add("Enable BitLocker to protect against physical DMA attacks");

                // Log only on first check or change
                bool changed = _cachedStatus == null ||
                               _cachedStatus.OverallProtectionLevel != status.OverallProtectionLevel;

                if (changed)
                {
                    var logMsg = $"DMA Protection: KernelDMA={status.KernelDMAProtectionEnabled}, IOMMU={status.IOMMUPresent}, BitLocker={status.BitLockerEnabled}, Level={status.OverallProtectionLevel}";
                    if (status.OverallProtectionLevel == "Low")
                        _logger.LogWarning(5, "DMAProtection", logMsg);
                    else
                        _logger.LogInfo(5, "DMAProtection", logMsg);
                }

                _cachedStatus = status;
                return status;
            }
        }

        public DMAProtectionStatus? GetCachedStatus() => _cachedStatus;

        private static bool CheckKernelDMAProtection()
        {
            // Check Device Guard VBS
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard");
            if (key?.GetValue("Enabled") is int val && val == 1) return true;

            using var key2 = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard");
            if (key2?.GetValue("EnableVirtualizationBasedSecurity") is int val2 && val2 == 1) return true;

            return false;
        }

        private static bool CheckIOMMU()
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            return key?.GetValue("Enabled") is int val && val == 1;
        }

        private static bool CheckBitLocker()
        {
            // Check BitLocker policy registry
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\FVE");
            if (key != null) return true; // Policy key presence suggests BitLocker is managed

            // Check DriveEncryptionState
            using var key2 = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\BitLocker");
            if (key2?.GetValue("DriveEncryptionState") is int state && state > 0) return true;

            return false;
        }
    }
}
