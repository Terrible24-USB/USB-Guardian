using Microsoft.Win32;
using System;
using System.Diagnostics;

namespace USBGuardian
{
    internal static class ServiceHardeningManager
    {
        public static bool SetServiceStart(string serviceName, int startValue, SecurityEventLogger? logger = null, string eventType = "ServiceHardening")
        {
            if (string.IsNullOrWhiteSpace(serviceName))
                return false;

            try
            {
                string servicePath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
                using var key = Registry.LocalMachine.OpenSubKey(servicePath, writable: true);
                if (key == null)
                {
                    logger?.LogWarning(0, eventType, $"Service key not found: {serviceName}", serviceName);
                    return false;
                }

                int previous = key.GetValue("Start") is int current ? current : -1;
                if (previous != startValue)
                    key.SetValue("Start", startValue, RegistryValueKind.DWord);

                logger?.LogPreBootAction(eventType,
                    $"Service '{serviceName}' Start: {(previous < 0 ? "unknown" : previous.ToString())} → {startValue}",
                    SecuritySeverity.Info,
                    serviceName);
                return true;
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, eventType, $"Failed to set service '{serviceName}' Start={startValue}: {ex.Message}", serviceName);
                Debug.WriteLine($"[ServiceHardening] Failed setting {serviceName} Start={startValue}: {ex.Message}");
                return false;
            }
        }

        public static void DisableUsbStorageSurface(SecurityEventLogger? logger = null)
        {
            SetServiceStart("usbstor", 4, logger);
            SetServiceStart("ShellHWDetection", 4, logger);
            DisableAutoRunPolicies(logger);
        }

        public static void EnableUsbStorManual(SecurityEventLogger? logger = null)
        {
            SetServiceStart("usbstor", 3, logger, "TemporaryEnable");
        }

        private static void DisableAutoRunPolicies(SecurityEventLogger? logger)
        {
            try
            {
                const string explorerPolicies = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
                using var key = Registry.LocalMachine.OpenSubKey(explorerPolicies, writable: true)
                    ?? Registry.LocalMachine.CreateSubKey(explorerPolicies, writable: true);
                if (key == null)
                {
                    logger?.LogWarning(0, "ServiceHardening", "Failed to open Explorer policy key for AutoRun disable.");
                    return;
                }

                key.SetValue("NoAutoRun", 1, RegistryValueKind.DWord);
                key.SetValue("NoDriveTypeAutoRun", 0xFF, RegistryValueKind.DWord);
                logger?.LogPreBootAction("ServiceHardening", "AutoRun/AutoPlay policies disabled at HKLM.");
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, "ServiceHardening", $"Failed to disable AutoRun policy: {ex.Message}");
                Debug.WriteLine($"[ServiceHardening] Failed to disable AutoRun policy: {ex.Message}");
            }
        }
    }
}
