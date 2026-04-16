using Microsoft.Win32;
using System;
using System.IO;

namespace USBGuardian
{
    internal static class BootRecoveryManager
    {
        private const string RecoveryPath = @"SOFTWARE\USBGuardian\Recovery";
        private const string EmergencyEnableValue = "EmergencyEnableUsbStor";

        public static bool IsPreBootLockPresent()
        {
            try
            {
                return File.Exists(PreBootSecurityManager.GetLockFilePath());
            }
            catch
            {
                return false;
            }
        }

        public static void ApplyEmergencyRecoveryIfRequested(SecurityEventLogger? logger = null)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RecoveryPath, writable: true);
                if (key?.GetValue(EmergencyEnableValue) is not int requested || requested != 1)
                    return;

                ServiceHardeningManager.EnableUsbStorManual(logger);
                key.DeleteValue(EmergencyEnableValue, throwOnMissingValue: false);

                string lockFile = PreBootSecurityManager.GetLockFilePath();
                if (File.Exists(lockFile))
                    File.Delete(lockFile);

                logger?.LogPreBootAction("Recovery", "Emergency recovery executed: USBSTOR enabled and pre-boot lock cleared.",
                    SecuritySeverity.Warning, "usbstor");
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, "Recovery", $"Emergency recovery check failed: {ex.Message}", "usbstor");
            }
        }
    }
}
