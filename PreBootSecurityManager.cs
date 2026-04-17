using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;

namespace USBGuardian
{
    internal static class PreBootSecurityManager
    {
        private const int ConfigFlagDisabled = 0x100;
        private const int ConfigFlagReinstall = 0x40;
        private const string UsbStorEnumPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";

        public static void InitializePreBootBlocking(SecurityEventLogger? logger = null)
        {
            try
            {
                logger?.LogPreBootAction("Initialize", "Initializing pre-boot USB storage blocking.");
                var whitelist = new DeviceWhitelist();
                logger?.LogPreBootAction("Initialize",
                    $"Loaded device whitelist entries: {whitelist.CountTrustedEntries()}");
                ServiceHardeningManager.DisableUsbStorageSurface(logger);
                DisableAllUsbStorInstances(logger);
                CreatePreBootLockFile(logger);
                logger?.LogPreBootAction("Initialize",
                    "Pre-boot monitoring initialized. Per-device ConfigFlags blocking active for unknown USBSTOR instances; global USBSTOR service remains unchanged.");
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, "PreBootInit", $"Pre-boot initialization failed: {ex.Message}");
                Debug.WriteLine($"[PreBoot] Initialization error: {ex.Message}");
            }
        }

        public static string GetLockFilePath()
        {
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "USB-Guardian");
            return Path.Combine(root, "preboot.lock");
        }

        public static void ReconcileStalePreBootState(SecurityEventLogger? logger = null)
        {
            try
            {
                string lockFile = GetLockFilePath();
                if (!File.Exists(lockFile))
                    return;

                logger?.LogPreBootAction("Recovery",
                    "Detected stale pre-boot lock from a previous run. Restoring USBSTOR instance flags.");
                ClearUsbStorDisableFlags(logger);
                ServiceHardeningManager.EnableUsbStorManual(logger);
                File.Delete(lockFile);
                logger?.LogPreBootAction("Recovery",
                    "Stale pre-boot lock state reconciled successfully.");
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, "Recovery", $"Failed to reconcile stale pre-boot lock state: {ex.Message}");
                Debug.WriteLine($"[PreBoot] Reconcile error: {ex.Message}");
            }
        }

        private static void DisableAllUsbStorInstances(SecurityEventLogger? logger)
        {
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(UsbStorEnumPath);
                if (root == null)
                {
                    logger?.LogPreBootAction("InstanceHardening", "No USBSTOR instances found in registry.");
                    return;
                }

                foreach (string deviceClassNode in root.GetSubKeyNames())
                {
                    using var classKey = root.OpenSubKey(deviceClassNode);
                    if (classKey == null) continue;

                    foreach (string instanceNode in classKey.GetSubKeyNames())
                    {
                        string path = $@"{UsbStorEnumPath}\{deviceClassNode}\{instanceNode}";
                        try
                        {
                            using var key = Registry.LocalMachine.OpenSubKey(path, writable: true);
                            if (key == null) continue;

                            int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                            int hardened = current | ConfigFlagDisabled | ConfigFlagReinstall;
                            key.SetValue("ConfigFlags", hardened, RegistryValueKind.DWord);
                            logger?.LogPreBootAction("InstanceHardening",
                                $"Applied ConfigFlags to USBSTOR instance '{deviceClassNode}\\{instanceNode}' (0x{current:X}→0x{hardened:X}).");
                        }
                        catch (Exception ex)
                        {
                            logger?.LogWarning(0, "InstanceHardening",
                                $"Failed to harden USBSTOR instance '{deviceClassNode}\\{instanceNode}': {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, "InstanceHardening", $"USBSTOR enumeration failed: {ex.Message}");
            }
        }

        private static void ClearUsbStorDisableFlags(SecurityEventLogger? logger)
        {
            using var root = Registry.LocalMachine.OpenSubKey(UsbStorEnumPath);
            if (root == null)
            {
                logger?.LogPreBootAction("Recovery", "No USBSTOR instances found during stale lock recovery.");
                return;
            }

            foreach (string deviceClassNode in root.GetSubKeyNames())
            {
                using var classKey = root.OpenSubKey(deviceClassNode);
                if (classKey == null) continue;

                foreach (string instanceNode in classKey.GetSubKeyNames())
                {
                    string path = $@"{UsbStorEnumPath}\{deviceClassNode}\{instanceNode}";
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(path, writable: true);
                        if (key == null) continue;

                        int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                        // Remove only USB Guardian's blocking bits (disabled + reinstall)
                        // while preserving any other ConfigFlags managed by Windows/OEM.
                        int restored = current & ~(ConfigFlagDisabled | ConfigFlagReinstall);
                        key.SetValue("ConfigFlags", restored, RegistryValueKind.DWord);
                        logger?.LogPreBootAction("Recovery",
                            $"Cleared stale pre-boot ConfigFlags on '{deviceClassNode}\\{instanceNode}' (0x{current:X}→0x{restored:X}).");
                    }
                    catch (Exception ex)
                    {
                        logger?.LogWarning(0, "Recovery",
                            $"Failed clearing stale ConfigFlags on '{deviceClassNode}\\{instanceNode}': {ex.Message}");
                    }
                }
            }
        }

        private static void CreatePreBootLockFile(SecurityEventLogger? logger)
        {
            try
            {
                string lockFile = GetLockFilePath();
                string? directory = Path.GetDirectoryName(lockFile);
                if (!string.IsNullOrWhiteSpace(directory))
                    Directory.CreateDirectory(directory);

                File.WriteAllText(lockFile, $"PreBoot blocking active since {DateTime.UtcNow:O}");
                logger?.LogPreBootAction("Persistence", $"Pre-boot lock file updated at {lockFile}.");
            }
            catch (Exception ex)
            {
                logger?.LogWarning(0, "Persistence", $"Failed to write pre-boot lock file: {ex.Message}");
            }
        }
    }
}
