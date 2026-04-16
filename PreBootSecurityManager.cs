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

        private static void DisableAllUsbStorInstances(SecurityEventLogger? logger)
        {
            const string enumPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(enumPath);
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
                        string path = $@"{enumPath}\{deviceClassNode}\{instanceNode}";
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
