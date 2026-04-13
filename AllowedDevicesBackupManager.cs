using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Manages atomic JSON backups of the AllowDeviceIDs policy list.
    ///
    /// Safety design (mirrors BlockedDeviceStore):
    /// - All writes are atomic: write to *.tmp then replace to avoid corruption.
    /// - A missing or corrupt backup file is handled gracefully (falls back to Tier 2).
    /// - Thread-safe via an internal lock.
    ///
    /// Default file location: <Application.StartupPath>\allowed_devices_backup.json
    /// </summary>
    public class AllowedDevicesBackupManager
    {
        private const string AllowDeviceIDsSubKey =
            @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs";

        private const string PolicyRestrictionsKey =
            @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

        private readonly string _filePath;
        private readonly object _lock = new();

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public AllowedDevicesBackupManager(string? filePath = null)
        {
            _filePath = filePath ?? Path.Combine(Application.StartupPath, "allowed_devices_backup.json");
        }

        // ---- Public API ----

        /// <summary>
        /// Reads the current AllowDeviceIDs registry values and saves them to disk.
        /// Call this whenever the policy is written so a recovery snapshot is always available.
        /// </summary>
        public void SaveBackup()
        {
            try
            {
                var ids = ReadCurrentAllowedIds();
                var backup = new AllowedDevicesBackup
                {
                    Timestamp = DateTime.UtcNow,
                    AllowedDeviceIDs = ids
                };

                lock (_lock)
                {
                    WriteToDisk(backup);
                }

                Debug.WriteLine($"[AllowedDevicesBackupManager] Saved backup with {ids.Count} IDs.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AllowedDevicesBackupManager] SaveBackup failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads the most recent backup from disk. Returns null if none exists or the file
        /// is corrupted (caller should fall through to Tier 2 recovery).
        /// </summary>
        public AllowedDevicesBackup? LoadBackup()
        {
            lock (_lock)
            {
                try
                {
                    if (!File.Exists(_filePath)) return null;
                    string json = File.ReadAllText(_filePath);
                    return JsonSerializer.Deserialize<AllowedDevicesBackup>(json, JsonOptions);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[AllowedDevicesBackupManager] LoadBackup failed: {ex.Message}");
                    return null;
                }
            }
        }

        /// <summary>
        /// Restores the saved AllowedDeviceIDs list back into the registry.
        /// Returns a human-readable result message.
        /// </summary>
        public string RestoreBackup(bool dryRun = false)
        {
            var backup = LoadBackup();
            if (backup == null)
                return "No backup file found — cannot restore AllowDeviceIDs.";

            if (dryRun)
                return $"[DRY RUN] Would restore {backup.AllowedDeviceIDs.Count} allowed device IDs " +
                       $"from backup dated {backup.Timestamp:u}.";

            try
            {
                // Clear existing values and re-write from backup
                using var key = Registry.LocalMachine.CreateSubKey(AllowDeviceIDsSubKey, writable: true);
                if (key == null)
                    return "Could not open AllowDeviceIDs registry key for writing.";

                // Remove all existing values
                foreach (string name in key.GetValueNames())
                    key.DeleteValue(name, throwOnMissingValue: false);

                // Write restored values
                for (int i = 0; i < backup.AllowedDeviceIDs.Count; i++)
                    key.SetValue((i + 1).ToString(), backup.AllowedDeviceIDs[i], RegistryValueKind.String);

                return $"Restored {backup.AllowedDeviceIDs.Count} allowed device IDs from backup " +
                       $"dated {backup.Timestamp:u}.";
            }
            catch (Exception ex)
            {
                return $"Restore failed: {ex.Message}";
            }
        }

        /// <summary>
        /// Returns true if a backup file exists on disk (may still be corrupted).
        /// </summary>
        public bool BackupExists() => File.Exists(_filePath);

        // ---- Private helpers ----

        private static List<string> ReadCurrentAllowedIds()
        {
            var ids = new List<string>();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(AllowDeviceIDsSubKey);
                if (key == null) return ids;

                foreach (string valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName);
                    if (val is string s && !string.IsNullOrWhiteSpace(s))
                        ids.Add(s.Trim());
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AllowedDevicesBackupManager] ReadCurrentAllowedIds failed: {ex.Message}");
            }
            return ids;
        }

        private void WriteToDisk(AllowedDevicesBackup backup)
        {
            string json = JsonSerializer.Serialize(backup, JsonOptions);
            string tempPath = _filePath + ".tmp";

            string? backupDirectory = Path.GetDirectoryName(tempPath);
            if (backupDirectory != null && !Directory.Exists(backupDirectory))
                Directory.CreateDirectory(backupDirectory);

            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _filePath, overwrite: true);
        }
    }

    /// <summary>
    /// Snapshot of the AllowDeviceIDs policy at a point in time.
    /// </summary>
    public class AllowedDevicesBackup
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>Snapshot of all Hardware ID strings stored under AllowDeviceIDs.</summary>
        public List<string> AllowedDeviceIDs { get; set; } = new();
    }
}
