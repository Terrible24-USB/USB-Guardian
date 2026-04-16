using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows.Forms;

namespace USBGuardian
{
    public class WhitelistEntry
    {
        public string VidPid { get; set; } = string.Empty;
        public string? SerialNumber { get; set; }
        public DateTime ApprovedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime? ExpiresAtUtc { get; set; }
        public string ApprovedBy { get; set; } = "admin";
    }

    public class DeviceWhitelistManager
    {
        private readonly string _path;
        private readonly object _lock = new();
        private Dictionary<string, WhitelistEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

        public DeviceWhitelistManager()
        {
            _path = Path.Combine(Application.StartupPath, "device_whitelist.json");
            Load();
        }

        public bool IsWhitelisted(DeviceFingerprint fingerprint)
        {
            string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
            lock (_lock)
            {
                PurgeExpiredLocked();

                if (!string.IsNullOrWhiteSpace(fingerprint.SerialNumber) &&
                    _entries.TryGetValue($"{vidPid}|{fingerprint.SerialNumber}", out _))
                    return true;

                return _entries.TryGetValue(vidPid, out _);
            }
        }

        public void Approve(DeviceFingerprint fingerprint, string approvedBy = "admin", TimeSpan? duration = null)
        {
            string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
            var entry = new WhitelistEntry
            {
                VidPid = vidPid,
                SerialNumber = string.IsNullOrWhiteSpace(fingerprint.SerialNumber) ? null : fingerprint.SerialNumber,
                ApprovedBy = approvedBy,
                ExpiresAtUtc = duration.HasValue ? DateTime.UtcNow.Add(duration.Value) : null
            };

            lock (_lock)
            {
                _entries[vidPid] = entry;
                if (!string.IsNullOrWhiteSpace(entry.SerialNumber))
                    _entries[$"{vidPid}|{entry.SerialNumber}"] = entry;
                SaveLocked();
            }
        }

        private void PurgeExpiredLocked()
        {
            var expired = _entries
                .Where(kvp => kvp.Value.ExpiresAtUtc.HasValue && kvp.Value.ExpiresAtUtc.Value <= DateTime.UtcNow)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expired)
                _entries.Remove(key);
        }

        private void SaveLocked()
        {
            var json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_path, json);
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_path)) return;
                var json = File.ReadAllText(_path);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, WhitelistEntry>>(json);
                if (loaded != null)
                    _entries = new Dictionary<string, WhitelistEntry>(loaded, StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                _entries = new Dictionary<string, WhitelistEntry>(StringComparer.OrdinalIgnoreCase);
            }
        }
    }
}
