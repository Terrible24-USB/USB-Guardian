using System;
using System.IO;
using System.Text.Json;
using System.Windows.Forms;

namespace USBGuardian
{
    public class ForensicsLogEntry
    {
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string EventType { get; set; } = string.Empty;
        public string? VidPid { get; set; }
        public string? DeviceId { get; set; }
        public string Details { get; set; } = string.Empty;
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
    }

    public class ForensicsLogger
    {
        private readonly string _path;
        private readonly object _lock = new();

        public ForensicsLogger()
        {
            _path = Path.Combine(Application.StartupPath, "forensics_log.jsonl");
        }

        public void Log(string eventType, DeviceFingerprint? fingerprint, string details, ThreatLevel threatLevel)
        {
            var entry = new ForensicsLogEntry
            {
                EventType = eventType,
                VidPid = fingerprint == null ? null : $"{fingerprint.Vid}:{fingerprint.Pid}",
                DeviceId = fingerprint?.DeviceId,
                Details = details,
                ThreatLevel = threatLevel
            };

            var line = JsonSerializer.Serialize(entry);
            lock (_lock)
            {
                File.AppendAllText(_path, line + Environment.NewLine);
            }
        }
    }
}
