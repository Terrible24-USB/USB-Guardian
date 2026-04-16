using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows.Forms;

namespace USBGuardian
{
    public enum SecuritySeverity
    {
        Info,
        Warning,
        Critical,
        Attack
    }

    public class SecurityEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public SecuritySeverity Severity { get; set; }
        public int Layer { get; set; }
        public string EventType { get; set; } = string.Empty;
        public string? DeviceVidPid { get; set; }
        public string? DeviceDescription { get; set; }
        public string Details { get; set; } = string.Empty;
        public string? SystemAction { get; set; }
    }

    public class SecurityEventLogger
    {
        private readonly Queue<SecurityEvent> _events = new();
        private readonly object _lock = new();
        private const int MaxEvents = 1000;
        private readonly string _logPath;

        public SecurityEventLogger()
        {
            _logPath = Path.Combine(Application.StartupPath, "security_log.json");
            LoadEvents();
        }

        public void LogEvent(SecurityEvent evt)
        {
            lock (_lock)
            {
                _events.Enqueue(evt);
                if (_events.Count > MaxEvents)
                    _events.Dequeue();

                PersistEvents();

                Debug.WriteLine($"[SecurityEventLogger] [{evt.Severity}] L{evt.Layer} {evt.EventType}: {evt.Details}");
            }
        }

        public void LogInfo(int layer, string eventType, string details, string? vidPid = null) =>
            LogEvent(new SecurityEvent { Severity = SecuritySeverity.Info, Layer = layer, EventType = eventType, Details = details, DeviceVidPid = vidPid });

        public void LogWarning(int layer, string eventType, string details, string? vidPid = null) =>
            LogEvent(new SecurityEvent { Severity = SecuritySeverity.Warning, Layer = layer, EventType = eventType, Details = details, DeviceVidPid = vidPid });

        public void LogCritical(int layer, string eventType, string details, string? vidPid = null) =>
            LogEvent(new SecurityEvent { Severity = SecuritySeverity.Critical, Layer = layer, EventType = eventType, Details = details, DeviceVidPid = vidPid });

        public void LogAttack(int layer, string eventType, string details, string? vidPid = null) =>
            LogEvent(new SecurityEvent { Severity = SecuritySeverity.Attack, Layer = layer, EventType = eventType, Details = details, DeviceVidPid = vidPid });

        public void LogPreBootAction(string action, string details, SecuritySeverity severity = SecuritySeverity.Info, string? vidPid = null)
        {
            LogEvent(new SecurityEvent
            {
                Severity = severity,
                Layer = 0,
                EventType = $"PreBoot.{action}",
                Details = details,
                DeviceVidPid = vidPid
            });
        }

        public void LogWindowsEvent(SecuritySeverity severity, string source, string message)
        {
            try
            {
                var type = severity switch
                {
                    SecuritySeverity.Critical => EventLogEntryType.Error,
                    SecuritySeverity.Attack => EventLogEntryType.Error,
                    SecuritySeverity.Warning => EventLogEntryType.Warning,
                    _ => EventLogEntryType.Information
                };

                EventLog.WriteEntry(source, message, type);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SecurityEventLogger] Failed writing Windows Event Log: {ex.Message}");
            }
        }

        public List<SecurityEvent> GetRecentEvents(int count = 50)
        {
            lock (_lock)
            {
                return _events.TakeLast(count).ToList();
            }
        }

        private void PersistEvents()
        {
            try
            {
                var json = JsonSerializer.Serialize(_events.ToList(), new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_logPath, json);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SecurityEventLogger] Failed to persist events: {ex.Message}");
            }
        }

        private void LoadEvents()
        {
            try
            {
                if (!File.Exists(_logPath)) return;
                var json = File.ReadAllText(_logPath);
                var loaded = JsonSerializer.Deserialize<List<SecurityEvent>>(json);
                if (loaded != null)
                {
                    lock (_lock)
                    {
                        foreach (var evt in loaded.TakeLast(MaxEvents))
                            _events.Enqueue(evt);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SecurityEventLogger] Failed to load events: {ex.Message}");
            }
        }
    }
}
