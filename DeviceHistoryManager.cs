using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;

namespace USBGuardian
{
    /// <summary>
    /// Types of events that can be recorded in the device history log.
    /// </summary>
    public enum DeviceEventType
    {
        Insertion,
        Whitelisted,
        Rejected,
        Blocked,
        ForensicReport
    }

    /// <summary>
    /// A single logged event for a USB device.
    /// </summary>
    public class DeviceEvent
    {
        public string? EventType { get; set; }
        public string? Timestamp { get; set; }
        public string? Notes { get; set; }

        public DeviceEvent() { }

        public DeviceEvent(DeviceEventType type, string? notes = null)
        {
            EventType = type.ToString();
            Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            Notes = notes;
        }
    }

    /// <summary>
    /// Complete history record for a single USB device (identified by fingerprint hash).
    /// </summary>
    public class DeviceHistoryRecord
    {
        public string? FingerprintHash { get; set; }
        public string? VidPid { get; set; }
        public string? Description { get; set; }
        public string? SerialNumber { get; set; }
        public string? FirstObservedTime { get; set; }
        public string? LastObservedTime { get; set; }
        public int TotalObservations { get; set; }
        public bool IsWhitelisted { get; set; }
        public string? WhitelistedAt { get; set; }
        public List<DeviceEvent> Events { get; set; }

        public DeviceHistoryRecord()
        {
            Events = new List<DeviceEvent>();
        }
    }

    /// <summary>
    /// Manages a persistent JSON history database for USB device events and generates forensic reports.
    /// </summary>
    public class DeviceHistoryManager
    {
        private readonly string _historyFilePath;
        private readonly string _forensicReportDir;
        private Dictionary<string, DeviceHistoryRecord> _records;

        private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public DeviceHistoryManager()
        {
            string baseDir = Application.StartupPath;
            _historyFilePath = Path.Combine(baseDir, "device_history.json");
            _forensicReportDir = Path.Combine(baseDir, "forensic_reports");
            _records = new Dictionary<string, DeviceHistoryRecord>(StringComparer.OrdinalIgnoreCase);

            Directory.CreateDirectory(_forensicReportDir);
            LoadHistory();
        }

        // ──────────────────────────────────────────────
        // Public API
        // ──────────────────────────────────────────────

        /// <summary>
        /// Records a device event and updates the persistent history file.
        /// Returns the updated (or newly created) history record so the caller can read it back.
        /// </summary>
        public DeviceHistoryRecord LogEvent(DeviceFingerprint fingerprint, DeviceEventType eventType, string notes = null)
        {
            try
            {
                string key = GetKey(fingerprint);
                string now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

                if (!_records.TryGetValue(key, out DeviceHistoryRecord record))
                {
                    record = new DeviceHistoryRecord
                    {
                        FingerprintHash  = key,
                        VidPid           = $"{fingerprint.Vid}:{fingerprint.Pid}",
                        Description      = fingerprint.Description,
                        SerialNumber     = fingerprint.SerialNumber,
                        FirstObservedTime = now,
                        LastObservedTime  = now,
                        TotalObservations = 0
                    };
                    _records[key] = record;
                }

                // Always update last-seen and increment insertion counter
                if (eventType == DeviceEventType.Insertion)
                {
                    record.LastObservedTime = now;
                    record.TotalObservations++;
                }

                // Update description/serial if we have better data now
                if (!string.IsNullOrEmpty(fingerprint.Description) && record.Description == null)
                    record.Description = fingerprint.Description;
                if (!string.IsNullOrEmpty(fingerprint.SerialNumber) && record.SerialNumber == null)
                    record.SerialNumber = fingerprint.SerialNumber;

                // Update whitelisted state
                if (eventType == DeviceEventType.Whitelisted && !record.IsWhitelisted)
                {
                    record.IsWhitelisted = true;
                    record.WhitelistedAt = now;
                }

                record.Events.Add(new DeviceEvent(eventType, notes));

                SaveHistory();
                return record;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DeviceHistoryManager] LogEvent error: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Returns the history record for the given device, or null if never seen before.
        /// </summary>
        public DeviceHistoryRecord GetHistory(DeviceFingerprint fingerprint)
        {
            string key = GetKey(fingerprint);
            _records.TryGetValue(key, out DeviceHistoryRecord record);
            return record;
        }

        /// <summary>
        /// Generates a JSON forensic report for the device and saves it to the forensic_reports directory.
        /// Returns the full path of the written report file.
        /// </summary>
        public string GenerateForensicReport(DeviceFingerprint fingerprint)
        {
            try
            {
                string key = GetKey(fingerprint);
                _records.TryGetValue(key, out DeviceHistoryRecord history);

                var report = new
                {
                    ReportGeneratedAt  = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    DeviceSnapshot     = BuildSnapshot(fingerprint),
                    ForensicHistory    = history
                };

                string json     = JsonSerializer.Serialize(report, _jsonOptions);
                string fileName = $"forensic_{fingerprint.Vid}_{fingerprint.Pid}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
                string filePath = Path.Combine(_forensicReportDir, fileName);

                File.WriteAllText(filePath, json, Encoding.UTF8);
                Debug.WriteLine($"[DeviceHistoryManager] Forensic report saved: {filePath}");
                return filePath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DeviceHistoryManager] GenerateForensicReport error: {ex.Message}");
                return null;
            }
        }

        // ──────────────────────────────────────────────
        // Private helpers
        // ──────────────────────────────────────────────

        private static string GetKey(DeviceFingerprint fp) =>
            fp.GenerateFingerprintHash();

        private void LoadHistory()
        {
            try
            {
                if (File.Exists(_historyFilePath))
                {
                    string json = File.ReadAllText(_historyFilePath, Encoding.UTF8);
                    var list = JsonSerializer.Deserialize<List<DeviceHistoryRecord>>(json, _jsonOptions);
                    if (list != null)
                    {
                        foreach (var r in list)
                            if (!string.IsNullOrEmpty(r.FingerprintHash))
                                _records[r.FingerprintHash] = r;
                    }
                    Debug.WriteLine($"[DeviceHistoryManager] Loaded {_records.Count} history records.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DeviceHistoryManager] LoadHistory error: {ex.Message}");
            }
        }

        private void SaveHistory()
        {
            try
            {
                string json = JsonSerializer.Serialize(_records.Values.ToList(), _jsonOptions);
                File.WriteAllText(_historyFilePath, json, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DeviceHistoryManager] SaveHistory error: {ex.Message}");
            }
        }

        private static object BuildSnapshot(DeviceFingerprint fp)
        {
            return new
            {
                fp.Vid,
                fp.Pid,
                fp.InstanceId,
                fp.Description,
                fp.Manufacturer,
                fp.SerialNumber,
                fp.ContainerId,
                fp.ParentIdPrefix,
                fp.DeviceClass,
                fp.Service,
                UsbDeviceClass    = $"0x{fp.UsbDeviceClass:X2}",
                UsbDeviceSubClass = $"0x{fp.UsbDeviceSubClass:X2}",
                UsbDeviceProtocol = $"0x{fp.UsbDeviceProtocol:X2}",
                InterfaceClass    = $"0x{fp.InterfaceClass:X2}",
                InterfaceSubClass = $"0x{fp.InterfaceSubClass:X2}",
                InterfaceProtocol = $"0x{fp.InterfaceProtocol:X2}",
                fp.DeviceTypes,
                BcdUSB            = $"0x{fp.BcdUSB:X4}",
                BcdDevice         = $"0x{fp.BcdDevice:X4}",
                fp.NumConfigurations,
                fp.NumInterfaces,
                MaxPowerMA        = fp.MaxPower * 2,
                fp.VolumeSerialNumber,
                fp.ScsiVendor,
                fp.ScsiProduct,
                fp.ScsiRevision,
                fp.HardwareIds,
                fp.DescriptorHash,
                fp.InterfaceDescriptorHash,
                fp.EndpointDescriptorHash,
                fp.BosHash,
                FingerprintHash   = fp.GenerateFingerprintHash(),
                FirstInstallTime  = fp.FirstInstallTime != DateTime.MinValue
                                        ? fp.FirstInstallTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                                        : null,
                LastConnectedTime = fp.LastConnectedTime != DateTime.MinValue
                                        ? fp.LastConnectedTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                                        : null,
                EnumerationTimeMs = fp.EnumerationTimeMs,
                CaptureTime       = fp.CaptureTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            };
        }
    }
}
