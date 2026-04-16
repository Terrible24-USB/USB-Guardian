using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Win32;
using System.Windows.Forms;

namespace USBGuardian
{
    public class IncidentResponseSnapshot
    {
        public DateTime LastIncidentUtc { get; set; }
        public bool UsbStorDisabled { get; set; }
        public bool EmergencyLockdownActive { get; set; }
        public string LastActionSummary { get; set; } = "No incident yet";
        public List<Dictionary<string, string>> ForensicRecords { get; set; } = new();
    }

    public class IncidentResponseManager
    {
        private readonly SecurityEventLogger _logger;
        private readonly UsbBlockingManager _blockingManager;
        private readonly object _lock = new();
        private readonly IncidentResponseSnapshot _snapshot = new();
        private const int MaxForensicRecords = 500;
        private const int ServiceStartDisabled = 4;

        public IncidentResponseManager(SecurityEventLogger logger, UsbBlockingManager blockingManager)
        {
            _logger = logger;
            _blockingManager = blockingManager;
        }

        public BlockingResult HandleThreat(DeviceFingerprint device, DeviceEvaluationResult evaluationResult)
        {
            var result = new BlockingResult { Method = "IncidentResponse" };
            string vidPid = $"{device.Vid}:{device.Pid}";

            try
            {
                _blockingManager.BlockDevice(device, evaluationResult.BlockReason);
                result.Success = true;
                result.Message = $"Device isolated by incident response: {evaluationResult.BlockReason}";

                PreserveForensics(device, evaluationResult);
                DisableUsbStorService();

                bool critical = evaluationResult.OverallThreatLevel == ThreatLevel.Critical ||
                                (evaluationResult.Layer3Result?.ShouldBlockImmediately ?? false);
                if (critical)
                    ApplyEmergencyUsbLockdown();

                WriteToWindowsEventLog(vidPid, evaluationResult.BlockReason, critical);
                NotifyUser(vidPid, evaluationResult.BlockReason, critical);

                _logger.LogCritical(6, "IncidentResponse",
                    $"Incident response executed for {vidPid}. Critical={critical}. Reason={evaluationResult.BlockReason}",
                    vidPid);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Incident response failed: {ex.Message}";
                Debug.WriteLine($"[IncidentResponseManager] {result.Message}");
                _logger.LogWarning(6, "IncidentResponseError", result.Message, vidPid);
            }

            return result;
        }

        public IncidentResponseSnapshot GetSnapshot()
        {
            lock (_lock)
            {
                return new IncidentResponseSnapshot
                {
                    LastIncidentUtc = _snapshot.LastIncidentUtc,
                    UsbStorDisabled = _snapshot.UsbStorDisabled,
                    EmergencyLockdownActive = _snapshot.EmergencyLockdownActive,
                    LastActionSummary = _snapshot.LastActionSummary,
                    ForensicRecords = new List<Dictionary<string, string>>(_snapshot.ForensicRecords)
                };
            }
        }

        private void DisableUsbStorService()
        {
            try
            {
                const string usbStorPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
                using var key = Registry.LocalMachine.OpenSubKey(usbStorPath, writable: true);
                if (key == null) return;
                key.SetValue("Start", ServiceStartDisabled, RegistryValueKind.DWord);

                lock (_lock)
                {
                    _snapshot.UsbStorDisabled = true;
                    _snapshot.LastActionSummary = "USBSTOR service disabled as part of incident isolation.";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[IncidentResponseManager] DisableUsbStorService failed: {ex.Message}");
            }
        }

        private void ApplyEmergencyUsbLockdown()
        {
            try
            {
                // Best-effort: disable USBSTOR and USB hub stack startup to reduce further exposure.
                SetServiceStart("USBSTOR", ServiceStartDisabled);
                SetServiceStart("usbhub", ServiceStartDisabled);
                SetServiceStart("USBHUB3", ServiceStartDisabled);

                lock (_lock)
                {
                    _snapshot.EmergencyLockdownActive = true;
                    _snapshot.LastActionSummary = "Emergency lockdown applied to USB subsystem services.";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[IncidentResponseManager] ApplyEmergencyUsbLockdown failed: {ex.Message}");
            }
        }

        private static void SetServiceStart(string serviceName, int startValue)
        {
            string svcPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
            using var key = Registry.LocalMachine.OpenSubKey(svcPath, writable: true);
            key?.SetValue("Start", startValue, RegistryValueKind.DWord);
        }

        private void PreserveForensics(DeviceFingerprint device, DeviceEvaluationResult evaluationResult)
        {
            var record = new Dictionary<string, string>
            {
                ["TimestampUtc"] = DateTime.UtcNow.ToString("O"),
                ["Vid"] = device.Vid ?? string.Empty,
                ["Pid"] = device.Pid ?? string.Empty,
                ["InstanceId"] = device.InstanceId ?? string.Empty,
                ["SerialNumber"] = device.SerialNumber ?? string.Empty,
                ["Description"] = device.Description ?? string.Empty,
                ["ThreatLevel"] = evaluationResult.OverallThreatLevel.ToString(),
                ["BlockReason"] = evaluationResult.BlockReason
            };

            lock (_lock)
            {
                _snapshot.LastIncidentUtc = DateTime.UtcNow;
                _snapshot.ForensicRecords.Add(record);
                // Keep bounded in-memory forensic history to avoid unbounded growth in long-running tray sessions.
                if (_snapshot.ForensicRecords.Count > MaxForensicRecords)
                    _snapshot.ForensicRecords.RemoveAt(0);
            }
        }

        private void WriteToWindowsEventLog(string vidPid, string reason, bool critical)
        {
            try
            {
                const string source = "USBGuardian";
                const string logName = "Application";
                if (!EventLog.SourceExists(source))
                    EventLog.CreateEventSource(source, logName);

                string message = $"USB threat blocked for {vidPid}. Critical={critical}. Reason={reason}";
                EventLog.WriteEntry(source, message,
                    critical ? EventLogEntryType.Error : EventLogEntryType.Warning, 6001);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[IncidentResponseManager] WriteToWindowsEventLog failed: {ex.Message}");
                _logger.LogWarning(6, "IncidentEventLogWriteFailed",
                    $"Could not write Windows Event Log entry (likely non-elevated context): {ex.Message}",
                    vidPid);
            }
        }

        private static void NotifyUser(string vidPid, string reason, bool critical)
        {
            try
            {
                MessageBox.Show(
                    $"Threat blocked for device {vidPid}\r\n\r\nReason: {reason}",
                    critical ? "USB Guardian - Critical Threat Blocked" : "USB Guardian - Threat Blocked",
                    MessageBoxButtons.OK,
                    critical ? MessageBoxIcon.Error : MessageBoxIcon.Warning);
            }
            catch
            {
                // Non-interactive contexts may not allow UI notifications.
            }
        }
    }
}
