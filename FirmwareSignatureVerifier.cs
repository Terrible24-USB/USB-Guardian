using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Forms;

namespace USBGuardian
{
    public class FirmwareRecord
    {
        public string VidPid { get; set; } = string.Empty;
        public string? SerialNumber { get; set; }
        public string? DescriptorHash { get; set; }
        public string? InterfaceHash { get; set; }
        public string? EndpointHash { get; set; }
        public int NumInterfaces { get; set; }
        public byte UsbDeviceClass { get; set; }
        public DateTime FirstSeenTime { get; set; } = DateTime.UtcNow;
        public DateTime LastVerifiedTime { get; set; } = DateTime.UtcNow;
    }

    public class FirmwareVerificationResult
    {
        public bool IsVerified { get; set; } = true;
        public bool IsTampered { get; set; }
        public bool IsNewDevice { get; set; }
        public List<string> Issues { get; set; } = new();
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
    }

    public class FirmwareSignatureVerifier
    {
        private readonly SecurityEventLogger _logger;
        private readonly string _recordsPath;
        private Dictionary<string, FirmwareRecord> _records = new();
        private readonly object _lock = new();

        public FirmwareSignatureVerifier(SecurityEventLogger logger)
        {
            _logger = logger;
            _recordsPath = Path.Combine(Application.StartupPath, "firmware_records.json");
            LoadRecords();
        }

        public FirmwareVerificationResult VerifyDevice(DeviceFingerprint fingerprint)
        {
            var result = new FirmwareVerificationResult();

            try
            {
                string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
                string key = string.IsNullOrEmpty(fingerprint.SerialNumber)
                    ? $"{vidPid}|{fingerprint.InstanceId}"
                    : $"{vidPid}|{fingerprint.SerialNumber}";

                lock (_lock)
                {
                    if (!_records.TryGetValue(key, out var existing))
                    {
                        // New device — record it
                        result.IsNewDevice = true;
                        result.IsVerified = true;
                        _records[key] = new FirmwareRecord
                        {
                            VidPid = vidPid,
                            SerialNumber = fingerprint.SerialNumber,
                            DescriptorHash = fingerprint.DescriptorHash,
                            InterfaceHash = fingerprint.InterfaceDescriptorHash,
                            EndpointHash = fingerprint.EndpointDescriptorHash,
                            NumInterfaces = fingerprint.NumInterfaces,
                            UsbDeviceClass = fingerprint.UsbDeviceClass
                        };
                        SaveRecords();
                        _logger.LogInfo(4, "FirmwareVerify", $"New device recorded: {vidPid}", vidPid);
                        return result;
                    }

                    // Existing device — compare
                    existing.LastVerifiedTime = DateTime.UtcNow;
                    ThreatLevel threat = ThreatLevel.None;

                    if (!string.IsNullOrEmpty(existing.DescriptorHash) &&
                        !string.IsNullOrEmpty(fingerprint.DescriptorHash) &&
                        existing.DescriptorHash != fingerprint.DescriptorHash)
                    {
                        result.IsTampered = true;
                        string oldPrev = existing.DescriptorHash.Length >= 8 ? existing.DescriptorHash[..8] : existing.DescriptorHash;
                        string newPrev = fingerprint.DescriptorHash.Length >= 8 ? fingerprint.DescriptorHash[..8] : fingerprint.DescriptorHash;
                        result.Issues.Add($"DescriptorHash changed: was {oldPrev}…, now {newPrev}…");
                        Escalate(ref threat, ThreatLevel.Critical);
                    }

                    if (!string.IsNullOrEmpty(existing.InterfaceHash) &&
                        !string.IsNullOrEmpty(fingerprint.InterfaceDescriptorHash) &&
                        existing.InterfaceHash != fingerprint.InterfaceDescriptorHash)
                    {
                        result.IsTampered = true;
                        result.Issues.Add("InterfaceDescriptorHash changed — possible interface injection");
                        Escalate(ref threat, ThreatLevel.Critical);
                    }

                    if (existing.NumInterfaces != fingerprint.NumInterfaces && fingerprint.NumInterfaces > 0)
                    {
                        result.IsTampered = true;
                        result.Issues.Add($"NumInterfaces changed: was {existing.NumInterfaces}, now {fingerprint.NumInterfaces}");
                        Escalate(ref threat, ThreatLevel.High);
                    }

                    if (existing.UsbDeviceClass != fingerprint.UsbDeviceClass && fingerprint.UsbDeviceClass != 0)
                    {
                        result.IsTampered = true;
                        result.Issues.Add($"UsbDeviceClass changed: was 0x{existing.UsbDeviceClass:X2}, now 0x{fingerprint.UsbDeviceClass:X2}");
                        Escalate(ref threat, ThreatLevel.Critical);
                    }

                    result.ThreatLevel = threat;
                    result.IsVerified = !result.IsTampered;

                    if (result.IsTampered)
                    {
                        _logger.LogAttack(4, "FirmwareTamper", $"Firmware tampering detected on {vidPid}: {string.Join("; ", result.Issues)}", vidPid);
                        // Update record to new state only if not tampered (keep old for forensics if tampered)
                    }
                    else
                    {
                        SaveRecords();
                        _logger.LogInfo(4, "FirmwareVerify", $"Device {vidPid} firmware verified — no changes", vidPid);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[FirmwareSignatureVerifier] Exception: {ex.Message}");
                result.Issues.Add($"Verification exception: {ex.Message}");
            }

            return result;
        }

        public void SaveRecords()
        {
            try
            {
                var json = JsonSerializer.Serialize(_records, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_recordsPath, json);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[FirmwareSignatureVerifier] Failed to save records: {ex.Message}");
            }
        }

        public void LoadRecords()
        {
            try
            {
                if (!File.Exists(_recordsPath)) return;
                var json = File.ReadAllText(_recordsPath);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, FirmwareRecord>>(json);
                if (loaded != null)
                {
                    lock (_lock)
                    {
                        _records = loaded;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[FirmwareSignatureVerifier] Failed to load records: {ex.Message}");
            }
        }

        private static void Escalate(ref ThreatLevel current, ThreatLevel proposed)
        {
            if (proposed > current)
                current = proposed;
        }
    }
}
