using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace USBGuardian
{
    public enum ThreatLevel
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    public class DescriptorValidationResult
    {
        public bool IsValid { get; set; } = true;
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
        public List<string> Issues { get; set; } = new();
        public string? DescriptorHash { get; set; }
    }

    public class DescriptorValidator
    {
        private readonly SecurityEventLogger _logger;

        private static readonly HashSet<ushort> KnownGoodBcdUSB = new()
        {
            0x0100, 0x0110, 0x0200, 0x0210, 0x0300, 0x0310, 0x0320
        };

        // For USB 2.0 and earlier: 8, 16, 32, 64 bytes. For USB 3.0 SuperSpeed: 9 (meaning 2^9 = 512 bytes).
        private static readonly HashSet<byte> ValidMaxPacketSizes = new() { 8, 16, 32, 64, 9 };

        public DescriptorValidator(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public DescriptorValidationResult ValidateDevice(DeviceFingerprint fingerprint)
        {
            var result = new DescriptorValidationResult
            {
                DescriptorHash = fingerprint.DescriptorHash
            };

            try
            {
                string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
                ThreatLevel threat = ThreatLevel.None;

                // Check for descriptor fuzzing (all zeros or all 0xFF)
                if (IsAllZerosDescriptor(fingerprint))
                {
                    result.Issues.Add("Descriptor appears to be all zeros — possible fuzzing attack");
                    threat = ThreatLevel.Critical;
                }

                if (IsAllOnesDescriptor(fingerprint))
                {
                    result.Issues.Add("Descriptor appears to be all 0xFF — possible fuzzing attack");
                    Escalate(ref threat, ThreatLevel.Critical);
                }

                // Validate bcdUSB
                if (fingerprint.BcdUSB == 0)
                {
                    result.Issues.Add("bcdUSB is zero — invalid USB version");
                    Escalate(ref threat, ThreatLevel.High);
                }
                else if (!KnownGoodBcdUSB.Contains(fingerprint.BcdUSB))
                {
                    result.Issues.Add($"bcdUSB 0x{fingerprint.BcdUSB:X4} is not a recognized USB version");
                    Escalate(ref threat, ThreatLevel.Medium);
                }

                // Validate MaxPacketSize0
                if (!ValidMaxPacketSizes.Contains(fingerprint.MaxPacketSize0))
                {
                    result.Issues.Add($"MaxPacketSize0={fingerprint.MaxPacketSize0} is not a valid value (must be 8/16/32/64 for USB 2.0, or 9 for USB 3.0 SuperSpeed where 2^9=512)");
                    Escalate(ref threat, ThreatLevel.Medium);
                }

                // Validate NumConfigurations
                if (fingerprint.NumConfigurations == 0)
                {
                    result.Issues.Add("NumConfigurations is 0 — invalid");
                    Escalate(ref threat, ThreatLevel.High);
                }
                else if (fingerprint.NumConfigurations > 4)
                {
                    result.Issues.Add($"NumConfigurations={fingerprint.NumConfigurations} is unusually high (>4)");
                    Escalate(ref threat, ThreatLevel.Low);
                }
                else if (fingerprint.NumConfigurations > 2)
                {
                    result.Issues.Add($"NumConfigurations={fingerprint.NumConfigurations} is suspicious (expected 1-2)");
                    Escalate(ref threat, ThreatLevel.Low);
                }

                // Validate NumInterfaces
                if (fingerprint.NumInterfaces < 0 || fingerprint.NumInterfaces > 10)
                {
                    result.Issues.Add($"NumInterfaces={fingerprint.NumInterfaces} is out of reasonable range (0-10)");
                    Escalate(ref threat, ThreatLevel.Medium);
                }

                // Validate UsbDeviceClass
                if (IsUndefinedDeviceClass(fingerprint.UsbDeviceClass))
                {
                    result.Issues.Add($"UsbDeviceClass=0x{fingerprint.UsbDeviceClass:X2} is in an undefined/reserved range");
                    Escalate(ref threat, ThreatLevel.Medium);
                }

                // Validate descriptor hash consistency
                if (string.IsNullOrEmpty(fingerprint.DescriptorHash))
                {
                    result.Issues.Add("DescriptorHash is missing");
                    Escalate(ref threat, ThreatLevel.Low);
                }

                result.ThreatLevel = threat;
                result.IsValid = result.ThreatLevel < ThreatLevel.High && result.Issues.Count == 0;

                if (result.ThreatLevel >= ThreatLevel.Critical)
                    _logger.LogAttack(1, "DescriptorValidation", $"Critical descriptor issues: {string.Join("; ", result.Issues)}", vidPid);
                else if (result.ThreatLevel >= ThreatLevel.High)
                    _logger.LogCritical(1, "DescriptorValidation", $"High threat descriptor: {string.Join("; ", result.Issues)}", vidPid);
                else if (result.ThreatLevel >= ThreatLevel.Medium)
                    _logger.LogWarning(1, "DescriptorValidation", $"Medium threat descriptor: {string.Join("; ", result.Issues)}", vidPid);
                else if (result.Issues.Count > 0)
                    _logger.LogWarning(1, "DescriptorValidation", $"Minor descriptor issues: {string.Join("; ", result.Issues)}", vidPid);
                else
                    _logger.LogInfo(1, "DescriptorValidation", "Descriptor validation passed", vidPid);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DescriptorValidator] Exception: {ex.Message}");
                result.Issues.Add($"Validation exception: {ex.Message}");
            }

            return result;
        }

        private static bool IsAllZerosDescriptor(DeviceFingerprint fp) =>
            fp.BcdUSB == 0 && fp.MaxPacketSize0 == 0 && fp.NumConfigurations == 0 && fp.UsbDeviceClass == 0;

        private static bool IsAllOnesDescriptor(DeviceFingerprint fp) =>
            fp.BcdUSB == 0xFFFF && fp.MaxPacketSize0 == 0xFF && fp.NumConfigurations == 0xFF && fp.UsbDeviceClass == 0xFF;

        private static bool IsUndefinedDeviceClass(byte cls)
        {
            // Known USB device classes
            HashSet<byte> knownClasses = new() { 0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0xDC, 0xE0, 0xEF, 0xFE, 0xFF };
            return !knownClasses.Contains(cls) && cls != 0x10 && cls != 0x11;
        }

        private static void Escalate(ref ThreatLevel current, ThreatLevel proposed)
        {
            if (proposed > current)
                current = proposed;
        }
    }
}
