using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace USBGuardian
{
    public class IdentityValidationResult
    {
        public bool IsValid { get; set; } = true;
        public bool ShouldBlock { get; set; }
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
        public string? DescriptorHash { get; set; }
        public List<string> Issues { get; set; } = new();

        public DescriptorValidationResult ToDescriptorValidationResult() => new()
        {
            IsValid = IsValid,
            ThreatLevel = ThreatLevel,
            DescriptorHash = DescriptorHash,
            Issues = new List<string>(Issues)
        };
    }

    public class DeviceIdentityValidator
    {
        private readonly SecurityEventLogger _logger;
        private readonly DescriptorValidator _descriptorValidator;

        public DeviceIdentityValidator(SecurityEventLogger logger)
        {
            _logger = logger;
            _descriptorValidator = new DescriptorValidator(logger);
        }

        public IdentityValidationResult Validate(DeviceFingerprint fingerprint)
        {
            var result = new IdentityValidationResult();

            try
            {
                var baseValidation = _descriptorValidator.ValidateDevice(fingerprint);
                result.IsValid = baseValidation.IsValid;
                result.ThreatLevel = baseValidation.ThreatLevel;
                result.DescriptorHash = baseValidation.DescriptorHash;
                result.Issues.AddRange(baseValidation.Issues);
                var threat = result.ThreatLevel;

                bool claimsKeyboard = fingerprint.UsbDeviceClass == 0x03 ||
                                      fingerprint.InterfaceClass == 0x03 ||
                                      string.Equals(fingerprint.DeviceClass, "Keyboard", StringComparison.OrdinalIgnoreCase);

                if (claimsKeyboard)
                {
                    if (string.IsNullOrWhiteSpace(fingerprint.SerialNumber))
                    {
                        result.Issues.Add("HID/keyboard identity has no serial number");
                        Escalate(ref threat, ThreatLevel.High);
                    }

                    if (fingerprint.MaxPacketSize0 != 8 && fingerprint.MaxPacketSize0 != 16 &&
                        fingerprint.MaxPacketSize0 != 32 && fingerprint.MaxPacketSize0 != 64)
                    {
                        result.Issues.Add("HID/keyboard reports unusual MaxPacketSize0");
                        Escalate(ref threat, ThreatLevel.High);
                    }
                }

                if (fingerprint.AllInterfaces != null &&
                    fingerprint.NumInterfaces > 0 &&
                    fingerprint.AllInterfaces.Count > 0 &&
                    fingerprint.AllInterfaces.Count != fingerprint.NumInterfaces)
                {
                    result.Issues.Add($"Interface descriptor mismatch: declared={fingerprint.NumInterfaces}, observed={fingerprint.AllInterfaces.Count}");
                    Escalate(ref threat, ThreatLevel.Medium);
                }

                result.ThreatLevel = threat;
                result.ShouldBlock = result.ThreatLevel >= ThreatLevel.High;
                result.IsValid = !result.ShouldBlock;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DeviceIdentityValidator] Exception: {ex.Message}");
                result.Issues.Add($"Identity validation exception: {ex.Message}");
                result.ShouldBlock = true;
                result.IsValid = false;
                var threat = result.ThreatLevel;
                Escalate(ref threat, ThreatLevel.High);
                result.ThreatLevel = threat;
            }

            return result;
        }

        private static void Escalate(ref ThreatLevel current, ThreatLevel proposed)
        {
            if (proposed > current)
                current = proposed;
        }
    }
}
