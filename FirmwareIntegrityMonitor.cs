namespace USBGuardian
{
    public class FirmwareIntegrityResult
    {
        public bool IsVerified { get; set; } = true;
        public bool IsTampered { get; set; }
        public bool IsNewDevice { get; set; }
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
        public System.Collections.Generic.List<string> Issues { get; set; } = new();

        public FirmwareVerificationResult ToFirmwareVerificationResult() => new()
        {
            IsVerified = IsVerified,
            IsTampered = IsTampered,
            IsNewDevice = IsNewDevice,
            ThreatLevel = ThreatLevel,
            Issues = new System.Collections.Generic.List<string>(Issues)
        };
    }

    public class FirmwareIntegrityMonitor
    {
        private readonly FirmwareSignatureVerifier _verifier;

        public FirmwareIntegrityMonitor(SecurityEventLogger logger)
        {
            _verifier = new FirmwareSignatureVerifier(logger);
        }

        public FirmwareIntegrityResult VerifyIntegrity(DeviceFingerprint fingerprint)
        {
            var verification = _verifier.VerifyDevice(fingerprint);
            return new FirmwareIntegrityResult
            {
                IsVerified = verification.IsVerified,
                IsTampered = verification.IsTampered,
                IsNewDevice = verification.IsNewDevice,
                ThreatLevel = verification.ThreatLevel,
                Issues = verification.Issues
            };
        }
    }
}
