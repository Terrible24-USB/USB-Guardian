using System;
using System.Linq;

namespace USBGuardian
{
    public sealed class IntelligentUsbDecisionResult
    {
        public DeviceInformationSnapshot DeviceInformation { get; set; } = new();
        public bool IsWhitelisted { get; set; }
        public bool ShouldBlockImmediately { get; set; }
        public string Reason { get; set; } = string.Empty;
        public DeviceDecisionResult? UserDecision { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public string RiskAssessment { get; set; } = string.Empty;
    }

    public sealed class IntelligentUsbBlocker
    {
        private readonly SecurityEventLogger _logger;
        private readonly DeviceInformationCollector _collector;
        private readonly DeviceWhitelist _whitelist;

        public IntelligentUsbBlocker(
            SecurityEventLogger logger,
            DeviceWhitelist? whitelist = null,
            DeviceInformationCollector? collector = null)
        {
            _logger = logger;
            _collector = collector ?? new DeviceInformationCollector();
            _whitelist = whitelist ?? new DeviceWhitelist();
        }

        public IntelligentUsbDecisionResult EvaluateAndDecide(
            DeviceFingerprint fingerprint,
            DeviceEvaluationResult? evaluationResult = null,
            Func<DeviceDecisionRequest, DeviceDecisionResult>? decisionProvider = null)
        {
            var info = _collector.Collect(fingerprint);
            var result = new IntelligentUsbDecisionResult
            {
                DeviceInformation = info,
                IsWhitelisted = _whitelist.IsTrusted(fingerprint)
            };

            if (result.IsWhitelisted)
            {
                result.Reason = "Device matched trusted whitelist.";
                result.ThreatLevel = ThreatLevel.None;
                result.RiskAssessment = "Trusted device";
                return result;
            }

            (ThreatLevel threat, string risk) = AssessRisk(fingerprint, evaluationResult);
            result.ThreatLevel = threat;
            result.RiskAssessment = risk;

            if (threat >= ThreatLevel.Critical)
            {
                result.ShouldBlockImmediately = true;
                result.Reason = "Critical threat indicators detected.";
                result.UserDecision = new DeviceDecisionResult { Action = DeviceDecisionAction.Block };
                _logger.LogCritical(0, "IntelligentBlocker",
                    $"Auto-blocking critical device {info.VidPid}: {risk}",
                    info.VidPid);
                return result;
            }

            var request = new DeviceDecisionRequest
            {
                DeviceInformation = info,
                ThreatLevel = threat,
                RiskAssessment = risk,
                SuggestedAction = threat >= ThreatLevel.High
                    ? "Block unless this device is explicitly trusted."
                    : "Allow once if expected, or whitelist only if you fully trust this device."
            };

            DeviceDecisionResult decision = (decisionProvider ?? DeviceDecisionDialog.ShowDecision)(request);
            if (decision.Action == DeviceDecisionAction.AllowAndWhitelist || decision.NeverAskAgain)
                _whitelist.Trust(fingerprint);

            result.UserDecision = decision;
            result.Reason = $"User decision: {decision.Action}";
            return result;
        }

        private static (ThreatLevel ThreatLevel, string RiskAssessment) AssessRisk(
            DeviceFingerprint fingerprint,
            DeviceEvaluationResult? evaluationResult)
        {
            if (evaluationResult != null && evaluationResult.ShouldBlock)
                return (ThreatLevel.Critical, evaluationResult.BlockReason);

            bool mixedHidStorage = fingerprint.AllInterfaces?.Any(i => i.InterfaceClass == 0x03) == true &&
                                   fingerprint.AllInterfaces?.Any(i => i.InterfaceClass == 0x08) == true;
            if (mixedHidStorage)
                return (ThreatLevel.High, "Composite HID + Storage behavior detected (possible BadUSB pattern).");

            if (UsbStorageBlocker.IsUsbStorageDevice(fingerprint))
                return (ThreatLevel.Medium, "Unknown USB storage device requires explicit authorization.");

            return (ThreatLevel.Low, "Unknown USB device.");
        }
    }
}
