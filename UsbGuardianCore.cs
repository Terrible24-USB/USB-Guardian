using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace USBGuardian
{
    public class DeviceEvaluationResult
    {
        public DeviceFingerprint? DeviceFingerprint { get; set; }
        public DescriptorValidationResult? Layer1Result { get; set; }
        public ClassBlockResult? Layer2Result { get; set; }
        public BehaviorAnalysisResult? Layer3Result { get; set; }
        public FirmwareVerificationResult? Layer4Result { get; set; }
        public HIDClassifier.HIDThreatAssessment? Layer5Result { get; set; }
        public ThreatLevel OverallThreatLevel { get; set; } = ThreatLevel.None;
        public bool ShouldBlock { get; set; }
        public string BlockReason { get; set; } = string.Empty;
        public List<string> Recommendations { get; set; } = new();
    }

    public class UsbGuardianCore
    {
        private readonly SecurityEventLogger _eventLogger;
        private readonly DescriptorValidator _descriptorValidator;
        private readonly DeviceClassBlocker _classBlocker;
        private readonly KeystrokeBehaviorAnalyzer _behaviorAnalyzer;
        private readonly FirmwareSignatureVerifier _firmwareVerifier;
        private readonly InputDeviceMonitor _inputMonitor;
        private readonly IncidentResponseManager _incidentResponseManager;
        private readonly UsbBlockingManager _blockingManager;

        public SecurityEventLogger EventLogger => _eventLogger;
        public UsbBlockingManager BlockingManager => _blockingManager;

        public UsbGuardianCore()
        {
            _eventLogger = new SecurityEventLogger();
            _descriptorValidator = new DescriptorValidator(_eventLogger);
            _classBlocker = new DeviceClassBlocker(_eventLogger);
            _behaviorAnalyzer = new KeystrokeBehaviorAnalyzer(_eventLogger);
            _firmwareVerifier = new FirmwareSignatureVerifier(_eventLogger);
            _blockingManager = new UsbBlockingManager(_eventLogger);
            _inputMonitor = new InputDeviceMonitor(_eventLogger);
            _incidentResponseManager = new IncidentResponseManager(_eventLogger, _blockingManager);
        }

        public async Task InitializeAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    _eventLogger.LogInfo(0, "Startup", "USB Guardian Core initializing");

                    _inputMonitor.StartRealtimeHidMonitoring();
                    _eventLogger.LogInfo(5, "HIDInit", "Layer 5 HID classifier/input monitor initialized");
                    _eventLogger.LogInfo(6, "IncidentInit", "Layer 6 incident response manager initialized");

                    _eventLogger.LogInfo(0, "Startup", "USB Guardian Core initialized — all 6 layers active");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[UsbGuardianCore] InitializeAsync failed: {ex.Message}");
                }
            });
        }

        public DeviceEvaluationResult EvaluateDevice(DeviceFingerprint fingerprint)
        {
            var result = new DeviceEvaluationResult { DeviceFingerprint = fingerprint };

            try
            {
                string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
                ThreatLevel overall = ThreatLevel.None;

                // Layer 1: Descriptor Validation
                result.Layer1Result = _descriptorValidator.ValidateDevice(fingerprint);
                Escalate(ref overall, result.Layer1Result.ThreatLevel);

                // Layer 2: Device Class Blocking
                result.Layer2Result = _classBlocker.EvaluateDevice(fingerprint);
                Escalate(ref overall, result.Layer2Result.ThreatLevel);

                // Layer 4: Firmware Signature Verification
                result.Layer4Result = _firmwareVerifier.VerifyDevice(fingerprint);
                Escalate(ref overall, result.Layer4Result.ThreatLevel);

                // Layer 3: Real-time keystroke behavior
                _behaviorAnalyzer.StartMonitoring(vidPid);
                if (_inputMonitor.WasRecentlyDisconnected(fingerprint.DevicePath ?? string.Empty))
                {
                    result.Layer3Result = new BehaviorAnalysisResult
                    {
                        IsRobot = true,
                        ShouldBlockImmediately = true,
                        BlockReason = "HID appeared on recently disconnected path",
                        RiskScore = 80
                    };
                }
                else
                {
                    result.Layer3Result = _behaviorAnalyzer.AnalyzeSession(vidPid);
                }
                if (result.Layer3Result.ShouldBlockImmediately)
                    Escalate(ref overall, ThreatLevel.Critical);
                else if (result.Layer3Result.IsRobot)
                    Escalate(ref overall, ThreatLevel.High);

                // Layer 5: HID classification and input-device monitoring
                result.Layer5Result = HIDClassifier.AssessDevice(fingerprint, result.Layer3Result);
                Escalate(ref overall, result.Layer5Result.ThreatLevel);

                result.OverallThreatLevel = overall;

                // Determine if device should be blocked
                bool criticalThreat = result.OverallThreatLevel == ThreatLevel.Critical;
                bool classBlocked = result.Layer2Result.ShouldBlock;
                bool firmwareTampered = result.Layer4Result.IsTampered;
                bool realtimeImmediate = result.Layer3Result.ShouldBlockImmediately;
                bool hidThreat = result.Layer5Result.IsLikelyRubberDucky;

                result.ShouldBlock = criticalThreat || classBlocked || firmwareTampered || realtimeImmediate || hidThreat;

                // Build block reason
                var reasons = new List<string>();
                if (criticalThreat) reasons.Add($"Critical threat level (L1={result.Layer1Result.ThreatLevel})");
                if (classBlocked) reasons.Add($"Class blocked: {result.Layer2Result.Reason}");
                if (firmwareTampered) reasons.Add($"Firmware tampered: {string.Join("; ", result.Layer4Result.Issues)}");
                if (realtimeImmediate) reasons.Add(result.Layer3Result.BlockReason);
                if (hidThreat) reasons.Add($"Layer 5 HID threat: {string.Join("; ", result.Layer5Result.Findings)}");
                result.BlockReason = string.Join(" | ", reasons);

                // Recommendations
                if (result.Layer1Result.Issues.Count > 0)
                    result.Recommendations.Add($"Layer 1: {string.Join("; ", result.Layer1Result.Issues)}");
                if (result.Layer4Result.IsNewDevice)
                    result.Recommendations.Add("Layer 4: New device recorded — monitor for future changes");
                if (result.Layer5Result.Findings.Count > 0)
                    result.Recommendations.Add($"Layer 5: {string.Join("; ", result.Layer5Result.Findings)}");

                _eventLogger.LogInfo(0, "DeviceEvaluated",
                    $"Device {vidPid} evaluated: threat={result.OverallThreatLevel}, block={result.ShouldBlock}",
                    vidPid);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] EvaluateDevice failed: {ex.Message}");
                result.Recommendations.Add($"Evaluation error: {ex.Message}");
            }

            return result;
        }

        public BlockingResult HandleThreat(DeviceFingerprint device, DeviceEvaluationResult evaluationResult)
        {
            var blockResult = new BlockingResult();

            try
            {
                if (!evaluationResult.ShouldBlock)
                {
                    blockResult.Message = "No threat action required";
                    return blockResult;
                }

                string vidPid = $"{device.Vid}:{device.Pid}";
                _eventLogger.LogAttack(0, "ThreatHandled",
                    $"Blocking device {vidPid}: {evaluationResult.BlockReason}", vidPid);

                blockResult = _incidentResponseManager.HandleThreat(device, evaluationResult);

                if (string.IsNullOrEmpty(blockResult.Message))
                    blockResult.Message = $"Device blocked: {evaluationResult.BlockReason}";
            }
            catch (Exception ex)
            {
                blockResult.Message = $"Threat handling failed: {ex.Message}";
                Debug.WriteLine($"[UsbGuardianCore] HandleThreat failed: {ex.Message}");
            }

            return blockResult;
        }

        public Dictionary<string, object> GetSecurityStatus()
        {
            var status = new Dictionary<string, object>();
            try
            {
                status["RecentEvents"] = _eventLogger.GetRecentEvents(10);
                status["Layer5_HID"] = "Realtime HID classification active";
                status["Layer6_IncidentResponse"] = _incidentResponseManager.GetSnapshot();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] GetSecurityStatus failed: {ex.Message}");
            }
            return status;
        }

        private static void Escalate(ref ThreatLevel current, ThreatLevel proposed)
        {
            if (proposed > current)
                current = proposed;
        }
    }
}
