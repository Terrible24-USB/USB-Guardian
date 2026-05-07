using System;
using System.Collections.Generic;

namespace USBGuardian
{
    public class UsbGuardianSecurityEngine
    {
        private readonly SecurityEventLogger _eventLogger;
        private readonly DeviceIdentityValidator _identityValidator;
        private readonly DeviceClassHardener _classHardener;
        private readonly RealTimeKeystrokeMonitor _keystrokeMonitor;
        private readonly FirmwareIntegrityMonitor _firmwareIntegrityMonitor;
        private readonly ThreatIsolationManager _threatIsolationManager;
        private readonly ForensicsLogger _forensicsLogger;
        private readonly DeviceWhitelistManager _whitelistManager;
        private readonly TemporaryDeviceEnablerManager _temporaryDeviceEnabler;

        public UsbGuardianSecurityEngine(SecurityEventLogger eventLogger, UsbBlockingManager blockingManager)
        {
            _eventLogger = eventLogger;
            _whitelistManager = new DeviceWhitelistManager();
            _temporaryDeviceEnabler = new TemporaryDeviceEnablerManager(eventLogger, _whitelistManager);
            _forensicsLogger = new ForensicsLogger();
            _identityValidator = new DeviceIdentityValidator(eventLogger);
            _classHardener = new DeviceClassHardener(eventLogger, _whitelistManager);
            _keystrokeMonitor = new RealTimeKeystrokeMonitor(eventLogger);
            _firmwareIntegrityMonitor = new FirmwareIntegrityMonitor(eventLogger);
            _threatIsolationManager = new ThreatIsolationManager(eventLogger, blockingManager, _forensicsLogger);
        }

        public DeviceEvaluationResult EvaluateDevice(DeviceFingerprint fingerprint)
        {
            _keystrokeMonitor.LastInsertedUsbDevice = fingerprint;
            var result = new DeviceEvaluationResult { DeviceFingerprint = fingerprint };
            string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";

            var identity = _identityValidator.Validate(fingerprint);
            result.IdentityLayerResult = identity;
            result.Layer1Result = identity.ToDescriptorValidationResult();
            var overallThreat = result.OverallThreatLevel;
            Escalate(ref overallThreat, identity.ThreatLevel);

            var classResult = _classHardener.Evaluate(fingerprint);
            result.ClassHardeningResult = classResult;
            result.Layer2Result = classResult.ToClassBlockResult();
            Escalate(ref overallThreat, classResult.ThreatLevel);

            var firmware = _firmwareIntegrityMonitor.VerifyIntegrity(fingerprint);
            result.FirmwareIntegrityResult = firmware;
            result.Layer4Result = firmware.ToFirmwareVerificationResult();
            Escalate(ref overallThreat, firmware.ThreatLevel);
            result.OverallThreatLevel = overallThreat;

            result.ShouldBlock = identity.ShouldBlock || classResult.ShouldBlock || firmware.IsTampered;
            result.BlockReason = string.Join(" | ", BuildReasons(identity, classResult, firmware));
            result.Recommendations.Add("Layer 3 real-time keystroke monitor is active for approved HID devices.");

            _forensicsLogger.Log("DeviceEvaluated", fingerprint,
                $"Evaluated with threat={result.OverallThreatLevel}, shouldBlock={result.ShouldBlock}",
                result.OverallThreatLevel);

            if (result.ShouldBlock)
                _eventLogger.LogAttack(0, "SecurityEngine", $"Device {vidPid} blocked: {result.BlockReason}", vidPid);
            else
                _eventLogger.LogInfo(0, "SecurityEngine", $"Device {vidPid} allowed", vidPid);

            return result;
        }

        public BlockingResult IsolateThreat(DeviceFingerprint device, DeviceEvaluationResult evaluation)
        {
            string reason = string.IsNullOrWhiteSpace(evaluation.BlockReason)
                ? "Threat detected by security engine"
                : evaluation.BlockReason;

            return _threatIsolationManager.IsolateThreat(device, reason, evaluation.OverallThreatLevel);
        }

        public void StartKeystrokeMonitoring(string vidPid) => _keystrokeMonitor.StartMonitoring(vidPid);

        public KeystrokeThreatResult EvaluateKeystrokeThreat(string vidPid, bool stop = false, bool isText = false, string text = "")
        {
            if (stop) return _keystrokeMonitor.StopMonitoring(vidPid);
            
            if (isText)
                _keystrokeMonitor.RecordText(vidPid, text);
            else
                _keystrokeMonitor.RecordKeystroke(vidPid, DateTime.UtcNow);

            return _keystrokeMonitor.AnalyzeRealtime(vidPid);
        }

        public bool IsWhitelisted(DeviceFingerprint fingerprint) => _whitelistManager.IsWhitelisted(fingerprint);

        public void ApproveWhitelisted(DeviceFingerprint fingerprint, string approvedBy = "admin") =>
            _whitelistManager.Approve(fingerprint, approvedBy);

        public bool TemporarilyEnableUsbStorage(DeviceFingerprint fingerprint, int enableDurationSeconds = 60)
        {
            string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";
            return _temporaryDeviceEnabler.TemporarilyEnableUsbStorage(vidPid, enableDurationSeconds);
        }

        private static IEnumerable<string> BuildReasons(
            IdentityValidationResult identity,
            DeviceClassHardeningResult classResult,
            FirmwareIntegrityResult firmware)
        {
            if (identity.ShouldBlock)
                yield return $"Identity validation failed: {string.Join("; ", identity.Issues)}";
            if (classResult.ShouldBlock)
                yield return $"Class hardening block: {classResult.Reason}";
            if (firmware.IsTampered)
                yield return $"Firmware integrity failure: {string.Join("; ", firmware.Issues)}";
        }

        private static void Escalate(ref ThreatLevel current, ThreatLevel proposed)
        {
            if (proposed > current)
                current = proposed;
        }
    }
}
