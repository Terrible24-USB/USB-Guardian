using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace USBGuardian
{
    public class DeviceEvaluationResult
    {
        public DeviceFingerprint? DeviceFingerprint { get; set; }
        public IdentityValidationResult? IdentityLayerResult { get; set; }
        public DescriptorValidationResult? Layer1Result { get; set; }
        public DeviceClassHardeningResult? ClassHardeningResult { get; set; }
        public ClassBlockResult? Layer2Result { get; set; }
        public FirmwareIntegrityResult? FirmwareIntegrityResult { get; set; }
        public FirmwareVerificationResult? Layer4Result { get; set; }
        public ThreatLevel OverallThreatLevel { get; set; } = ThreatLevel.None;
        public bool ShouldBlock { get; set; }
        public string BlockReason { get; set; } = string.Empty;
        public List<string> Recommendations { get; set; } = new();
    }

    public class UsbGuardianCore
    {
        private readonly SecurityEventLogger _eventLogger;
        private readonly UsbBlockingManager _blockingManager;
        private readonly UsbGuardianSecurityEngine _securityEngine;
        private readonly DeviceInformationCollector _deviceInformationCollector;
        private readonly DeviceWhitelist _deviceWhitelist;
        private readonly IntelligentUsbBlocker _intelligentUsbBlocker;

        public SecurityEventLogger EventLogger => _eventLogger;
        public UsbBlockingManager BlockingManager => _blockingManager;
        public IntelligentUsbBlocker IntelligentUsbBlocker => _intelligentUsbBlocker;

        public UsbGuardianCore()
        {
            _eventLogger = new SecurityEventLogger();
            _blockingManager = new UsbBlockingManager(_eventLogger);
            _securityEngine = new UsbGuardianSecurityEngine(_eventLogger, _blockingManager);
            _deviceInformationCollector = new DeviceInformationCollector();
            _deviceWhitelist = new DeviceWhitelist();
            _intelligentUsbBlocker = new IntelligentUsbBlocker(_eventLogger, _deviceWhitelist, _deviceInformationCollector);
        }

        public async Task InitializeAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    _eventLogger.LogInfo(0, "Startup", "USB Guardian Core initializing");
                    _eventLogger.LogInfo(0, "Startup", "USB Guardian Core initialized — 5-layer aggressive defense active");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[UsbGuardianCore] InitializeAsync failed: {ex.Message}");
                }
            });
        }

        public DeviceEvaluationResult EvaluateDevice(DeviceFingerprint fingerprint)
        {
            try
            {
                return _securityEngine.EvaluateDevice(fingerprint);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] EvaluateDevice failed: {ex.Message}");
                return new DeviceEvaluationResult
                {
                    DeviceFingerprint = fingerprint,
                    ShouldBlock = true,
                    OverallThreatLevel = ThreatLevel.High,
                    BlockReason = $"Evaluation error: {ex.Message}",
                    Recommendations = new List<string> { $"Evaluation error: {ex.Message}" }
                };
            }
        }

        public void StartKeystrokeMonitoring(string vidPid)
        {
            try
            {
                _securityEngine.StartKeystrokeMonitoring(vidPid);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] StartKeystrokeMonitoring failed for {vidPid}: {ex.Message}");
            }
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

                var isolation = _securityEngine.IsolateThreat(device, evaluationResult);

                blockResult.Success = isolation.Success;
                blockResult.Method = isolation.Method;
                blockResult.Message = isolation.Message;
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
                status["Architecture"] = "5-layer aggressive defense";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] GetSecurityStatus failed: {ex.Message}");
            }
            return status;
        }

        public bool IsWhitelisted(DeviceFingerprint fingerprint)
        {
            try
            {
                return _securityEngine.IsWhitelisted(fingerprint);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] IsWhitelisted failed: {ex.Message}");
                return false;
            }
        }

        public void ApproveWhitelist(DeviceFingerprint fingerprint)
        {
            try
            {
                _securityEngine.ApproveWhitelisted(fingerprint);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] ApproveWhitelist failed: {ex.Message}");
            }
        }

        public bool TemporarilyEnableUsbStorage(DeviceFingerprint fingerprint, int enableDurationSeconds = 60)
        {
            try
            {
                return _securityEngine.TemporarilyEnableUsbStorage(fingerprint, enableDurationSeconds);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UsbGuardianCore] TemporarilyEnableUsbStorage failed: {ex.Message}");
                return false;
            }
        }

        public UnblockResult RecoverAllowedDevice(
            DeviceFingerprint device,
            UnblockManager unblockManager,
            int waitTimeoutMs = 2000)
        {
            var result = new UnblockResult();

            if (device == null)
            {
                result.Messages.Add("Allow recovery skipped: device is null.");
                result.NeedsReplug = true;
                return result;
            }

            if (unblockManager == null)
            {
                result.Messages.Add("Allow recovery skipped: UnblockManager is unavailable.");
                result.NeedsReplug = true;
                return result;
            }

            string vidPid = $"{device.Vid}:{device.Pid}";
            _eventLogger.LogInfo(0, "AllowRecovery",
                $"Starting allow recovery for {vidPid}", vidPid);

            try
            {
                return unblockManager.RecoverEvaluatingDevice(device, waitTimeoutMs);
            }
            catch (Exception ex)
            {
                result.Messages.Add($"Allow recovery failed: {ex.Message}");
                result.NeedsReplug = true;
                Debug.WriteLine($"[UsbGuardianCore] RecoverAllowedDevice failed: {ex.Message}");
                return result;
            }
        }

    }
}
