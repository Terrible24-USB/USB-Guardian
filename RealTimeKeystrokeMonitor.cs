using System;
using System.Collections.Generic;

namespace USBGuardian
{
    public class KeystrokeThreatResult
    {
        public bool IsThreat { get; set; }
        public bool ShouldIsolate { get; set; }
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
        public string Reason { get; set; } = string.Empty;
        public double KeysPerSecond { get; set; }
        public double TimingVariancePercent { get; set; }
        public List<string> SuspiciousPatterns { get; set; } = new();
    }

    public class RealTimeKeystrokeMonitor
    {
        private readonly SecurityEventLogger _logger;
        private readonly KeystrokeBehaviorAnalyzer _analyzer;
        private readonly RubberDuckyPatternDetector _patternDetector;

        // Per-session throttle: only run the full analysis once per second max.
        // This prevents hammering the log file with thousands of Info entries.
        private readonly Dictionary<string, DateTime> _lastAnalysisTime = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan AnalysisInterval = TimeSpan.FromSeconds(1);

        // Tracks the last USB device evaluated by the security engine
        // so we can correlate keyboard macro attacks to the most recently inserted device.
        public DeviceFingerprint? LastInsertedUsbDevice { get; set; }

        public RealTimeKeystrokeMonitor(SecurityEventLogger logger)
        {
            _logger = logger;
            _analyzer = new KeystrokeBehaviorAnalyzer(logger);
            _patternDetector = new RubberDuckyPatternDetector();
        }

        public void StartMonitoring(string vidPid) => _analyzer.StartMonitoring(vidPid);

        public void RecordKeystroke(string vidPid, DateTime timestamp) => _analyzer.RecordKeystroke(vidPid, timestamp);

        public void RecordText(string vidPid, string text) => _analyzer.RecordText(vidPid, text);

        public KeystrokeThreatResult AnalyzeRealtime(string vidPid)
        {
            // Throttle: skip analysis if we ran it less than 1 second ago for this session.
            DateTime now = DateTime.UtcNow;
            if (_lastAnalysisTime.TryGetValue(vidPid, out DateTime last) &&
                (now - last) < AnalysisInterval)
            {
                return new KeystrokeThreatResult(); // blank — not a threat, not logged
            }
            _lastAnalysisTime[vidPid] = now;

            var behavior = _analyzer.AnalyzeSession(vidPid);
            var pattern = _patternDetector.AnalyzeCommands(behavior.SuspiciousCommandsDetected);

            var result = new KeystrokeThreatResult
            {
                KeysPerSecond = behavior.KeysPerSecond,
                TimingVariancePercent = behavior.TimingVariancePercent,
                SuspiciousPatterns = pattern.Matches,
                IsThreat = behavior.IsRobot || pattern.IsThreat,
                ShouldIsolate = false,
                ThreatLevel = ThreatLevel.None
            };

            if (behavior.KeysPerSecond > 100)
            {
                result.IsThreat = true;
                result.ShouldIsolate = true;
                result.ThreatLevel = ThreatLevel.Critical;
                result.Reason = $">100 keys per second detected ({behavior.KeysPerSecond:F1} kps)";
            }
            else if (behavior.KeysPerSecond >= 20 && behavior.TimingVariancePercent < 10)
            {
                result.IsThreat = true;
                result.ShouldIsolate = true;
                result.ThreatLevel = ThreatLevel.High;
                result.Reason = $"Uniform high-speed input ({behavior.KeysPerSecond:F1} kps, variance {behavior.TimingVariancePercent:F1}%)";
            }
            else if (pattern.IsThreat)
            {
                result.IsThreat = true;
                result.ShouldIsolate = true;
                result.ThreatLevel = ThreatLevel.Critical;
                result.Reason = $"Rubber Ducky command pattern detected: {string.Join(", ", pattern.Matches)}";
            }

            if (result.ShouldIsolate)
            {
                string priorUsbInfo = LastInsertedUsbDevice != null 
                    ? $" | Prior USB: {LastInsertedUsbDevice.Vid}:{LastInsertedUsbDevice.Pid} ({LastInsertedUsbDevice.Description ?? "Unknown Device"})" 
                    : "";
                    
                _logger.LogAttack(3, "RealTimeKeystrokeThreat", result.Reason + priorUsbInfo, vidPid);
            }

            return result;
        }

        public KeystrokeThreatResult StopMonitoring(string vidPid)
        {
            _ = _analyzer.StopMonitoring(vidPid);
            return AnalyzeRealtime(vidPid);
        }
    }
}
