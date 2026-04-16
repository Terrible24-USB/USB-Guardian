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
                result.Reason = $">100 KPS detected ({behavior.KeysPerSecond:F1})";
            }
            else if (behavior.KeysPerSecond >= 20 && behavior.TimingVariancePercent < 10)
            {
                result.IsThreat = true;
                result.ShouldIsolate = true;
                result.ThreatLevel = ThreatLevel.High;
                result.Reason = $"Uniform high-speed input ({behavior.KeysPerSecond:F1} KPS, variance {behavior.TimingVariancePercent:F1}%)";
            }
            else if (pattern.IsThreat)
            {
                result.IsThreat = true;
                result.ShouldIsolate = true;
                result.ThreatLevel = ThreatLevel.Critical;
                result.Reason = $"Rubber Ducky command pattern detected: {string.Join(", ", pattern.Matches)}";
            }

            if (result.ShouldIsolate)
                _logger.LogAttack(3, "RealTimeKeystrokeThreat", result.Reason, vidPid);

            return result;
        }

        public KeystrokeThreatResult StopMonitoring(string vidPid)
        {
            _ = _analyzer.StopMonitoring(vidPid);
            return AnalyzeRealtime(vidPid);
        }
    }
}
