using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace USBGuardian
{
    public class KeystrokeSession
    {
        public string DeviceVidPid { get; set; } = string.Empty;
        public DateTime StartTime { get; set; } = DateTime.UtcNow;
        public List<DateTime> KeystrokeTimestamps { get; set; } = new();
        public List<string> SuspiciousCommands { get; set; } = new();
    }

    public class BehaviorAnalysisResult
    {
        public bool IsRobot { get; set; }
        public double KeysPerSecond { get; set; }
        public double TimingVariancePercent { get; set; }
        public bool ShouldBlockImmediately { get; set; }
        public string BlockReason { get; set; } = string.Empty;
        public List<string> SuspiciousCommandsDetected { get; set; } = new();
        public int RiskScore { get; set; }
    }

    public class KeystrokeBehaviorAnalyzer
    {
        private readonly SecurityEventLogger _logger;
        private readonly Dictionary<string, KeystrokeSession> _sessions = new();
        private readonly Dictionary<string, string> _immediateBlockReasons = new();
        private readonly object _lock = new();
        private const double InstantBlockThresholdKps = 100.0;
        private const int RealtimeWindowMilliseconds = 1000;

        private static readonly List<string> SuspiciousPatterns = new()
        {
            "powershell", "cmd.exe", "wget", "curl", "invoke-expression", "iex",
            "base64", "bypass", "encodedcommand", "downloadstring", "start-process",
            "net user", "reg add"
        };

        public KeystrokeBehaviorAnalyzer(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public void StartMonitoring(string vidPid)
        {
            lock (_lock)
            {
                _sessions[vidPid] = new KeystrokeSession { DeviceVidPid = vidPid };
                _logger.LogInfo(3, "BehaviorMonitor", $"Started keystroke monitoring for {vidPid}", vidPid);
            }
        }

        public void RecordKeystroke(string vidPid, DateTime timestamp)
        {
            lock (_lock)
            {
                if (!_sessions.TryGetValue(vidPid, out var session)) return;
                session.KeystrokeTimestamps.Add(timestamp);

                DateTime windowStart = timestamp.AddMilliseconds(-RealtimeWindowMilliseconds);
                int recentCount = 0;
                for (int i = session.KeystrokeTimestamps.Count - 1; i >= 0; i--)
                {
                    if (session.KeystrokeTimestamps[i] < windowStart)
                        break;
                    recentCount++;
                }

                double kps = recentCount / (RealtimeWindowMilliseconds / 1000.0);
                if (kps > InstantBlockThresholdKps)
                {
                    string reason = $"Instant block: impossible keystroke velocity detected ({kps:F1} KPS > {InstantBlockThresholdKps:F0})";
                    _immediateBlockReasons[vidPid] = reason;
                    _logger.LogAttack(3, "InstantKeystrokeBlock", reason, vidPid);
                }
            }
        }

        public void RecordText(string vidPid, string text)
        {
            lock (_lock)
            {
                if (!_sessions.TryGetValue(vidPid, out var session)) return;

                // Scan for suspicious command patterns (primary purpose of RecordText)
                string lower = text.ToLowerInvariant();
                foreach (var pattern in SuspiciousPatterns)
                {
                    if (lower.Contains(pattern) && !session.SuspiciousCommands.Contains(pattern))
                    {
                        session.SuspiciousCommands.Add(pattern);
                        _logger.LogAttack(3, "SuspiciousCommand", $"Suspicious command pattern '{pattern}' detected from {vidPid}", vidPid);
                        if (!_immediateBlockReasons.ContainsKey(vidPid))
                            _immediateBlockReasons[vidPid] = $"Instant block: suspicious command sequence '{pattern}' detected";
                    }
                }
            }
        }

        public BehaviorAnalysisResult AnalyzeSession(string vidPid)
        {
            KeystrokeSession? session;
            lock (_lock)
            {
                _sessions.TryGetValue(vidPid, out session);
            }

            var result = new BehaviorAnalysisResult();
            if (session == null) return result;

            try
            {
                result.SuspiciousCommandsDetected = new List<string>(session.SuspiciousCommands);
                if (_immediateBlockReasons.TryGetValue(vidPid, out string? reason))
                {
                    result.ShouldBlockImmediately = true;
                    result.BlockReason = reason;
                }

                var timestamps = session.KeystrokeTimestamps;
                if (timestamps.Count < 2)
                {
                    result.RiskScore = session.SuspiciousCommands.Count > 0 ? 50 : 0;
                    return result;
                }

                double elapsed = (timestamps[^1] - timestamps[0]).TotalSeconds;
                result.KeysPerSecond = elapsed > 0 ? timestamps.Count / elapsed : timestamps.Count;

                // Calculate timing variance
                var intervals = new List<double>();
                for (int i = 1; i < timestamps.Count; i++)
                    intervals.Add((timestamps[i] - timestamps[i - 1]).TotalMilliseconds);

                double mean = intervals.Average();
                double variance = mean > 0 ? intervals.Select(x => Math.Abs(x - mean) / mean).Average() * 100.0 : 0;
                result.TimingVariancePercent = variance;

                bool robotBySpeed = result.KeysPerSecond > 50;
                bool robotByVariance = result.TimingVariancePercent < 10.0 && timestamps.Count >= 10;
                result.IsRobot = robotBySpeed || robotByVariance;

                // Compute risk score 0-100
                int score = 0;
                if (robotBySpeed) score += 40;
                if (robotByVariance) score += 30;
                score += Math.Min(30, session.SuspiciousCommands.Count * 10);
                result.RiskScore = Math.Min(100, score);

                if (result.IsRobot)
                    _logger.LogAttack(3, "RobotKeystroke", $"Robot-like keystrokes from {vidPid}: {result.KeysPerSecond:F1} kps, {result.TimingVariancePercent:F1}% variance, risk={result.RiskScore}", vidPid);
                else if (result.SuspiciousCommandsDetected.Count > 0)
                    _logger.LogWarning(3, "SuspiciousInput", $"Suspicious commands from {vidPid}: {string.Join(", ", result.SuspiciousCommandsDetected)}", vidPid);
                else
                    _logger.LogInfo(3, "BehaviorAnalysis", $"Keystroke analysis for {vidPid}: {result.KeysPerSecond:F1} kps, risk={result.RiskScore}", vidPid);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[KeystrokeBehaviorAnalyzer] Exception: {ex.Message}");
            }

            return result;
        }

        public BehaviorAnalysisResult StopMonitoring(string vidPid)
        {
            var result = AnalyzeSession(vidPid);
            lock (_lock)
            {
                _sessions.Remove(vidPid);
                _immediateBlockReasons.Remove(vidPid);
                _logger.LogInfo(3, "BehaviorMonitor", $"Stopped keystroke monitoring for {vidPid}", vidPid);
            }
            return result;
        }

        public bool TryGetImmediateBlockReason(string vidPid, out string reason)
        {
            lock (_lock)
            {
                return _immediateBlockReasons.TryGetValue(vidPid, out reason!);
            }
        }
    }
}
