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
        public List<string> SuspiciousCommandsDetected { get; set; } = new();
        public int RiskScore { get; set; }
    }

    public class KeystrokeBehaviorAnalyzer
    {
        private readonly SecurityEventLogger _logger;
        private readonly Dictionary<string, KeystrokeSession> _sessions = new();
        private readonly object _lock = new();

        // FIX: cap the number of concurrent sessions and evict stale entries to prevent
        // unbounded memory growth.  Each session accumulates keystroke timestamps for its
        // lifetime; without a bound, a long-running process that sees many HID devices
        // would grow indefinitely.
        private const int MaxSessions = 50;
        private static readonly TimeSpan SessionStaleAfter = TimeSpan.FromHours(2);

        private static readonly List<string> SuspiciousPatterns = new()
        {
            "powershell", "cmd.exe", "wget", "curl", "invoke-expression", "iex",
            "base64", "bypass", "encodedcommand", "downloadstring", "start-process",
            "net user", "reg add"
        };

        // Sliding window: only the most recent N timestamps are kept.
        // This ensures KPS always reflects CURRENT burst speed, not lifetime average.
        // A Rubber Ducky fires ~200 keystrokes in ~1.5 seconds → KPS ≈ 130 → Critical.
        // Normal humans type 5-8 KPS → window is never filled fast enough to trigger.
        private const int MaxTimestamps = 200;

        public KeystrokeBehaviorAnalyzer(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public void StartMonitoring(string vidPid)
        {
            lock (_lock)
            {
                // Evict stale sessions before adding a new one
                EvictStaleSessions_Locked();

                _sessions[vidPid] = new KeystrokeSession { DeviceVidPid = vidPid };
                _logger.LogInfo(3, "BehaviorMonitor", $"Started keystroke monitoring for {vidPid}", vidPid);
            }
        }

        // Must be called under _lock
        private void EvictStaleSessions_Locked()
        {
            DateTime cutoff = DateTime.UtcNow - SessionStaleAfter;
            var stale = new List<string>();
            foreach (var kvp in _sessions)
            {
                if (kvp.Value.StartTime < cutoff)
                    stale.Add(kvp.Key);
            }
            foreach (var key in stale)
            {
                _sessions.Remove(key);
                _logger.LogInfo(3, "BehaviorMonitor", $"Evicted stale keystroke session for {key}", key);
            }

            // If still over cap after eviction, drop oldest sessions
            while (_sessions.Count >= MaxSessions)
            {
                string oldest = null;
                DateTime oldestTime = DateTime.MaxValue;
                foreach (var kvp in _sessions)
                {
                    if (kvp.Value.StartTime < oldestTime)
                    {
                        oldestTime = kvp.Value.StartTime;
                        oldest = kvp.Key;
                    }
                }
                if (oldest != null)
                {
                    _sessions.Remove(oldest);
                    _logger.LogInfo(3, "BehaviorMonitor", $"Evicted oldest keystroke session (cap reached) for {oldest}", oldest);
                }
                else break;
            }
        }

        public void RecordKeystroke(string vidPid, DateTime timestamp)
        {
            lock (_lock)
            {
                if (!_sessions.TryGetValue(vidPid, out var session)) return;
                session.KeystrokeTimestamps.Add(timestamp);

                // Enforce sliding window — drop oldest timestamps beyond the cap.
                // This means KPS is always computed over the most recent MaxTimestamps
                // events, not the entire session lifetime, so burst attacks are always
                // visible even in a long-running session.
                while (session.KeystrokeTimestamps.Count > MaxTimestamps)
                    session.KeystrokeTimestamps.RemoveAt(0);
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
                    _logger.LogAttack(3, "RobotKeystroke",
                        $"Robot-like keystrokes from {vidPid}: {result.KeysPerSecond:F1} kps, " +
                        $"{result.TimingVariancePercent:F1}% variance, risk={result.RiskScore}", vidPid);
                else if (result.SuspiciousCommandsDetected.Count > 0)
                    _logger.LogWarning(3, "SuspiciousInput",
                        $"Suspicious commands from {vidPid}: {string.Join(", ", result.SuspiciousCommandsDetected)}", vidPid);
                // NOTE: No Info log for clean keystrokes — that would generate thousands of
                // entries per minute, flood the 1,000-event cap, and push out real USB events.
                // Threat detections are always written; clean typing is silently discarded.
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
                _logger.LogInfo(3, "BehaviorMonitor", $"Stopped keystroke monitoring for {vidPid}", vidPid);
            }
            return result;
        }
    }
}
