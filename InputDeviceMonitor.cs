using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Linq;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Scans for HID input devices (keyboard, mouse, touchpad) and checks whether
    /// any of them are currently blocked by a policy-based AllowDeviceIDs restriction
    /// combined with DenyUnspecified=1.
    ///
    /// Used at startup to detect input-device lockout before the main UI initialises.
    /// </summary>
    public class InputDeviceMonitor
    {
        // Registry path that holds the policy-based allowlist
        private const string PolicyRestrictionsKey =
            @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
        private const string AllowDeviceIDsSubKey =
            @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceIDs";

        // WMI device classes that represent input devices
        private static readonly string[] InputDeviceClasses = { "Keyboard", "Mouse" };
        private readonly object _lock = new();
        private readonly Dictionary<string, List<DateTime>> _keystrokeSamples = new();
        private readonly Dictionary<string, DateTime> _recentlyDisconnectedHid = new();
        private readonly SecurityEventLogger? _logger;
        private ManagementEventWatcher? _creationWatcher;
        private ManagementEventWatcher? _deletionWatcher;

        public class InputMonitorResult
        {
            public bool ShouldBlock { get; set; }
            public string Reason { get; set; } = string.Empty;
            public double KeysPerSecond { get; set; }
            public bool UniformTimingDetected { get; set; }
            public bool RecentlyDisconnectedPortReused { get; set; }
        }

        /// <summary>
        /// Represents a detected input device that appears to be blocked.
        /// </summary>
        public class BlockedInputDevice
        {
            public string Description { get; set; } = string.Empty;
            public string DeviceClass  { get; set; } = string.Empty;
            public string PnpDeviceId  { get; set; } = string.Empty;
        }

        public InputDeviceMonitor(SecurityEventLogger? logger = null)
        {
            _logger = logger;
        }

        /// <summary>
        /// Returns a list of input devices that are present in the system but whose
        /// hardware IDs are NOT listed in AllowDeviceIDs while DenyUnspecified=1 is active.
        ///
        /// Returns an empty list if DenyUnspecified is not active (no lockout risk),
        /// or if all detected input devices are found in the allowlist.
        /// </summary>
        public List<BlockedInputDevice> DetectBlockedInputDevices()
        {
            var blocked = new List<BlockedInputDevice>();

            try
            {
                // Fast-path: if DenyUnspecified is not enabled, no lockout is possible.
                if (!IsDenyUnspecifiedEnabled())
                    return blocked;

                var allowedIds = LoadAllowedDeviceIds();
                var inputDevices = QueryInputDevicesViaWmi();

                foreach (var device in inputDevices)
                {
                    if (!IsDeviceAllowed(device.PnpDeviceId, allowedIds))
                        blocked.Add(device);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] Detection failed: {ex.Message}");
            }

            return blocked;
        }

        public InputMonitorResult RecordKeystrokeSample(string vidPid, DateTime timestamp)
        {
            var result = new InputMonitorResult();
            try
            {
                lock (_lock)
                {
                    if (!_keystrokeSamples.TryGetValue(vidPid, out var samples))
                    {
                        samples = new List<DateTime>();
                        _keystrokeSamples[vidPid] = samples;
                    }

                    samples.Add(timestamp);
                    DateTime windowStart = timestamp.AddSeconds(-1);
                    samples.RemoveAll(t => t < windowStart);

                    result.KeysPerSecond = samples.Count;
                    if (result.KeysPerSecond > 100)
                    {
                        result.ShouldBlock = true;
                        result.Reason = $"Impossible input rate ({result.KeysPerSecond:F0} KPS)";
                    }

                    if (samples.Count >= 8)
                    {
                        var intervals = new List<double>(samples.Count - 1);
                        for (int i = 1; i < samples.Count; i++)
                            intervals.Add((samples[i] - samples[i - 1]).TotalMilliseconds);

                        if (intervals.Count > 0)
                        {
                            double mean = intervals.Average();
                            if (mean > 0)
                            {
                                double variance = intervals.Select(i => Math.Pow(i - mean, 2)).Average();
                                double stdDev = Math.Sqrt(variance);
                                double coeffVar = stdDev / mean;
                                result.UniformTimingDetected = coeffVar < 0.08;
                                if (result.UniformTimingDetected && mean < 40.0)
                                {
                                    result.ShouldBlock = true;
                                    result.Reason = "Uniform machine-like keystroke timing detected";
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] RecordKeystrokeSample failed: {ex.Message}");
            }

            if (result.ShouldBlock)
                _logger?.LogAttack(5, "RealtimeInputBlock", $"{vidPid}: {result.Reason}", vidPid);

            return result;
        }

        public void StartRealtimeHidMonitoring()
        {
            try
            {
                if (_creationWatcher != null || _deletionWatcher != null)
                    return;

                _creationWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity'"));
                _creationWatcher.EventArrived += (_, e) => HandleRealtimePnpEvent(e, isCreation: true);
                _creationWatcher.Start();

                _deletionWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity'"));
                _deletionWatcher.EventArrived += (_, e) => HandleRealtimePnpEvent(e, isCreation: false);
                _deletionWatcher.Start();

                _logger?.LogInfo(5, "InputMonitor", "Real-time HID WMI monitoring started");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] StartRealtimeHidMonitoring failed: {ex.Message}");
            }
        }

        public void StopRealtimeHidMonitoring()
        {
            try
            {
                _creationWatcher?.Stop();
                _creationWatcher?.Dispose();
                _creationWatcher = null;

                _deletionWatcher?.Stop();
                _deletionWatcher?.Dispose();
                _deletionWatcher = null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] StopRealtimeHidMonitoring failed: {ex.Message}");
            }
        }

        public bool WasRecentlyDisconnected(string pnpDeviceId)
        {
            lock (_lock)
            {
                if (_recentlyDisconnectedHid.TryGetValue(pnpDeviceId, out DateTime disconnectedAt))
                {
                    return (DateTime.UtcNow - disconnectedAt) <= TimeSpan.FromMinutes(10);
                }
                return false;
            }
        }

        // ---- Private helpers ----

        private static bool IsDenyUnspecifiedEnabled()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PolicyRestrictionsKey);
                if (key == null) return false;
                var val = key.GetValue("DenyUnspecified");
                return val is int i && i == 1;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] IsDenyUnspecifiedEnabled failed: {ex.Message}");
                return false;
            }
        }

        private static HashSet<string> LoadAllowedDeviceIds()
        {
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(AllowDeviceIDsSubKey);
                if (key == null) return ids;

                foreach (string valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName);
                    if (val is string s && !string.IsNullOrWhiteSpace(s))
                        ids.Add(s.Trim());
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] LoadAllowedDeviceIds failed: {ex.Message}");
            }
            return ids;
        }

        private static List<BlockedInputDevice> QueryInputDevicesViaWmi()
        {
            var devices = new List<BlockedInputDevice>();
            ManagementObjectCollection results = null;
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_PnPEntity WHERE PNPClass='Keyboard' OR PNPClass='Mouse'");
                results = searcher.Get();
                foreach (ManagementObject obj in results)
                {
                    string? deviceId  = obj["DeviceID"]?.ToString();
                    string? pnpClass  = obj["PNPClass"]?.ToString();
                    string? name      = obj["Name"]?.ToString();

                    if (string.IsNullOrWhiteSpace(deviceId)) continue;

                    devices.Add(new BlockedInputDevice
                    {
                        PnpDeviceId  = deviceId,
                        DeviceClass  = pnpClass ?? "HID",
                        Description  = name ?? deviceId
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] WMI query failed: {ex.Message}");
            }
            finally
            {
                results?.Dispose();
            }
            return devices;
        }

        /// <summary>
        /// Returns true when any entry in <paramref name="allowedIds"/> is a prefix of
        /// or equals the device's PnP ID (policy IDs are often hardware-ID prefixes).
        /// </summary>
        private static bool IsDeviceAllowed(string pnpDeviceId, HashSet<string> allowedIds)
        {
            if (allowedIds.Count == 0) return false;

            foreach (string allowed in allowedIds)
            {
                if (pnpDeviceId.StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private void HandleRealtimePnpEvent(EventArrivedEventArgs e, bool isCreation)
        {
            try
            {
                if (e.NewEvent?["TargetInstance"] is not ManagementBaseObject target)
                    return;

                string pnpClass = target["PNPClass"]?.ToString() ?? string.Empty;
                if (!InputDeviceClasses.Contains(pnpClass, StringComparer.OrdinalIgnoreCase))
                    return;

                string deviceId = target["DeviceID"]?.ToString() ?? string.Empty;
                if (string.IsNullOrEmpty(deviceId))
                    return;

                if (isCreation)
                {
                    bool reused = WasRecentlyDisconnected(deviceId);
                    string evt = reused ? "HidPortReuse" : "HidConnected";
                    string details = reused
                        ? $"Potential HID emulation on recently disconnected port: {deviceId}"
                        : $"HID device connected: {deviceId}";
                    if (reused)
                        _logger?.LogWarning(5, evt, details, deviceId);
                    else
                        _logger?.LogInfo(5, evt, details, deviceId);
                }
                else
                {
                    lock (_lock)
                    {
                        _recentlyDisconnectedHid[deviceId] = DateTime.UtcNow;
                    }
                    _logger?.LogInfo(5, "HidDisconnected", $"HID device disconnected: {deviceId}", deviceId);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[InputDeviceMonitor] HandleRealtimePnpEvent failed: {ex.Message}");
            }
        }
    }
}
