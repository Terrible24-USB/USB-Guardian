using System;
using System.Diagnostics;

namespace USBGuardian
{
    /// <summary>
    /// Orchestrates Layers 2 and 3 of the 4-layer Rubber Ducky defense on USB arrival.
    ///
    /// Execution sequence (called from the PnpDeviceGuard.DeviceArrived handler):
    ///   [2] FREEZE — CM_Disable_DevNode stops all further HID reports (&lt;5ms).
    ///   [3] FLUSH  — InputQueueFlusher removes keystrokes queued before the freeze.
    ///
    /// Layer 1 (fast PnP detection) is owned by <see cref="PnpDeviceGuard"/>.
    /// Layer 4 (execution-path block) is owned by <see cref="InputContainmentManager"/>
    /// and is activated by the caller when it shows the decision dialog.
    ///
    /// Timing telemetry for each layer is logged via <see cref="SecurityEventLogger"/>
    /// and can be monitored in the debug output to verify the &lt;50ms target.
    /// </summary>
    internal sealed class RubberDuckyDefense
    {
        private readonly SecurityEventLogger _logger;

        public RubberDuckyDefense(SecurityEventLogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Performs Layer 2 (device freeze) and Layer 3 (input queue flush) and
        /// records timing telemetry.  Call this from the PnpDeviceGuard.DeviceArrived
        /// event handler.
        /// </summary>
        /// <param name="symbolicLink">
        /// The symbolic link string received from PnpDeviceGuard (e.g.
        /// <c>\\?\USB#VID_xxxx&amp;PID_xxxx#instanceId#{guid}</c>).
        /// </param>
        /// <param name="instanceId">
        /// Out: the resolved PnP device-instance ID used for the freeze call,
        /// or <see cref="string.Empty"/> on failure.
        /// </param>
        /// <param name="freezeMs">
        /// Out: milliseconds taken by CM_Disable_DevNode, or 0 on failure.
        /// </param>
        /// <returns>
        /// <c>true</c> if the device was successfully frozen; <c>false</c> otherwise.
        /// </returns>
        public bool HandleArrival(string symbolicLink, out string instanceId, out long freezeMs)
        {
            instanceId = string.Empty;
            freezeMs = 0;

            if (string.IsNullOrWhiteSpace(symbolicLink))
                return false;

            try
            {
                // ── [2] FREEZE ────────────────────────────────────────────────────
                instanceId = PnpDeviceGuard.SymbolicLinkToInstanceId(symbolicLink);
                if (string.IsNullOrWhiteSpace(instanceId))
                {
                    _logger.LogWarning(0, "RubberDuckyDefense",
                        $"Could not resolve instance ID from symlink: {symbolicLink}");
                    return false;
                }

                var freezeSw = Stopwatch.StartNew();
                bool frozen = PnpDeviceGuard.DisableDevNode(instanceId);
                freezeSw.Stop();
                freezeMs = freezeSw.ElapsedMilliseconds;

                if (!frozen)
                {
                    _logger.LogWarning(0, "RubberDuckyDefense",
                        $"[2] CM_Disable_DevNode failed for {instanceId}");
                    return false;
                }

                _logger.LogInfo(0, "RubberDuckyDefense",
                    $"[2] Freeze: {freezeMs}ms — {instanceId}");

                // ── [3] FLUSH ─────────────────────────────────────────────────────
                var flushSw = Stopwatch.StartNew();
                InputQueueFlusher.FlushAll();
                flushSw.Stop();

                _logger.LogInfo(0, "RubberDuckyDefense",
                    $"[3] Flush: {flushSw.ElapsedMilliseconds}ms — " +
                    $"total [2+3]: {freezeMs + flushSw.ElapsedMilliseconds}ms");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(0, "RubberDuckyDefense",
                    $"HandleArrival failed for symlink '{symbolicLink}': {ex.Message}");
                return false;
            }
        }
    }
}
