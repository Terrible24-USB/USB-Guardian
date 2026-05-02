using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace USBGuardian
{
    internal sealed class TemporaryDeviceEnablerManager
    {
        private readonly SecurityEventLogger _logger;
        private readonly DeviceWhitelistManager _whitelist;
        private readonly object _lock = new();
        private readonly Dictionary<string, DateTime> _enabledDevices = new(StringComparer.OrdinalIgnoreCase);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string? pDeviceID, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Reenumerate_DevNode(uint dnDevInst, uint ulFlags);

        private const int CR_SUCCESS = 0;
        private const uint CM_LOCATE_DEVNODE_NORMAL = 0;
        private const uint CM_REENUMERATE_NORMAL = 0;

        public TemporaryDeviceEnablerManager(SecurityEventLogger logger, DeviceWhitelistManager whitelist)
        {
            _logger = logger;
            _whitelist = whitelist;
        }

        public bool TemporarilyEnableUsbStorage(string vidPid, int enableDurationSeconds = 60)
        {
            return TemporarilyEnableUsbStorageCore(vidPid, enableDurationSeconds);
        }

        public async Task<bool> TemporarilyEnableUsbStorageAsync(string vidPid, int enableDurationSeconds = 60)
        {
            return await Task.Run(() => TemporarilyEnableUsbStorageCore(vidPid, enableDurationSeconds)).ConfigureAwait(false);
        }

        private bool TemporarilyEnableUsbStorageCore(string vidPid, int enableDurationSeconds)
        {
            if (string.IsNullOrWhiteSpace(vidPid))
                return false;

            try
            {
                ServiceHardeningManager.EnableUsbStorManual(_logger);
                Thread.Sleep(100);

                ClearConfigFlagsForVidPid(vidPid);
                Thread.Sleep(100);

                TriggerDeviceRescan();
                Thread.Sleep(500);

                DateTime expiresUtc = DateTime.UtcNow.AddSeconds(enableDurationSeconds);
                lock (_lock)
                {
                    _enabledDevices[vidPid] = expiresUtc;
                }
                _logger.LogPreBootAction("TemporaryEnable",
                    $"USB storage temporarily enabled for {vidPid} for {enableDurationSeconds}s.", SecuritySeverity.Warning, vidPid);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(enableDurationSeconds)).ConfigureAwait(false);
                        bool expired = false;
                        lock (_lock)
                        {
                            if (_enabledDevices.TryGetValue(vidPid, out DateTime currentExpiry) &&
                                currentExpiry == expiresUtc &&
                                currentExpiry <= DateTime.UtcNow)
                            {
                                _enabledDevices.Remove(vidPid);
                                expired = true;
                            }
                        }

                        if (expired)
                        {
                            _logger.LogPreBootAction("TemporaryEnable",
                                $"Temporary USB storage window expired for {vidPid}. No persistent pre-boot block re-applied.",
                                SecuritySeverity.Warning,
                                vidPid);
                        }
                    }
                    catch (Exception delayedEx)
                    {
                        _logger.LogWarning(0, "TemporaryEnable", $"Temporary enable expiration handler failed for {vidPid}: {delayedEx.Message}", vidPid);
                    }
                });

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(0, "TemporaryEnable", $"Failed to temporarily enable {vidPid}: {ex.Message}", vidPid);
                return false;
            }
        }

        public bool IsWhitelisted(string vidPid)
        {
            if (string.IsNullOrWhiteSpace(vidPid)) return false;
            var parts = vidPid.Split(':', 2);
            if (parts.Length != 2) return false;

            var candidate = new DeviceFingerprint { Vid = parts[0], Pid = parts[1] };
            return _whitelist.IsWhitelisted(candidate);
        }

        public bool IsTemporaryWindowActive(string vidPid)
        {
            if (string.IsNullOrWhiteSpace(vidPid)) return false;
            lock (_lock)
            {
                if (!_enabledDevices.TryGetValue(vidPid, out DateTime expiresUtc))
                    return false;

                if (expiresUtc <= DateTime.UtcNow)
                {
                    _enabledDevices.Remove(vidPid);
                    return false;
                }

                return true;
            }
        }

        private void ClearConfigFlagsForVidPid(string vidPid)
        {
            var parts = vidPid.Split(':', 2);
            if (parts.Length != 2) return;

            string vid = parts[0];
            string pid = parts[1];
            string usbPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}";

            try
            {
                using var parent = Registry.LocalMachine.OpenSubKey(usbPath);
                if (parent == null) return;

                foreach (string instance in parent.GetSubKeyNames())
                {
                    using var key = Registry.LocalMachine.OpenSubKey($@"{usbPath}\{instance}", writable: true);
                    if (key == null) continue;

                    int current = key.GetValue("ConfigFlags") is int flags ? flags : 0;
                    int cleared = current & ~(0x100 | 0x40);
                    key.SetValue("ConfigFlags", cleared, RegistryValueKind.DWord);
                    _logger.LogPreBootAction("TemporaryEnable",
                        $"Cleared ConfigFlags on USB\\VID_{vid}&PID_{pid}\\{instance}: 0x{current:X}→0x{cleared:X}",
                        SecuritySeverity.Info,
                        vidPid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(0, "TemporaryEnable", $"Failed clearing ConfigFlags for {vidPid}: {ex.Message}", vidPid);
            }
        }

        private void TriggerDeviceRescan()
        {
            try
            {
                int locate = CM_Locate_DevNodeW(out uint devInst, null, CM_LOCATE_DEVNODE_NORMAL);
                if (locate == CR_SUCCESS)
                {
                    CM_Reenumerate_DevNode(devInst, CM_REENUMERATE_NORMAL);
                    return;
                }

                _logger.LogWarning(0, "TemporaryEnable", $"Device rescan locate call failed (code={locate}).");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TemporaryEnable] Device rescan failed: {ex.Message}");
            }
        }
    }
}
