using Microsoft.Win32;
using System;
using System.Diagnostics;

namespace USBGuardian
{
    public class ThreatIsolationManager
    {
        private const int ConfigFlagDisabled = 0x100;
        private const int ConfigFlagReinstall = 0x40;

        private readonly SecurityEventLogger _eventLogger;
        private readonly UsbBlockingManager _blockingManager;
        private readonly ForensicsLogger _forensicsLogger;
        private int _criticalThreatCount;

        public ThreatIsolationManager(SecurityEventLogger eventLogger, UsbBlockingManager blockingManager, ForensicsLogger forensicsLogger)
        {
            _eventLogger = eventLogger;
            _blockingManager = blockingManager;
            _forensicsLogger = forensicsLogger;
        }

        public BlockingResult IsolateThreat(DeviceFingerprint device, string reason, ThreatLevel level)
        {
            string vidPid = $"{device.Vid}:{device.Pid}";
            var result = new BlockingResult { Method = "ThreatIsolation" };

            try
            {
                _blockingManager.BlockDevice(device, reason);
                DisableInstanceConfigFlags(device);

                // Only kill the usbstor service globally on Critical threats.
                // For lower-level threats, per-device ConfigFlags isolation is sufficient
                // and avoids breaking the driver association (Code 28) for all storage devices.
                if (level >= ThreatLevel.Critical)
                    DisableUsbStorService();

                _eventLogger.LogCritical(5, "ThreatIsolation", $"Threat isolation executed for {vidPid}: {reason}", vidPid);
                _eventLogger.LogWindowsEvent(SecuritySeverity.Critical, "USB Guardian", $"Threat isolation executed for {vidPid}: {reason}");
                _forensicsLogger.Log("ThreatIsolation", device, reason, level);

                if (level >= ThreatLevel.Critical)
                    _criticalThreatCount++;

                if (_criticalThreatCount >= 3)
                    DisableUsbSubsystemEmergency();

                result.Success = true;
                result.Message = "Threat isolated";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Threat isolation failed: {ex.Message}";
                Debug.WriteLine($"[ThreatIsolationManager] {result.Message}");
            }

            return result;
        }

        private static void DisableInstanceConfigFlags(DeviceFingerprint device)
        {
            if (string.IsNullOrWhiteSpace(device.Vid) || string.IsNullOrWhiteSpace(device.Pid) || string.IsNullOrWhiteSpace(device.InstanceId))
                return;

            string regPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{device.Vid}&PID_{device.Pid}\{device.InstanceId}";
            using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: true);
            if (key == null) return;

            int current = key.GetValue("ConfigFlags") is int flags ? flags : 0;
            key.SetValue("ConfigFlags", current | ConfigFlagDisabled | ConfigFlagReinstall, RegistryValueKind.DWord);
        }

        private static void DisableUsbStorService()
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", writable: true);
            key?.SetValue("Start", 4, RegistryValueKind.DWord);
        }

        private void DisableUsbSubsystemEmergency()
        {
            try
            {
                using var hub = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBHUB3", writable: true);
                hub?.SetValue("Start", 4, RegistryValueKind.DWord);

                using var xhci = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBXHCI", writable: true);
                xhci?.SetValue("Start", 4, RegistryValueKind.DWord);

                _eventLogger.LogAttack(5, "EmergencyUsbShutdown", "Critical threat threshold exceeded; emergency USB subsystem disable attempted.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ThreatIsolationManager] Emergency USB shutdown failed: {ex.Message}");
            }
        }
    }
}