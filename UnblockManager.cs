using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Reverses block operations that were recorded in a <see cref="BlockedDeviceRecord"/>.
    ///
    /// Safety design:
    /// - Only touches registry keys/values that were explicitly recorded at block time.
    ///   Nothing is changed unless the original value was captured in <see cref="BlockActionRecord"/>.
    /// - Does NOT use hardcoded service Start defaults; always restores the captured previous value.
    /// - <see cref="DryRun"/> mode: when true, every action is logged but no system changes are made.
    ///   Enable via the <c>USB_GUARDIAN_DRY_RUN=1</c> environment variable or by setting the property.
    /// </summary>
    public class UnblockManager
    {
        // ConfigFlags bits added by USB Guardian at block time
        private const int ConfigFlagDisabled = 0x100;
        private const int ConfigFlagReinstall = 0x40;

        private readonly BlockedDeviceStore _store;
        private readonly SecurityEventLogger _logger;

        /// <summary>
        /// When true, all actions are logged but no system changes are made.
        /// Activated by the USB_GUARDIAN_DRY_RUN=1 environment variable, or
        /// by setting this property directly.
        /// </summary>
        public bool DryRun { get; set; }

        public UnblockManager(BlockedDeviceStore store, SecurityEventLogger logger)
        {
            _store = store;
            _logger = logger;
            DryRun = string.Equals(
                Environment.GetEnvironmentVariable("USB_GUARDIAN_DRY_RUN"),
                "1",
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Reverse all block actions recorded for <paramref name="record"/>.
        /// After successful completion the record is removed from the store.
        ///
        /// Returns a list of human-readable result strings (one per action attempted).
        /// </summary>
        public List<string> UnblockDevice(BlockedDeviceRecord record)
        {
            var results = new List<string>();
            if (record == null) return results;

            string vidPid = $"{record.Vid}:{record.Pid}";
            string dryTag = DryRun ? " [DRY RUN]" : string.Empty;
            _logger.LogInfo(0, "Unblock", $"Unblocking {vidPid} ({record.Description}){dryTag}", vidPid);

            bool wmiDoneExplicitly = false;

            foreach (var action in record.Actions)
            {
                try
                {
                    string result = action.ActionType switch
                    {
                        "ConfigFlags"  => RestoreConfigFlags(action),
                        "ServiceStart" => RestoreServiceStart(action),
                        "WmiDisable"   => EnableViaWmi(record, ref wmiDoneExplicitly),
                        _              => $"Unknown action type '{action.ActionType}' — skipped"
                    };
                    results.Add(result);
                    _logger.LogInfo(0, "UnblockAction",
                        $"{action.ActionType}: {result}{dryTag}", vidPid);
                }
                catch (Exception ex)
                {
                    string msg = $"Error in '{action.ActionType}': {ex.Message}";
                    results.Add(msg);
                    Debug.WriteLine($"[UnblockManager] {msg}");
                }
            }

            // Always attempt WMI re-enable even if it was not recorded as an explicit action
            // (e.g., in the UsbStorageBlocker path where WMI disable is done separately).
            if (!wmiDoneExplicitly)
            {
                try
                {
                    bool dummy = false;
                    string wmiResult = EnableViaWmi(record, ref dummy);
                    results.Add($"WMI re-enable: {wmiResult}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[UnblockManager] WMI enable fallback failed: {ex.Message}");
                }
            }

            // Remove from the store so it no longer appears in the unblock list
            if (!DryRun)
                _store.Remove(record.Vid, record.Pid, record.InstanceId);

            return results;
        }

        // ---- Action reversal helpers ----

        private string RestoreConfigFlags(BlockActionRecord action)
        {
            if (string.IsNullOrEmpty(action.RegistryPath))
                return "Skipped: no registry path recorded";

            if (DryRun)
                return $"[DRY RUN] Would restore ConfigFlags on {action.RegistryPath} " +
                       $"(target value: 0x{(action.PreviousConfigFlags ?? 0):X})";

            using var key = Registry.LocalMachine.OpenSubKey(action.RegistryPath, writable: true);
            if (key == null)
                return $"Registry key not found: {action.RegistryPath}";

            // If we captured the previous value, restore it exactly.
            // If not, at minimum clear the bits USB Guardian set.
            int newValue;
            if (action.PreviousConfigFlags.HasValue)
            {
                newValue = action.PreviousConfigFlags.Value;
            }
            else
            {
                int current = key.GetValue("ConfigFlags") is int f ? f : 0;
                newValue = current & ~(ConfigFlagDisabled | ConfigFlagReinstall);
            }

            key.SetValue("ConfigFlags", newValue, RegistryValueKind.DWord);
            return $"Restored ConfigFlags=0x{newValue:X} on {action.RegistryPath}";
        }

        private string RestoreServiceStart(BlockActionRecord action)
        {
            if (string.IsNullOrEmpty(action.ServiceName))
                return "Skipped: no service name recorded";

            if (action.PreviousServiceStart == null)
                return $"Skipped: no previous Start value was recorded for service '{action.ServiceName}'";

            if (DryRun)
                return $"[DRY RUN] Would restore service '{action.ServiceName}' " +
                       $"Start to {action.PreviousServiceStart.Value}";

            string svcPath = $@"SYSTEM\CurrentControlSet\Services\{action.ServiceName}";
            using var svcKey = Registry.LocalMachine.OpenSubKey(svcPath, writable: true);
            if (svcKey == null)
                return $"Service key not found: {svcPath}";

            svcKey.SetValue("Start", action.PreviousServiceStart.Value, RegistryValueKind.DWord);
            return $"Restored service '{action.ServiceName}' Start={action.PreviousServiceStart.Value}";
        }

        private string EnableViaWmi(BlockedDeviceRecord record, ref bool markedDone)
        {
            markedDone = true;

            if (DryRun)
                return $"[DRY RUN] Would enable VID_{record.Vid}&PID_{record.Pid} via WMI";

            try
            {
                string query = $"SELECT * FROM Win32_PnPEntity " +
                               $"WHERE DeviceID LIKE '%VID_{record.Vid}&PID_{record.Pid}%'";
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    obj.InvokeMethod("Enable", null);
                    return $"Enabled via WMI: {obj["DeviceID"]}";
                }
                return "Device not found via WMI (may already be active or physically absent)";
            }
            catch (Exception ex)
            {
                return $"WMI enable failed: {ex.Message}";
            }
        }
    }
}
