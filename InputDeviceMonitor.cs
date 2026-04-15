using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
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

        /// <summary>
        /// Represents a detected input device that appears to be blocked.
        /// </summary>
        public class BlockedInputDevice
        {
            public string Description { get; set; } = string.Empty;
            public string DeviceClass  { get; set; } = string.Empty;
            public string PnpDeviceId  { get; set; } = string.Empty;
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
    }
}
