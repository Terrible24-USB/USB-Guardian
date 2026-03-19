using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace USBGuardian
{
    public class ClassBlockResult
    {
        public bool ShouldBlock { get; set; }
        public string Reason { get; set; } = string.Empty;
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
    }

    public class DeviceClassBlocker
    {
        private readonly SecurityEventLogger _logger;

        private static readonly Dictionary<byte, string> BlockedClasses = new()
        {
            { 0x08, "Mass Storage" },
            { 0x09, "Hub" },
            { 0xFF, "Vendor-Specific" },
            { 0x02, "CDC/Modem" },
            { 0x07, "Printer" },
            { 0x01, "Audio" },
            { 0xE0, "Wireless" },
            { 0xEF, "Composite" }
        };

        private static readonly HashSet<string> CriticalClasses = new() { "08", "09", "FF" };
        private static readonly HashSet<string> HighThreatClasses = new() { "02", "07", "01", "E0", "EF" };

        // Whitelisted VID:PID pairs (e.g., "046D:C52B" for Logitech Unifying Receiver)
        private static readonly HashSet<string> WhitelistedVidPids = new(StringComparer.OrdinalIgnoreCase)
        {
            // Populate with known-safe devices as needed
        };

        public DeviceClassBlocker(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public ClassBlockResult EvaluateDevice(DeviceFingerprint fingerprint)
        {
            var result = new ClassBlockResult();

            try
            {
                string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";

                // Whitelist check
                if (WhitelistedVidPids.Contains(vidPid))
                {
                    result.ThreatLevel = ThreatLevel.None;
                    result.ShouldBlock = false;
                    result.Reason = "Device is whitelisted";
                    _logger.LogInfo(2, "ClassBlock", $"Device {vidPid} is whitelisted — allowed", vidPid);
                    return result;
                }

                // Check for mixed HID + Storage interfaces (BadUSB indicator)
                bool hasHid = false, hasStorage = false;
                if (fingerprint.AllInterfaces != null)
                {
                    foreach (var iface in fingerprint.AllInterfaces)
                    {
                        if (iface.InterfaceClass == 0x03) hasHid = true;
                        if (iface.InterfaceClass == 0x08) hasStorage = true;
                    }
                }
                else
                {
                    hasHid = fingerprint.UsbDeviceClass == 0x03 || fingerprint.InterfaceClass == 0x03;
                    hasStorage = fingerprint.UsbDeviceClass == 0x08 || fingerprint.InterfaceClass == 0x08;
                }

                if (hasHid && hasStorage)
                {
                    result.ShouldBlock = true;
                    result.ThreatLevel = ThreatLevel.Critical;
                    result.Reason = "Device exposes both HID and Mass Storage interfaces — likely BadUSB";
                    _logger.LogAttack(2, "ClassBlock", $"BadUSB pattern detected on {vidPid}: mixed HID+Storage", vidPid);
                    return result;
                }

                byte cls = fingerprint.UsbDeviceClass;
                string clsHex = cls.ToString("X2");

                if (CriticalClasses.Contains(clsHex) && BlockedClasses.TryGetValue(cls, out string? critName))
                {
                    result.ShouldBlock = true;
                    result.ThreatLevel = ThreatLevel.Critical;
                    result.Reason = $"Device class 0x{clsHex} ({critName}) is blocked at Critical threat level";
                    _logger.LogAttack(2, "ClassBlock", result.Reason, vidPid);
                }
                else if (HighThreatClasses.Contains(clsHex) && BlockedClasses.TryGetValue(cls, out string? highName))
                {
                    result.ShouldBlock = true;
                    result.ThreatLevel = ThreatLevel.High;
                    result.Reason = $"Device class 0x{clsHex} ({highName}) is blocked at High threat level";
                    _logger.LogCritical(2, "ClassBlock", result.Reason, vidPid);
                }
                else if (cls == 0x03)
                {
                    // HID: flag but don't auto-block
                    result.ShouldBlock = false;
                    result.ThreatLevel = ThreatLevel.Medium;
                    result.Reason = "HID device detected — not auto-blocked but flagged for monitoring";
                    _logger.LogWarning(2, "ClassBlock", $"HID device {vidPid} flagged for monitoring", vidPid);
                }
                else
                {
                    result.ShouldBlock = false;
                    result.ThreatLevel = ThreatLevel.None;
                    result.Reason = "Device class is not in blocked list";
                    _logger.LogInfo(2, "ClassBlock", $"Device {vidPid} class 0x{clsHex} — allowed", vidPid);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[DeviceClassBlocker] Exception: {ex.Message}");
                result.Reason = $"Evaluation exception: {ex.Message}";
            }

            return result;
        }
    }
}
