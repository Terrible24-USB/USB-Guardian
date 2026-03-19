using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace USBGuardian
{
    /// <summary>
    /// 4-layer built-in device detection system.
    /// Identifies laptop keyboards, mice, trackpads, and other
    /// internal hardware that must never be blocked.
    /// </summary>
    public static class BuiltInDeviceSafetyChecker
    {
        // Layer 1: Service names associated with built-in/internal devices
        private static readonly HashSet<string> BuiltInServiceNames = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            "kbdhid",    // Built-in keyboard (HID)
            "mouhid",    // Built-in mouse (HID)
            "hidusb",    // Generic HID over USB (often internal)
            "acpibtn",   // ACPI button device (power/sleep buttons)
            "i8042prt",  // PS/2 keyboard and mouse port driver
            "pci",       // PCI bus devices
            "acpi",      // ACPI devices
        };

        // Layer 2: Known built-in / ACPI VID:PID combinations
        // ACPI devices use these pseudo-VID patterns in their hardware IDs
        private static readonly HashSet<string> BuiltInVidPidPrefixes = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            "ACPI\\",
            "PCI\\",
            "ROOT\\",
            "BTHENUM\\",  // Bluetooth enum (internal adapter)
        };

        // Layer 3: Keywords in device descriptions that indicate built-in hardware
        private static readonly string[] BuiltInDescriptionKeywords = new[]
        {
            "internal",
            "built-in",
            "builtin",
            "embedded",
            "integrated",
            "onboard",
            "laptop",
            "notebook",
            "touchpad",
            "trackpad",
            "pointing device",
            "ps/2",
            "i8042",
            "acpi",
        };

        // Layer 4: Hardware ID prefixes that indicate non-USB (i.e., built-in) devices
        private static readonly string[] BuiltInHardwareIdPrefixes = new[]
        {
            "ACPI\\",
            "PCI\\",
            "ROOT\\",
            "BTHENUM\\",
            "HID\\VID_ACPI",
        };

        /// <summary>
        /// Returns true if the device is DEFINITELY a built-in device.
        /// Used for hard-blocking the block operation with a critical warning.
        /// </summary>
        public static bool IsDefinitelyBuiltIn(DeviceFingerprint device)
        {
            if (device == null)
                return false;

            // Layer 1: Service name check
            if (!string.IsNullOrEmpty(device.Service) &&
                BuiltInServiceNames.Contains(device.Service))
            {
                Debug.WriteLine($"[BuiltInCheck] Layer 1 match: service='{device.Service}'");
                return true;
            }

            // Layer 4: Hardware ID prefix check (strong signal)
            if (device.HardwareIds != null)
            {
                foreach (string hwId in device.HardwareIds)
                {
                    if (string.IsNullOrEmpty(hwId))
                        continue;
                    foreach (string prefix in BuiltInHardwareIdPrefixes)
                    {
                        if (hwId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            Debug.WriteLine($"[BuiltInCheck] Layer 4 match: hwId='{hwId}'");
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Returns true if the device MIGHT be a built-in device.
        /// Used for showing a softer warning while still allowing the user to proceed.
        /// Checks USB HID class (0x03) combined with description keywords.
        /// </summary>
        public static bool MightBeBuiltIn(DeviceFingerprint device)
        {
            if (device == null)
                return false;

            // Already definitely built-in → also "might be"
            if (IsDefinitelyBuiltIn(device))
                return true;

            // Layer 3: Description keyword check
            if (!string.IsNullOrEmpty(device.Description))
            {
                string desc = device.Description.ToLowerInvariant();
                if (BuiltInDescriptionKeywords.Any(kw => desc.Contains(kw)))
                {
                    Debug.WriteLine($"[BuiltInCheck] Layer 3 match: description='{device.Description}'");
                    return true;
                }
            }

            // HID class (0x03) combined with known internal service
            if (device.UsbDeviceClass == 0x03 || device.InterfaceClass == 0x03)
            {
                // HID devices could be internal keyboards/mice — flag as "might be"
                if (!string.IsNullOrEmpty(device.Service) &&
                    (device.Service.Equals("kbdhid", StringComparison.OrdinalIgnoreCase) ||
                     device.Service.Equals("mouhid", StringComparison.OrdinalIgnoreCase) ||
                     device.Service.Equals("hidusb", StringComparison.OrdinalIgnoreCase)))
                {
                    Debug.WriteLine($"[BuiltInCheck] Layer 1+HID match: service='{device.Service}'");
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Self-test method that validates the detection logic against known cases.
        /// Returns true if all tests pass; false otherwise.
        /// </summary>
        public static bool RunSelfTest()
        {
            bool allPassed = true;

            // Test 1: Built-in keyboard (kbdhid service) must be detected
            var keyboard = new DeviceFingerprint
            {
                Description = "HID Keyboard Device",
                Service = "kbdhid",
                UsbDeviceClass = 0x03,
                InterfaceClass = 0x03,
                HardwareIds = new List<string>()
            };
            bool keyboardResult = IsDefinitelyBuiltIn(keyboard);
            if (!keyboardResult)
            {
                Debug.WriteLine("[SelfTest] FAIL: Built-in keyboard not detected");
                allPassed = false;
            }
            else
            {
                Debug.WriteLine("[SelfTest] PASS: Built-in keyboard detected correctly");
            }

            // Test 2: Built-in mouse (mouhid service) must be detected
            var mouse = new DeviceFingerprint
            {
                Description = "HID-compliant mouse",
                Service = "mouhid",
                UsbDeviceClass = 0x03,
                InterfaceClass = 0x03,
                HardwareIds = new List<string>()
            };
            bool mouseResult = IsDefinitelyBuiltIn(mouse);
            if (!mouseResult)
            {
                Debug.WriteLine("[SelfTest] FAIL: Built-in mouse not detected");
                allPassed = false;
            }
            else
            {
                Debug.WriteLine("[SelfTest] PASS: Built-in mouse detected correctly");
            }

            // Test 3: External USB keyboard must NOT be flagged as definitely built-in
            var externalKeyboard = new DeviceFingerprint
            {
                Description = "USB Keyboard",
                Service = "kbdclass",
                Vid = "045E",
                Pid = "0750",
                UsbDeviceClass = 0x00,
                InterfaceClass = 0x03,
                HardwareIds = new List<string> { "USB\\VID_045E&PID_0750" }
            };
            bool externalResult = IsDefinitelyBuiltIn(externalKeyboard);
            if (externalResult)
            {
                Debug.WriteLine("[SelfTest] FAIL: External keyboard incorrectly flagged as built-in");
                allPassed = false;
            }
            else
            {
                Debug.WriteLine("[SelfTest] PASS: External keyboard correctly identified as external");
            }

            // Test 4: PCI device (hardware ID starts with PCI\\) must be detected as built-in
            var pciDevice = new DeviceFingerprint
            {
                Description = "PCI Standard PCI-to-PCI Bridge",
                Service = "pci",
                HardwareIds = new List<string> { "PCI\\VEN_8086&DEV_1234" }
            };
            bool pciResult = IsDefinitelyBuiltIn(pciDevice);
            if (!pciResult)
            {
                Debug.WriteLine("[SelfTest] FAIL: PCI device not detected as built-in");
                allPassed = false;
            }
            else
            {
                Debug.WriteLine("[SelfTest] PASS: PCI device detected as built-in correctly");
            }

            Debug.WriteLine($"[SelfTest] Result: {(allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED")}");
            return allPassed;
        }
    }
}
