using System;
using System.Collections.Generic;
using System.Linq;

namespace USBGuardian
{
    /// <summary>
    /// Identifies USB HID device types and detects suspicious interface combinations.
    /// </summary>
    public static class HIDClassifier
    {
        // USB Interface Class codes
        public const byte CLASS_AUDIO = 0x01;
        public const byte CLASS_CDC = 0x02;
        public const byte CLASS_HID = 0x03;
        public const byte CLASS_PHYSICAL = 0x05;
        public const byte CLASS_IMAGE = 0x06;
        public const byte CLASS_PRINTER = 0x07;
        public const byte CLASS_MASS_STORAGE = 0x08;
        public const byte CLASS_HUB = 0x09;
        public const byte CLASS_CDC_DATA = 0x0A;
        public const byte CLASS_SMART_CARD = 0x0B;
        public const byte CLASS_VIDEO = 0x0E;
        public const byte CLASS_AUDIO_VIDEO = 0x10;
        public const byte CLASS_DIAGNOSTIC = 0xDC;
        public const byte CLASS_WIRELESS = 0xE0;
        public const byte CLASS_VENDOR_SPECIFIC = 0xFF;

        // HID Boot Protocol sub-type codes (bInterfaceProtocol when bInterfaceSubClass = 1)
        public const byte HID_PROTO_NONE = 0x00;
        public const byte HID_PROTO_KEYBOARD = 0x01;
        public const byte HID_PROTO_MOUSE = 0x02;

        // Audio SubClass codes
        public const byte AUDIO_SUBCLASS_CONTROL = 0x01;
        public const byte AUDIO_SUBCLASS_STREAMING = 0x02;
        public const byte AUDIO_SUBCLASS_MIDI = 0x03;

        // Mass Storage SubClass codes
        public const byte MSC_SUBCLASS_SCSI = 0x06;

        // Mass Storage Protocol codes
        public const byte MSC_PROTO_BULK_ONLY = 0x50;

        // Video SubClass codes
        public const byte VIDEO_SUBCLASS_CONTROL = 0x01;
        public const byte VIDEO_SUBCLASS_STREAMING = 0x02;

        /// <summary>
        /// Represents a single USB interface with its class descriptors.
        /// </summary>
        public class InterfaceInfo
        {
            public byte InterfaceClass { get; set; }
            public byte InterfaceSubClass { get; set; }
            public byte InterfaceProtocol { get; set; }
        }

        /// <summary>
        /// Classifies a single USB interface and returns an emoji + label string.
        /// Returns null for unknown/uninteresting class codes.
        /// </summary>
        public static string? ClassifyInterface(byte cls, byte sub, byte proto)
        {
            switch (cls)
            {
                case CLASS_HID:
                    // Boot-protocol devices explicitly identify themselves
                    if (sub == 0x01)
                    {
                        if (proto == HID_PROTO_KEYBOARD) return "⌨️ Keyboard";
                        if (proto == HID_PROTO_MOUSE)    return "🖱️ Mouse";
                    }
                    // Generic HID — best-effort by protocol field alone
                    if (proto == HID_PROTO_KEYBOARD) return "⌨️ Keyboard";
                    if (proto == HID_PROTO_MOUSE)    return "🖱️ Mouse";
                    return "🕹️ HID Device";

                case CLASS_MASS_STORAGE:
                    return "💾 Storage Device";

                case CLASS_PRINTER:
                    return "🖨️ Printer";

                case CLASS_IMAGE:
                    return "📷 Scanner/Camera";

                case CLASS_AUDIO:
                    switch (sub)
                    {
                        case AUDIO_SUBCLASS_CONTROL:   return "🎵 Audio Device";
                        case AUDIO_SUBCLASS_STREAMING: return "🎤 Microphone/Headset";
                        case AUDIO_SUBCLASS_MIDI:      return "🎹 MIDI Device";
                        default:                       return "🔊 Audio Device";
                    }

                case CLASS_VIDEO:
                    switch (sub)
                    {
                        case VIDEO_SUBCLASS_CONTROL:   return "📹 Webcam/Monitor";
                        case VIDEO_SUBCLASS_STREAMING: return "📹 Webcam/Monitor";
                        default:                       return "📹 Video Device";
                    }

                case CLASS_WIRELESS:
                    return "📡 Wireless Adapter";

                case CLASS_HUB:
                    return "🔌 USB Hub";

                case CLASS_SMART_CARD:
                    return "💳 Smart Card Reader";

                case CLASS_PHYSICAL:
                    return "🕹️ Physical Interface";

                case CLASS_VENDOR_SPECIFIC:
                    return "⚙️ Vendor Specific";

                default:
                    return null;
            }
        }

        /// <summary>
        /// Detects the distinct device types present across all reported interfaces.
        /// Returns a deduplicated list of type labels.
        /// </summary>
        public static List<string> DetectDeviceTypes(List<InterfaceInfo> interfaces)
        {
            if (interfaces == null || interfaces.Count == 0)
                return new List<string>();

            var seen  = new HashSet<string>();
            var types = new List<string>();
            foreach (var iface in interfaces)
            {
                string? label = ClassifyInterface(iface.InterfaceClass, iface.InterfaceSubClass, iface.InterfaceProtocol);
                if (label != null && seen.Add(label))
                    types.Add(label);
            }
            return types;
        }

        /// <summary>
        /// Detects suspicious interface combinations and returns security warnings.
        /// Each returned tuple is (severity, message) where severity is "CRITICAL", "WARNING", or "INFO".
        /// </summary>
        public static List<(string Severity, string Message)> DetectSuspiciousCombinations(List<InterfaceInfo> interfaces)
        {
            var warnings = new List<(string, string)>();
            if (interfaces == null || interfaces.Count == 0)
                return warnings;

            bool hasStorage  = interfaces.Any(i => i.InterfaceClass == CLASS_MASS_STORAGE);
            bool hasHid      = interfaces.Any(i => i.InterfaceClass == CLASS_HID);
            bool hasKeyboard = interfaces.Any(i => i.InterfaceClass == CLASS_HID &&
                                                    (i.InterfaceProtocol == HID_PROTO_KEYBOARD ||
                                                     (i.InterfaceSubClass == 0x01 && i.InterfaceProtocol == HID_PROTO_KEYBOARD)));
            bool hasMouse    = interfaces.Any(i => i.InterfaceClass == CLASS_HID &&
                                                    (i.InterfaceProtocol == HID_PROTO_MOUSE ||
                                                     (i.InterfaceSubClass == 0x01 && i.InterfaceProtocol == HID_PROTO_MOUSE)));
            bool hasAudio    = interfaces.Any(i => i.InterfaceClass == CLASS_AUDIO &&
                                                    i.InterfaceSubClass == AUDIO_SUBCLASS_STREAMING);
            bool hasVideo    = interfaces.Any(i => i.InterfaceClass == CLASS_VIDEO);
            bool hasPrinter  = interfaces.Any(i => i.InterfaceClass == CLASS_PRINTER);
            int  hidCount    = interfaces.Count(i => i.InterfaceClass == CLASS_HID);

            if (hasStorage && hasKeyboard)
            {
                warnings.Add(("CRITICAL",
                    "Storage device with keyboard input detected!\n" +
                    "   → Potential data exfiltration or BadUSB attack"));
            }
            else if (hasStorage && hasHid)
            {
                warnings.Add(("CRITICAL",
                    "Storage device with input device detected!\n" +
                    "   → Potential data exfiltration attack"));
            }

            if (hasAudio && hasKeyboard)
            {
                warnings.Add(("CRITICAL",
                    "Microphone/audio with keyboard detected!\n" +
                    "   → Potential keystroke surveillance device"));
            }

            if (hasPrinter && hasAudio)
            {
                warnings.Add(("WARNING",
                    "Printer with audio interface detected!\n" +
                    "   → Multi-sensor combination is unusual"));
            }

            if (hasVideo && (hasHid || hasStorage))
            {
                warnings.Add(("WARNING",
                    "Video interface combined with input or storage detected!\n" +
                    "   → Potential surveillance device"));
            }

            if (hidCount > 2)
            {
                warnings.Add(("WARNING",
                    $"Unusually high number of HID interfaces ({hidCount})!\n" +
                    "   → May indicate a composite attack device"));
            }

            return warnings;
        }

        /// <summary>
        /// Returns a human-readable name for a USB interface class code.
        /// </summary>
        public static string GetClassName(byte cls)
        {
            switch (cls)
            {
                case 0x00: return "Device Class (per-interface)";
                case CLASS_AUDIO: return "Audio Class";
                case CLASS_CDC: return "Communications Class";
                case CLASS_HID: return "HID Class";
                case CLASS_PHYSICAL: return "Physical Interface Class";
                case CLASS_IMAGE: return "Image Class";
                case CLASS_PRINTER: return "Printer Class";
                case CLASS_MASS_STORAGE: return "Mass Storage Class";
                case CLASS_HUB: return "Hub Class";
                case CLASS_CDC_DATA: return "CDC-Data Class";
                case CLASS_SMART_CARD: return "Smart Card Class";
                case CLASS_VIDEO: return "Video Class";
                case CLASS_AUDIO_VIDEO: return "Audio/Video Class";
                case CLASS_DIAGNOSTIC: return "Diagnostic Class";
                case CLASS_WIRELESS: return "Wireless Controller Class";
                case CLASS_VENDOR_SPECIFIC: return "Vendor Specific Class";
                default: return $"Unknown (0x{cls:X2})";
            }
        }

        /// <summary>
        /// Returns a human-readable name for a USB interface subclass, given the parent class.
        /// </summary>
        public static string GetSubClassName(byte cls, byte sub)
        {
            switch (cls)
            {
                case CLASS_AUDIO:
                    switch (sub)
                    {
                        case AUDIO_SUBCLASS_CONTROL:   return "Audio Control";
                        case AUDIO_SUBCLASS_STREAMING: return "Audio Streaming";
                        case AUDIO_SUBCLASS_MIDI:      return "MIDI Streaming";
                        default:                       return $"0x{sub:X2}";
                    }
                case CLASS_HID:
                    switch (sub)
                    {
                        case 0x00: return "No Subclass";
                        case 0x01: return "Boot Interface";
                        default:   return $"0x{sub:X2}";
                    }
                case CLASS_MASS_STORAGE:
                    switch (sub)
                    {
                        case 0x01: return "RBC";
                        case 0x02: return "SFF-8020i/MMC-2 (ATAPI)";
                        case 0x03: return "QIC-157 (tape)";
                        case 0x04: return "UFI (floppy)";
                        case 0x05: return "SFF-8070i";
                        case 0x06: return "SCSI Transparent";
                        default:   return $"0x{sub:X2}";
                    }
                case CLASS_VIDEO:
                    switch (sub)
                    {
                        case VIDEO_SUBCLASS_CONTROL:   return "Video Control";
                        case VIDEO_SUBCLASS_STREAMING: return "Video Streaming";
                        case 0x03:                     return "Video Interface Collection";
                        default:                       return $"0x{sub:X2}";
                    }
                default:
                    return $"0x{sub:X2}";
            }
        }

        /// <summary>
        /// Returns a human-readable name for a USB interface protocol, given the parent class.
        /// </summary>
        public static string GetProtocolName(byte cls, byte sub, byte proto)
        {
            switch (cls)
            {
                case CLASS_HID:
                    switch (proto)
                    {
                        case HID_PROTO_NONE:     return "None";
                        case HID_PROTO_KEYBOARD: return "Keyboard";
                        case HID_PROTO_MOUSE:    return "Mouse";
                        default:                 return $"0x{proto:X2}";
                    }
                case CLASS_MASS_STORAGE:
                    switch (proto)
                    {
                        case 0x00: return "CBI (with completion interrupt)";
                        case 0x01: return "CBI (no completion interrupt)";
                        case 0x50: return "Bulk-Only Transport";
                        default:   return $"0x{proto:X2}";
                    }
                default:
                    return $"0x{proto:X2}";
            }
        }
    }
}
