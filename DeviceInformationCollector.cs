using System;
using System.Security.Cryptography;
using System.Text;

namespace USBGuardian
{
    public sealed class DeviceInformationSnapshot
    {
        public string VidPid { get; set; } = "UNKNOWN:UNKNOWN";
        public string? SerialNumber { get; set; }
        public string Manufacturer { get; set; } = "Unknown";
        public string ProductName { get; set; } = "Unknown";
        public string DeviceClass { get; set; } = "Unknown";
        public byte DeviceSubClass { get; set; }
        public int InterfaceCount { get; set; }
        public string DescriptorHash { get; set; } = string.Empty;
        public DateTime InsertionTimestampUtc { get; set; } = DateTime.UtcNow;
        public string PortInformation { get; set; } = "Unavailable";
    }

    public sealed class DeviceInformationCollector
    {
        public DeviceInformationSnapshot Collect(DeviceFingerprint fingerprint)
        {
            if (fingerprint == null) throw new ArgumentNullException(nameof(fingerprint));

            string vid = string.IsNullOrWhiteSpace(fingerprint.Vid) ? "UNKNOWN" : fingerprint.Vid;
            string pid = string.IsNullOrWhiteSpace(fingerprint.Pid) ? "UNKNOWN" : fingerprint.Pid;
            int interfaceCount = fingerprint.InterfaceCount > 0
                ? fingerprint.InterfaceCount
                : (fingerprint.NumInterfaces > 0 ? fingerprint.NumInterfaces : fingerprint.AllInterfaces?.Count ?? 0);

            return new DeviceInformationSnapshot
            {
                VidPid = $"{vid}:{pid}",
                SerialNumber = string.IsNullOrWhiteSpace(fingerprint.SerialNumber) ? null : fingerprint.SerialNumber,
                Manufacturer = string.IsNullOrWhiteSpace(fingerprint.Manufacturer) ? "Unknown" : fingerprint.Manufacturer,
                ProductName = string.IsNullOrWhiteSpace(fingerprint.Description) ? "Unknown" : fingerprint.Description,
                DeviceClass = string.IsNullOrWhiteSpace(fingerprint.DeviceClass)
                    ? (fingerprint.UsbDeviceClass == 0x08 ? "Mass Storage" : "Unknown")
                    : fingerprint.DeviceClass,
                DeviceSubClass = fingerprint.UsbDeviceSubClass,
                InterfaceCount = interfaceCount,
                DescriptorHash = BuildDescriptorHash(fingerprint),
                InsertionTimestampUtc = fingerprint.CaptureTime != DateTime.MinValue
                    ? fingerprint.CaptureTime.ToUniversalTime()
                    : DateTime.UtcNow,
                PortInformation = !string.IsNullOrWhiteSpace(fingerprint.LocationInfo)
                    ? fingerprint.LocationInfo
                    : (!string.IsNullOrWhiteSpace(fingerprint.Address) ? fingerprint.Address : "Unavailable")
            };
        }

        private static string BuildDescriptorHash(DeviceFingerprint fingerprint)
        {
            if (!string.IsNullOrWhiteSpace(fingerprint.DescriptorHash))
                return fingerprint.DescriptorHash;

            string payload = string.Join("|",
                fingerprint.Vid ?? string.Empty,
                fingerprint.Pid ?? string.Empty,
                fingerprint.BcdUSB.ToString("X4"),
                fingerprint.BcdDevice.ToString("X4"),
                fingerprint.NumConfigurations,
                fingerprint.NumInterfaces,
                fingerprint.InterfaceClass,
                fingerprint.InterfaceSubClass,
                fingerprint.InterfaceProtocol);

            using SHA256 sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(payload)));
        }
    }
}
