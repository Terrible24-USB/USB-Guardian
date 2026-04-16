using System;

namespace USBGuardian
{
    public class DeviceClassHardeningResult
    {
        public bool ShouldBlock { get; set; }
        public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;
        public string Reason { get; set; } = string.Empty;

        public ClassBlockResult ToClassBlockResult() => new()
        {
            ShouldBlock = ShouldBlock,
            ThreatLevel = ThreatLevel,
            Reason = Reason
        };
    }

    public class DeviceClassHardener
    {
        private readonly SecurityEventLogger _logger;
        private readonly DeviceClassBlocker _legacyBlocker;
        private readonly DeviceWhitelistManager _whitelistManager;

        public DeviceClassHardener(SecurityEventLogger logger, DeviceWhitelistManager whitelistManager)
        {
            _logger = logger;
            _whitelistManager = whitelistManager;
            _legacyBlocker = new DeviceClassBlocker(logger);
        }

        public DeviceClassHardeningResult Evaluate(DeviceFingerprint fingerprint)
        {
            string vidPid = $"{fingerprint.Vid}:{fingerprint.Pid}";

            if (_whitelistManager.IsWhitelisted(fingerprint))
            {
                _logger.LogInfo(2, "ClassHardening", $"Whitelisted device allowed: {vidPid}", vidPid);
                return new DeviceClassHardeningResult
                {
                    ShouldBlock = false,
                    ThreatLevel = ThreatLevel.None,
                    Reason = "Device is whitelisted"
                };
            }

            bool hasHid = fingerprint.UsbDeviceClass == 0x03 || fingerprint.InterfaceClass == 0x03;
            bool hasStorage = fingerprint.UsbDeviceClass == 0x08 || fingerprint.InterfaceClass == 0x08;

            if (fingerprint.AllInterfaces != null)
            {
                foreach (var iface in fingerprint.AllInterfaces)
                {
                    if (iface.InterfaceClass == 0x03) hasHid = true;
                    if (iface.InterfaceClass == 0x08) hasStorage = true;
                }
            }

            if (hasHid && hasStorage)
            {
                return new DeviceClassHardeningResult
                {
                    ShouldBlock = true,
                    ThreatLevel = ThreatLevel.Critical,
                    Reason = "Composite HID + Storage device blocked"
                };
            }

            if (hasHid)
            {
                return new DeviceClassHardeningResult
                {
                    ShouldBlock = true,
                    ThreatLevel = ThreatLevel.High,
                    Reason = "Default-deny policy: new HID device is not whitelisted"
                };
            }

            if (fingerprint.UsbDeviceClass == 0xFF)
            {
                return new DeviceClassHardeningResult
                {
                    ShouldBlock = true,
                    ThreatLevel = ThreatLevel.Critical,
                    Reason = "Vendor-specific class blocked unless whitelisted"
                };
            }

            var legacy = _legacyBlocker.EvaluateDevice(fingerprint);
            return new DeviceClassHardeningResult
            {
                ShouldBlock = legacy.ShouldBlock,
                ThreatLevel = legacy.ThreatLevel,
                Reason = legacy.Reason
            };
        }
    }
}
