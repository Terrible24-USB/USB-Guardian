using System;

namespace USBGuardian
{
    public sealed class DeviceWhitelist
    {
        private readonly DeviceWhitelistManager _manager;

        public DeviceWhitelist(DeviceWhitelistManager? manager = null)
        {
            _manager = manager ?? new DeviceWhitelistManager();
        }

        public bool IsTrusted(DeviceFingerprint fingerprint)
        {
            if (fingerprint == null) return false;
            return _manager.IsWhitelisted(fingerprint);
        }

        public void Trust(DeviceFingerprint fingerprint, string approvedBy = "admin", TimeSpan? duration = null)
        {
            if (fingerprint == null) return;
            _manager.Approve(fingerprint, approvedBy, duration);
        }

        public int CountTrustedEntries() => _manager.EntryCount;
    }
}
