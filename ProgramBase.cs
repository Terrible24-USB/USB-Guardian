using System;

namespace USBGuardian
{
    internal static class ProgramBase
    {
        private static readonly object InitLock = new();
        private static bool _initialized;

        public static void EnsureStartupSecurity(SecurityEventLogger? logger = null, bool includePreBoot = true)
        {
            lock (InitLock)
            {
                if (_initialized) return;

                try
                {
                    BootRecoveryManager.ApplyEmergencyRecoveryIfRequested(logger);
                }
                catch (Exception ex)
                {
                    logger?.LogWarning(0, "BootRecovery", $"Emergency recovery check failed: {ex.Message}");
                }

                if (includePreBoot)
                    PreBootSecurityManager.InitializePreBootBlocking(logger);
                _initialized = true;
            }
        }
    }
}
