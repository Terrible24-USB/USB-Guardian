// DesktopIsolation.cs — DISABLED
// Desktop switching was removed because SwitchDesktop() affects the entire
// display session, causing a black screen in normal desktop environments.
// Protection is provided by PnpDeviceGuard (CM_Disable_DevNode) instead.
namespace USBGuardian
{
    internal sealed class DesktopIsolation : System.IDisposable
    {
        public bool IsActive => false;
        public bool Enter() => false; // no-op
        public void Exit() { }       // no-op
        public void Dispose() { }       // no-op
    }
}