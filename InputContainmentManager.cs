using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace USBGuardian
{
    /// <summary>
    /// Manages input containment during a USB device decision prompt.
    /// Uses low-level keyboard/mouse hooks to whitelist only the keys
    /// needed for the decision dialog (A/W/B/I/Enter/Esc/Tab).
    /// The primary protection against Rubber Ducky is PnpDeviceGuard
    /// (CM_Disable_DevNode at ~10-30ms), which freezes the device before
    /// it can send any HID reports. These hooks are a lightweight backstop.
    /// </summary>
    internal sealed class InputContainmentManager : IDisposable
    {
        private static readonly System.Windows.Forms.Keys[] AllowedKeys =
        {
            System.Windows.Forms.Keys.A,
            System.Windows.Forms.Keys.W,
            System.Windows.Forms.Keys.B,
            System.Windows.Forms.Keys.I,
            System.Windows.Forms.Keys.Return,
            System.Windows.Forms.Keys.Escape,
            System.Windows.Forms.Keys.Tab,
        };

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int HC_ACTION = 0;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        private readonly SecurityEventLogger _logger;
        private readonly object _stateLock = new();

        private IntPtr _keyboardHook = IntPtr.Zero;
        private IntPtr _mouseHook = IntPtr.Zero;
        private LowLevelKeyboardProc? _keyboardProc;
        private LowLevelMouseProc? _mouseProc;
        private IntPtr _trustedHwnd = IntPtr.Zero;
        private int _activeFlag;
        private bool _disposed;

        public bool IsActive => Volatile.Read(ref _activeFlag) == 1;

        public InputContainmentManager(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public void InitializeHooks()
        {
            lock (_stateLock)
            {
                ThrowIfDisposed();
                if (_keyboardHook != IntPtr.Zero) return;

                _keyboardProc = KeyboardHookCallback;
                _mouseProc = MouseHookCallback;

                _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, GetModuleHandle(null), 0);
                _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, GetModuleHandle(null), 0);

                if (_keyboardHook == IntPtr.Zero || _mouseHook == IntPtr.Zero)
                    _logger.LogWarning(0, "InputContainment",
                        $"Low-level hook install failed (Win32={Marshal.GetLastWin32Error()}).");
                else
                    _logger.LogInfo(0, "InputContainment", "Low-level hooks installed.");
            }
        }

        public void Activate(string reason)
        {
            Volatile.Write(ref _activeFlag, 1);
            _logger.LogInfo(0, "InputContainment", $"Activated: {reason}");
        }

        public void Deactivate(string reason)
        {
            Volatile.Write(ref _activeFlag, 0);
            lock (_stateLock) _trustedHwnd = IntPtr.Zero;
            _logger.LogInfo(0, "InputContainment", $"Deactivated: {reason}");
        }

        // ── TrustedWindowScope ───────────────────────────────────────────────────────

        public TrustedWindowScope BeginTrustedWindowScope(IntPtr hwnd)
            => new TrustedWindowScope(this, hwnd);

        internal sealed class TrustedWindowScope : IDisposable
        {
            private readonly InputContainmentManager _owner;
            private readonly IntPtr _hwnd;
            private bool _disposed;

            internal TrustedWindowScope(InputContainmentManager owner, IntPtr hwnd)
            {
                _owner = owner;
                _hwnd = hwnd;
                lock (owner._stateLock) owner._trustedHwnd = hwnd;
            }

            public void Dispose()
            {
                if (_disposed) return;
                _disposed = true;
                lock (_owner._stateLock)
                    if (_owner._trustedHwnd == _hwnd)
                        _owner._trustedHwnd = IntPtr.Zero;
            }
        }

        internal readonly struct ContainmentScope : IDisposable
        {
            private readonly InputContainmentManager? _owner;
            private readonly string _reason;
            public ContainmentScope(InputContainmentManager owner, string reason)
            { _owner = owner; _reason = reason; }
            public void Dispose() => _owner?.Deactivate(_reason);
        }

        // ── hook callbacks ───────────────────────────────────────────────────────────

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

            // Always allow input to our own trusted window.
            IntPtr fg = GetForegroundWindow();
            if (fg != IntPtr.Zero && (fg == _trustedHwnd || IsOwnedByCurrentProcess(fg)))
                return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

            // Whitelist: only let through keys needed for the decision dialog.
            int msg = wParam.ToInt32();
            if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
            {
                int vk = Marshal.ReadInt32(lParam);
                foreach (var k in AllowedKeys)
                    if (vk == (int)k)
                        return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);
            }

            return (IntPtr)1; // block
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            IntPtr fg = GetForegroundWindow();
            if (fg != IntPtr.Zero && (fg == _trustedHwnd || IsOwnedByCurrentProcess(fg)))
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            return (IntPtr)1; // block
        }

        private static bool IsOwnedByCurrentProcess(IntPtr hwnd)
        {
            GetWindowThreadProcessId(hwnd, out uint pid);
            return pid == (uint)Environment.ProcessId;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(InputContainmentManager));
        }

        public void Dispose()
        {
            if (_disposed) return;
            lock (_stateLock)
            {
                if (_disposed) return;
                _disposed = true;
                Volatile.Write(ref _activeFlag, 0);
                if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; }
                if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; }
            }
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);
    }
}