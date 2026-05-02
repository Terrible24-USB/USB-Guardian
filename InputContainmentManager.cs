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
            // Arrow keys for accessibility — navigate dialog buttons
            System.Windows.Forms.Keys.Up,
            System.Windows.Forms.Keys.Down,
            System.Windows.Forms.Keys.Left,
            System.Windows.Forms.Keys.Right,
        };

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int HC_ACTION = 0;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int LLKHF_ALTDOWN = 0x20;
        private const int VK_LWIN = 0x5B;
        private const int VK_RWIN = 0x5C;
        private const int VK_ESCAPE = 0x1B;
        private const int VK_TAB = 0x09;
        private const int VK_F4 = 0x73;

        private readonly SecurityEventLogger _logger;
        private readonly object _stateLock = new();

        private IntPtr _keyboardHook = IntPtr.Zero;
        private IntPtr _mouseHook = IntPtr.Zero;
        private LowLevelKeyboardProc? _keyboardProc;
        private LowLevelMouseProc? _mouseProc;
        private IntPtr _trustedHwnd = IntPtr.Zero;
        private int _activeFlag;
        private bool _hooksInstalled;
        private bool _disposed;
        // Ticks until which the 2-second aggressive lockdown is active (allows only Enter/Esc).
        private long _aggressiveLockdownUntilTicks;

        public bool IsActive => Volatile.Read(ref _activeFlag) == 1;

        public InputContainmentManager(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public void Activate(string reason)
        {
            EnsureHooksInstalled();
            if (!_hooksInstalled)
            {
                _logger.LogWarning(0, "InputContainment", $"Activation skipped because hooks are not installed: {reason}");
                return;
            }

            FlushPendingInputState();
            // Start 2-second aggressive lockdown: only Enter/Esc pass through during
            // this window to stop any buffered Ducky keystrokes from reaching the dialog.
            Interlocked.Exchange(ref _aggressiveLockdownUntilTicks,
                DateTime.UtcNow.AddSeconds(2).Ticks);
            Volatile.Write(ref _activeFlag, 1);
            _logger.LogInfo(0, "InputContainment", $"Activated (2s aggressive lockdown): {reason}");
        }

        public void Deactivate(string reason)
        {
            Volatile.Write(ref _activeFlag, 0);
            Interlocked.Exchange(ref _aggressiveLockdownUntilTicks, 0);
            lock (_stateLock) _trustedHwnd = IntPtr.Zero;
            ReleaseHooks();
            _logger.LogInfo(0, "InputContainment", $"Deactivated: {reason}");
        }

        private void EnsureHooksInstalled()
        {
            lock (_stateLock)
            {
                ThrowIfDisposed();
                if (_hooksInstalled) return;

                _keyboardProc = KeyboardHookCallback;
                _mouseProc = MouseHookCallback;

                _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, GetModuleHandle(null), 0);
                _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, GetModuleHandle(null), 0);

                if (_keyboardHook == IntPtr.Zero || _mouseHook == IntPtr.Zero)
                {
                    _logger.LogWarning(0, "InputContainment",
                        $"Low-level hook install failed (Win32={Marshal.GetLastWin32Error()}).");
                    if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; }
                    if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; }
                    _hooksInstalled = false;
                    return;
                }

                _hooksInstalled = true;
                _logger.LogInfo(0, "InputContainment", "Low-level hooks installed.");
            }
        }

        private void ReleaseHooks()
        {
            lock (_stateLock)
            {
                if (!_hooksInstalled || _activeFlag == 1) return;

                if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; }
                if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; }
                _hooksInstalled = false;
                _logger.LogInfo(0, "InputContainment", "Low-level hooks removed.");
            }
        }

        private void FlushPendingInputState()
        {
            var releases = new[] { 0x5B, 0x5C, 0x11, 0x12, 0x10, 0x1B };
            INPUT[] inputs = new INPUT[releases.Length];
            for (int i = 0; i < releases.Length; i++)
            {
                inputs[i] = new INPUT
                {
                    type = 1,
                    U = new INPUTUNION
                    {
                        ki = new KEYBDINPUT
                        {
                            wVk = (ushort)releases[i],
                            dwFlags = 0x0002
                        }
                    }
                };
            }

            _ = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
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


        // ── hook callbacks ───────────────────────────────────────────────────────────

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

            var keyInfo = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);

            // Always block dangerous system combos (Win, Alt+Tab, Ctrl+Esc, etc.)
            // regardless of which window is focused — these open execution paths.
            if (IsDangerousCombo(keyInfo))
                return (IntPtr)1;

            // During the 2-second aggressive lockdown window, allow only Enter/Esc
            // to stop buffered Ducky keystrokes from reaching the dialog.
            long lockdownTicks = Volatile.Read(ref _aggressiveLockdownUntilTicks);
            if (lockdownTicks != 0 && DateTime.UtcNow.Ticks < lockdownTicks)
            {
                int vkLock = unchecked((int)keyInfo.vkCode);
                if (vkLock != 0x0D && vkLock != 0x1B) // VK_RETURN, VK_ESCAPE
                    return (IntPtr)1;
            }

            // If our trusted decision window is focused, allow only whitelisted keys.
            IntPtr fg = GetForegroundWindow();
            if (IsTrustedContextWindow(fg))
            {
                int vk = unchecked((int)keyInfo.vkCode);
                foreach (var k in AllowedKeys)
                    if (vk == (int)k)
                        return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

                return (IntPtr)1;
            }

            return (IntPtr)1;
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            IntPtr fg = GetForegroundWindow();
            if (IsTrustedContextWindow(fg))
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            var mouse = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
            IntPtr underCursor = WindowFromPoint(mouse.pt);
            if (IsTrustedContextWindow(underCursor))
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            return (IntPtr)1;
        }

        private static bool IsDangerousCombo(KBDLLHOOKSTRUCT keyInfo)
        {
            int vk = unchecked((int)keyInfo.vkCode);
            bool altDown = (keyInfo.flags & LLKHF_ALTDOWN) != 0;
            bool ctrlDown = (GetKeyState(0x11) & 0x8000) != 0;
            bool shiftDown = (GetKeyState(0x10) & 0x8000) != 0;
            bool winDown = (GetKeyState(VK_LWIN) & 0x8000) != 0 || (GetKeyState(VK_RWIN) & 0x8000) != 0;

            // Block Win key alone and any Win+key combo (Start menu, Win+R Run, etc.)
            if (vk == VK_LWIN || vk == VK_RWIN)
                return true;
            if (winDown)
                return true;
            // Block Ctrl+Esc → Start menu
            if (ctrlDown && vk == VK_ESCAPE)
                return true;
            // Block Alt+F4 → close window
            if (altDown && vk == VK_F4)
                return true;
            // Block Alt+Tab → task switch
            if (altDown && vk == VK_TAB)
                return true;
            // Block Alt+Esc → minimize/cycle without showing switcher
            if (altDown && vk == VK_ESCAPE)
                return true;
            // Block Ctrl+Shift+Esc → Task Manager
            if (ctrlDown && shiftDown && vk == VK_ESCAPE)
                return true;

            return false;
        }


        private bool IsTrustedContextWindow(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero) return false;
            if (IsOwnedByCurrentProcess(hwnd)) return true;

            IntPtr trusted;
            lock (_stateLock) trusted = _trustedHwnd;
            if (trusted == IntPtr.Zero) return false;

            if (hwnd == trusted) return true;
            return IsChild(trusted, hwnd);
        }

        private bool IsOwnedByCurrentProcess(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero) return false;

            IntPtr trusted;
            lock (_stateLock) trusted = _trustedHwnd;
            if (trusted == IntPtr.Zero) return false;

            IntPtr trustedRoot = GetAncestor(trusted, 3);
            IntPtr hwndRoot = GetAncestor(hwnd, 3);
            if (trustedRoot != IntPtr.Zero && trustedRoot == hwndRoot)
                return true;

            if (hwnd == trusted) return true;
            return IsChild(trusted, hwnd);
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


        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT
        {
            public uint type;
            public INPUTUNION U;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct INPUTUNION
        {
            [FieldOffset(0)] public KEYBDINPUT ki;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KEYBDINPUT
        {
            public ushort wVk;
            public ushort wScan;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
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

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("user32.dll")]
        private static extern short GetKeyState(int nVirtKey);

        [DllImport("user32.dll")]
        private static extern IntPtr WindowFromPoint(POINT point);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsChild(IntPtr hWndParent, IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetAncestor(IntPtr hwnd, uint gaFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }
    }
}