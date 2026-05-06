using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace USBGuardian
{
    /// <summary>
    /// Manages input containment during a USB device decision prompt.
    ///
    /// TWO-LAYER PROTECTION:
    ///
    /// Layer A — Early Combo Block (active from T+10ms, PnP fire)
    ///   A separate lightweight hook installed at app startup.
    ///   Activated immediately when OnPnpDeviceArrived fires.
    ///   Blocks all shell-opening combos before CM_Disable_DevNode completes.
    ///   Covers the ~13ms gap where 2-3 keystrokes could slip through.
    ///   Blocked combos: WIN keys, CTRL+ESC, CTRL+SHIFT+ESC, ALT+F4,
    ///                   CTRL+T/N/L/R/V (browser + clipboard injection).
    ///
    /// Layer B — Full Containment (active from dialog open, ~T+500ms)
    ///   Full keyboard + mouse hooks. Whitelist-only keys pass through.
    ///   Only our process windows receive input.
    ///
    /// Timeline:
    ///   T+10ms  PnP fires → EarlyComboBlock() → deadly combos dead
    ///   T+30ms  CM_Disable_DevNode → device frozen
    ///   T+500ms Dialog opens → Activate() → full containment
    ///   User decides → Deactivate() → EarlyComboUnblock() → everything restored
    /// </summary>
    internal sealed class InputContainmentManager : IDisposable
    {
        // ── allowed keys during full containment ────────────────────────────────────
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

        // ── VK codes ────────────────────────────────────────────────────────────────
        private const int VK_LWIN = 0x5B;
        private const int VK_RWIN = 0x5C;
        private const int VK_APPS = 0x5D; // context menu key
        private const int VK_ESCAPE = 0x1B;
        private const int VK_F4 = 0x73;
        private const int VK_TAB = 0x09;
        private const int VK_T = 0x54; // CTRL+T new tab
        private const int VK_N = 0x4E; // CTRL+N new window
        private const int VK_L = 0x4C; // CTRL+L address bar
        private const int VK_R = 0x52; // CTRL+R refresh / browser run
        private const int VK_V = 0x56; // CTRL+V paste (clipboard inject)
        private const int VK_SHIFT = 0x10;

        // ── hook constants ───────────────────────────────────────────────────────────
        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int HC_ACTION = 0;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int LLKHF_ALTDOWN = 0x20;

        private readonly SecurityEventLogger _logger;
        private readonly SynchronizationContext _uiContext;
        private readonly object _stateLock = new();

        // ── Layer B: full containment hooks ─────────────────────────────────────────
        private IntPtr _keyboardHook = IntPtr.Zero;
        private IntPtr _mouseHook = IntPtr.Zero;
        private LowLevelKeyboardProc? _keyboardProc;
        private LowLevelMouseProc? _mouseProc;
        private IntPtr _trustedHwnd = IntPtr.Zero;
        private int _activeFlag;
        private bool _hooksInstalled;

        // ── Layer A: early combo block hook ─────────────────────────────────────────
        private IntPtr _earlyHook = IntPtr.Zero;
        private LowLevelKeyboardProc? _earlyProc;
        private int _earlyBlockFlag;   // 1 = early block active
        private bool _earlyHookInstalled;

        private bool _disposed;

        public bool IsActive => Volatile.Read(ref _activeFlag) == 1;
        public bool EarlyBlocking => Volatile.Read(ref _earlyBlockFlag) == 1;

        public InputContainmentManager(SecurityEventLogger logger, SynchronizationContext uiContext)
        {
            _logger = logger;
            _uiContext = uiContext;
            // Install the early hook on the UI thread so the message pump
            // receives hook callbacks. SetWindowsHookEx on a non-pump thread
            // means callbacks are silently dropped by Windows.
            _uiContext.Post(_ => InstallEarlyHook(), null);
        }

        // ── Layer A public API ───────────────────────────────────────────────────────

        /// <summary>
        /// Called by OnPnpDeviceArrived at ~T+10ms.
        /// Activates deadly-combo blocking before CM_Disable_DevNode completes.
        /// </summary>
        public void EarlyComboBlock()
        {
            Volatile.Write(ref _earlyBlockFlag, 1);
            Debug.WriteLine("[InputContainment] Early combo block ACTIVE.");
            _logger.LogInfo(0, "InputContainment", "Early combo block activated at PnP arrival.");
        }

        /// <summary>
        /// Called by Deactivate() after dialog closes.
        /// Restores all blocked combos for normal system use.
        /// </summary>
        public void EarlyComboUnblock()
        {
            Volatile.Write(ref _earlyBlockFlag, 0);
            Debug.WriteLine("[InputContainment] Early combo block RELEASED.");
            _logger.LogInfo(0, "InputContainment", "Early combo block released after decision.");
        }

        private void InstallEarlyHook()
        {
            lock (_stateLock)
            {
                if (_earlyHookInstalled || _disposed) return;

                _earlyProc = EarlyComboHookCallback;
                _earlyHook = SetWindowsHookEx(WH_KEYBOARD_LL, _earlyProc, GetModuleHandle(null), 0);

                if (_earlyHook == IntPtr.Zero)
                {
                    _logger.LogWarning(0, "InputContainment",
                        $"Early combo hook install failed (Win32={Marshal.GetLastWin32Error()}). " +
                        "Gap protection unavailable.");
                    return;
                }

                _earlyHookInstalled = true;
                Debug.WriteLine("[InputContainment] Early combo hook installed at startup.");
            }
        }

        /// <summary>
        /// The early hook callback — only runs filtering when _earlyBlockFlag == 1.
        /// Near-zero overhead when inactive (single volatile read + pass-through).
        /// </summary>
        private IntPtr EarlyComboHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !EarlyBlocking)
                return CallNextHookEx(_earlyHook, nCode, wParam, lParam);

            // Always let our own process through (dialog buttons etc).
            IntPtr fg = GetForegroundWindow();
            if (IsOwnedByCurrentProcess(fg))
                return CallNextHookEx(_earlyHook, nCode, wParam, lParam);

            var key = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            if (IsDeadlyCombo(key))
            {
                Debug.WriteLine($"[EarlyBlock] Blocked deadly combo VK=0x{key.vkCode:X2}");
                return (IntPtr)1;
            }

            return CallNextHookEx(_earlyHook, nCode, wParam, lParam);
        }

        /// <summary>
        /// Returns true for any keystroke that could open a shell, terminal,
        /// browser address bar, or execute clipboard content.
        ///
        /// Blocked combos:
        ///   WIN+anything        — Start menu / Run / all WIN shortcuts
        ///   CTRL+ESC            — Start menu (WIN alternative)
        ///   CTRL+SHIFT+ESC      — Task Manager
        ///   ALT+F4              — Close window (disruptive)
        ///   APPS key            — Context menu (can right-click → open terminal)
        ///   CTRL+T              — Browser new tab
        ///   CTRL+N              — Browser new window
        ///   CTRL+L              — Browser address bar focus
        ///   CTRL+R              — Browser run / page refresh (can trigger reload attacks)
        ///   CTRL+V              — Clipboard paste (clipboard injection attack)
        /// </summary>
        private static bool IsDeadlyCombo(KBDLLHOOKSTRUCT key)
        {
            int vk = unchecked((int)key.vkCode);
            bool altDown = (key.flags & LLKHF_ALTDOWN) != 0;
            bool ctrlDown = (GetKeyState(0x11) & 0x8000) != 0;
            bool shiftDown = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            bool winDown = (GetKeyState(VK_LWIN) & 0x8000) != 0
                          || (GetKeyState(VK_RWIN) & 0x8000) != 0;

            // WIN key itself or any WIN+X combo
            if (vk == VK_LWIN || vk == VK_RWIN) return true;
            if (winDown) return true;

            // Context menu key
            if (vk == VK_APPS) return true;

            // CTRL+ESC = Start menu
            if (ctrlDown && vk == VK_ESCAPE) return true;

            // CTRL+SHIFT+ESC = Task Manager
            if (ctrlDown && shiftDown && vk == VK_ESCAPE) return true;

            // ALT+F4 = close window
            if (altDown && vk == VK_F4) return true;

            // Browser / shell combos requiring CTRL
            if (ctrlDown)
            {
                if (vk == VK_T) return true;  // new tab
                if (vk == VK_N) return true;  // new window
                if (vk == VK_L) return true;  // address bar
                if (vk == VK_R) return true;  // refresh/run
                if (vk == VK_V) return true;  // clipboard paste
            }

            return false;
        }

        // ── Layer B public API ───────────────────────────────────────────────────────

        public void Activate(string reason)
        {
            EnsureHooksInstalled();
            if (!_hooksInstalled)
            {
                _logger.LogWarning(0, "InputContainment",
                    $"Full containment activation skipped — hooks not installed: {reason}");
                return;
            }

            FlushPendingInputState();
            Volatile.Write(ref _activeFlag, 1);
            _logger.LogInfo(0, "InputContainment", $"Full containment activated: {reason}");
        }

        public void Deactivate(string reason)
        {
            Volatile.Write(ref _activeFlag, 0);
            EarlyComboUnblock();                     // always release early block on deactivate
            lock (_stateLock) _trustedHwnd = IntPtr.Zero;
            ReleaseHooks();
            _logger.LogInfo(0, "InputContainment", $"Containment deactivated: {reason}");
        }

        private void EnsureHooksInstalled()
        {
            // If already on UI thread, install directly.
            // Otherwise marshal to UI thread and block until done
            // (Send is synchronous — caller waits).
            if (SynchronizationContext.Current == _uiContext)
            {
                EnsureHooksInstalledCore();
            }
            else
            {
                _uiContext.Send(_ => EnsureHooksInstalledCore(), null);
            }
        }

        private void EnsureHooksInstalledCore()
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
                        $"Full containment hook install failed (Win32={Marshal.GetLastWin32Error()}).");
                    if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; }
                    if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; }
                    _hooksInstalled = false;
                    return;
                }

                _hooksInstalled = true;
                _logger.LogInfo(0, "InputContainment", "Full containment hooks installed.");
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
                _logger.LogInfo(0, "InputContainment", "Full containment hooks removed.");
            }
        }

        private void FlushPendingInputState()
        {
            // Send synthetic key-up events for modifier keys to clear stuck state
            // that a Ducky may have left in WIN-down / CTRL-down etc.
            var releases = new[] { VK_LWIN, VK_RWIN, 0x11, 0x12, 0x10, VK_ESCAPE };
            var inputs = new INPUT[releases.Length];
            for (int i = 0; i < releases.Length; i++)
            {
                inputs[i] = new INPUT
                {
                    type = 1,
                    U = new INPUTUNION { ki = new KEYBDINPUT { wVk = (ushort)releases[i], dwFlags = 0x0002 } }
                };
            }
            SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        }

        // ── TrustedWindowScope ───────────────────────────────────────────────────────

        public TrustedWindowScope BeginTrustedWindowScope(IntPtr hwnd)
            => new TrustedWindowScope(this, hwnd);

        internal sealed class TrustedWindowScope : IDisposable
        {
            private readonly InputContainmentManager _owner;
            private readonly IntPtr _hwnd;
            private System.Threading.Timer? _reClipTimer;
            private bool _disposed;

            internal TrustedWindowScope(InputContainmentManager owner, IntPtr hwnd)
            {
                _owner = owner;
                _hwnd = hwnd;
                lock (owner._stateLock) owner._trustedHwnd = hwnd;

                // Clip immediately with whatever rect we have now,
                // then re-clip at 50ms and 200ms to catch the fully laid-out rect.
                ApplyClip();
                _reClipTimer = new System.Threading.Timer(_ =>
                {
                    if (_disposed) return;
                    ApplyClip();
                }, null, 50, 150);   // fire at 50ms, then every 150ms (keeps clip fresh)
            }

            private void ApplyClip()
            {
                if (_hwnd == IntPtr.Zero || _disposed) return;
                if (GetWindowRect(_hwnd, out RECT r))
                    ClipCursor(ref r);
            }

            public void Dispose()
            {
                if (_disposed) return;
                _disposed = true;
                _reClipTimer?.Dispose();
                _reClipTimer = null;
                lock (_owner._stateLock)
                    if (_owner._trustedHwnd == _hwnd)
                        _owner._trustedHwnd = IntPtr.Zero;

                // Release cursor confinement.
                ClipCursor(IntPtr.Zero);
            }
        }

        // ── Layer B hook callbacks ───────────────────────────────────────────────────

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

            var key = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);

            // Deadly combos always blocked during full containment too.
            if (IsDeadlyCombo(key)) return (IntPtr)1;

            // Our own process windows get full input.
            IntPtr fg = GetForegroundWindow();
            if (IsTrustedContextWindow(fg))
                return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

            // Everything else: whitelist only.
            int vk = unchecked((int)key.vkCode);
            foreach (var k in AllowedKeys)
                if (vk == (int)k)
                    return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

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
            if (IsTrustedContextWindow(WindowFromPoint(mouse.pt)))
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            return (IntPtr)1;
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

        private static bool IsOwnedByCurrentProcess(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero) return false;
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
                Volatile.Write(ref _earlyBlockFlag, 0);

                if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; }
                if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; }
                if (_earlyHook != IntPtr.Zero) { UnhookWindowsHookEx(_earlyHook); _earlyHook = IntPtr.Zero; }
            }
        }

        // ── structs ──────────────────────────────────────────────────────────────────

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

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int x; public int y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT { public uint type; public INPUTUNION U; }

        [StructLayout(LayoutKind.Explicit)]
        private struct INPUTUNION { [FieldOffset(0)] public KEYBDINPUT ki; }

        [StructLayout(LayoutKind.Sequential)]
        private struct KEYBDINPUT
        {
            public ushort wVk;
            public ushort wScan;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        // ── delegates & P/Invoke ─────────────────────────────────────────────────────

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

        [DllImport("user32.dll")]
        private static extern short GetKeyState(int nVirtKey);

        [DllImport("user32.dll")]
        private static extern IntPtr WindowFromPoint(POINT pt);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsChild(IntPtr hWndParent, IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("user32.dll")]
        private static extern bool ClipCursor(ref RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool ClipCursor(IntPtr lpRect);   // null overload to release

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);
    }
}