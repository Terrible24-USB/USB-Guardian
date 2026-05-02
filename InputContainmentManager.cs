using System;
<<<<<<< HEAD
=======
using System.ComponentModel;
>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace USBGuardian
{
    /// <summary>
    /// Process-wide input containment gate.
    /// Hooks are installed once at startup and remain resident.
    /// Activation is reference-counted so overlapping callers cannot
    /// accidentally disable containment early.
    /// </summary>
    internal sealed class InputContainmentManager : IDisposable
    {
        private readonly SecurityEventLogger _logger;
        private readonly object _stateLock = new();

<<<<<<< HEAD
        private IntPtr _keyboardHook = IntPtr.Zero;
        private IntPtr _mouseHook = IntPtr.Zero;
        private LowLevelKeyboardProc? _keyboardProc;
        private LowLevelMouseProc? _mouseProc;
        private int _activeFlag;
        private bool _disposed;

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int HC_ACTION = 0;

        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_SYSKEYUP = 0x0105;
=======
        private IntPtr _keyboardHook;
        private IntPtr _mouseHook;
        private LowLevelKeyboardProc? _keyboardProc;
        private LowLevelMouseProc? _mouseProc;

        private int _activationCount;
        private bool _disposed;

        private static readonly int CurrentProcessId = Process.GetCurrentProcess().Id;

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int HC_ACTION = 0;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYDOWN = 0x0104;
>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723

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
                if (_keyboardHook != IntPtr.Zero && _mouseHook != IntPtr.Zero)
                    return;

                _keyboardProc = KeyboardHookCallback;
                _mouseProc = MouseHookCallback;

<<<<<<< HEAD
                _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, GetModuleHandle(null), 0);
                _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, GetModuleHandle(null), 0);
=======
                IntPtr moduleHandle = GetModuleHandle(null);
                _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, moduleHandle, 0);
                _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, moduleHandle, 0);
>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723

                if (_keyboardHook == IntPtr.Zero || _mouseHook == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
<<<<<<< HEAD
                    _logger.LogWarning(0, "SinkMode", $"Failed to install low-level hooks (Win32={err})");
                    Debug.WriteLine($"[SinkMode] Hook installation failed: {err}");
                }
                else
                {
                    _logger.LogInfo(0, "SinkMode", "Low-level keyboard/mouse hooks installed.");
                }
            }
        }

        public void Activate(string reason)
        {
            Volatile.Write(ref _activeFlag, 1);
            _logger.LogWarning(0, "SinkMode", $"Activated containment: {reason}");
        }

        public void Deactivate(string reason)
        {
            Volatile.Write(ref _activeFlag, 0);
            _logger.LogInfo(0, "SinkMode", $"Deactivated containment: {reason}");
=======
                    CleanupHooks_NoThrow();
                    throw new Win32Exception(err, "Unable to install low-level input hooks.");
                }

                _logger.LogInfo(0, "SinkMode", "Low-level keyboard/mouse hooks installed.");
            }
        }

        public ContainmentScope BeginContainment(string reason)
        {
            lock (_stateLock)
            {
                ThrowIfDisposed();
                if (_keyboardHook == IntPtr.Zero || _mouseHook == IntPtr.Zero)
                {
                    try { InitializeHooks(); }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(0, "SinkMode", $"Containment hook init failed: {ex.Message}");
                        Debug.WriteLine($"[SinkMode] BeginContainment init failed: {ex}");
                    }
                }

                int count = Interlocked.Increment(ref _activationCount);
                if (count == 1)
                    _logger.LogWarning(0, "SinkMode", $"Activated containment: {reason}");
                else
                    _logger.LogInfo(0, "SinkMode", $"Containment nested activation ({count}): {reason}");
            }

            return new ContainmentScope(this, reason);
        }

        private void EndContainment(string reason)
        {
            int count = Interlocked.Decrement(ref _activationCount);
            if (count < 0)
            {
                Interlocked.Exchange(ref _activationCount, 0);
                _logger.LogWarning(0, "SinkMode", "Containment activation underflow detected; corrected to 0.");
                return;
            }

            if (count == 0)
                _logger.LogInfo(0, "SinkMode", $"Deactivated containment: {reason}");
>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723
        }

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);

            // Allow interaction with the guardian's own decision UI while still
            // blocking input to other processes/windows.
            if (!IsForegroundOwnedByCurrentProcess())
                return (IntPtr)1;

            return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode != HC_ACTION || !IsActive)
                return CallNextHookEx(_mouseHook, nCode, wParam, lParam);

            if (!IsForegroundOwnedByCurrentProcess())
                return (IntPtr)1;

            return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
        }

        private static bool IsForegroundOwnedByCurrentProcess()
        {
            IntPtr fg = GetForegroundWindow();
            if (fg == IntPtr.Zero)
                return false;

            _ = GetWindowThreadProcessId(fg, out uint pid);
            return pid == (uint)Environment.ProcessId;
        }

        public void Dispose()
        {
            if (_disposed) return;
<<<<<<< HEAD
            lock (_stateLock)
            {
                if (_disposed) return;
                _disposed = true;
                CleanupHooks_NoThrow();
            }
        }

        private void CleanupHooks_NoThrow()
        {
            try
=======
            _disposed = true;

            lock (_stateLock)

>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723
            {
                lock (_stateLock)
                {
<<<<<<< HEAD
                    if (_keyboardHook != IntPtr.Zero)
                    {
                        UnhookWindowsHookEx(_keyboardHook);
                        _keyboardHook = IntPtr.Zero;
                    }

                    if (_mouseHook != IntPtr.Zero)
                    {
                        UnhookWindowsHookEx(_mouseHook);
                        _mouseHook = IntPtr.Zero;
                    }
=======
                    UnhookWindowsHookEx(_keyboardHook);
                    _keyboardHook = IntPtr.Zero;
                }

                if (_mouseHook != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(_mouseHook);
                    _mouseHook = IntPtr.Zero;
>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SinkMode] Cleanup error: {ex.Message}");
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(InputContainmentManager));
        }

        internal readonly struct ContainmentScope : IDisposable
        {
            private readonly InputContainmentManager? _owner;
            private readonly string _reason;

            public ContainmentScope(InputContainmentManager owner, string reason)
            {
                _owner = owner;
                _reason = reason;
            }

            public void Dispose()
            {
                _owner?.Deactivate(_reason);
            }
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
<<<<<<< HEAD
        private static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfn, IntPtr hMod, uint dwThreadId);
=======
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);
>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723

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
<<<<<<< HEAD
=======

>>>>>>> 0bdff85604eb2bf74cbcd4946b8780b243565723
    }
}
