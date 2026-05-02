using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace USBGuardian
{
    internal sealed class InputContainmentManager : IDisposable
    {
        private readonly SecurityEventLogger _logger;
        private readonly object _stateLock = new();

        private IntPtr _keyboardHook = IntPtr.Zero;
        private IntPtr _mouseHook = IntPtr.Zero;
        private LowLevelKeyboardProc? _keyboardProc;
        private LowLevelMouseProc? _mouseProc;
        private int _activeFlag;
        private bool _disposed;

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int HC_ACTION = 0;
<<<<<<< HEAD
=======
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
>>>>>>> origin/master

        public bool IsActive => Volatile.Read(ref _activeFlag) == 1;

        public InputContainmentManager(SecurityEventLogger logger)
        {
            _logger = logger;
        }

        public void InitializeHooks()
        {
            lock (_stateLock)
            {
                if (_keyboardHook != IntPtr.Zero && _mouseHook != IntPtr.Zero)
                    return;

                _keyboardProc = KeyboardHookCallback;
                _mouseProc = MouseHookCallback;

                _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, GetModuleHandle(null), 0);
                _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, GetModuleHandle(null), 0);

                if (_keyboardHook == IntPtr.Zero || _mouseHook == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
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
        }

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
<<<<<<< HEAD
            if (ShouldBlockEvent(nCode))
                return (IntPtr)1;

=======
            if (nCode == HC_ACTION && IsActive)
            {
                int msg = wParam.ToInt32();
                if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
                    return (IntPtr)1;
            }
>>>>>>> origin/master
            return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
<<<<<<< HEAD
            if (ShouldBlockEvent(nCode))
                return (IntPtr)1;

            return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
        }

        private bool ShouldBlockEvent(int nCode)
        {
            if (nCode != HC_ACTION || !IsActive)
                return false;

            // Allow interaction with the guardian's own decision UI while still
            // blocking input to other processes/windows.
            return !IsForegroundOwnedByCurrentProcess();
        }

        private static bool IsForegroundOwnedByCurrentProcess()
        {
            IntPtr fg = GetForegroundWindow();
            if (fg == IntPtr.Zero)
                return false;

            _ = GetWindowThreadProcessId(fg, out uint pid);
            return pid == (uint)Environment.ProcessId;
        }

=======
            if (nCode == HC_ACTION && IsActive)
                return (IntPtr)1;
            return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
        }

>>>>>>> origin/master
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            lock (_stateLock)
            {
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

<<<<<<< HEAD
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

=======
>>>>>>> origin/master
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);
    }
}
