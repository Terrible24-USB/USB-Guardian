using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace USBGuardian
{
    /// <summary>
    /// Implements a global low-level keyboard hook (WH_KEYBOARD_LL) to capture ALL keystrokes 
    /// (both physical and software-injected) and feed them into the RealTimeKeystrokeMonitor.
    /// This runs constantly in the background.
    /// </summary>
    public sealed class GlobalKeystrokeTelemetry : IDisposable
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int HC_ACTION = 0;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        // LLKHF_INJECTED: Test the injected flag (bit 4)
        private const uint LLKHF_INJECTED = 0x00000010;

        private IntPtr _hookId = IntPtr.Zero;
        private readonly LowLevelKeyboardProc _proc;
        private readonly UsbGuardianSecurityEngine _securityEngine;
        private readonly SecurityEventLogger _logger;
        private readonly SynchronizationContext _uiContext;
        private bool _disposed = false;
        private readonly object _lock = new();

        public GlobalKeystrokeTelemetry(
            UsbGuardianSecurityEngine securityEngine,
            SecurityEventLogger logger,
            SynchronizationContext uiContext)
        {
            _securityEngine = securityEngine;
            _logger = logger;
            _uiContext = uiContext;
            _proc = HookCallback;

            // Start monitoring the special virtual endpoints
            _securityEngine.StartKeystrokeMonitoring("SOFTWARE_MACRO");
            _securityEngine.StartKeystrokeMonitoring("PHYSICAL_KEYBOARD");
        }

        public void Start()
        {
            // CRITICAL: WH_KEYBOARD_LL callbacks are delivered on the thread that
            // called SetWindowsHookEx. That thread MUST be pumping a Windows message
            // loop or callbacks are silently dropped. We marshal to the UI thread
            // (which runs Application.Run's message pump) to guarantee delivery.
            _uiContext.Post(_ => InstallHookOnUiThread(), null);
        }

        private void InstallHookOnUiThread()
        {
            lock (_lock)
            {
                if (_hookId == IntPtr.Zero && !_disposed)
                {
                    _hookId = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(null), 0);
                    if (_hookId == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();
                        Debug.WriteLine($"[GlobalKeystrokeTelemetry] Failed to install global hook. Win32Error: {err}");
                        _logger.LogWarning(3, "Telemetry",
                            $"Global Keystroke Telemetry hook failed to install (Win32Error={err}). " +
                            "Layer 3 macro detection inactive.");
                    }
                    else
                    {
                        Debug.WriteLine("[GlobalKeystrokeTelemetry] Global telemetry hook installed on UI thread.");
                        _logger.LogInfo(3, "Telemetry", "Global Keystroke Telemetry activated on UI message pump.");
                    }
                }
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (_hookId != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(_hookId);
                    _hookId = IntPtr.Zero;
                    Debug.WriteLine("[GlobalKeystrokeTelemetry] Global telemetry hook removed.");
                }
            }
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                try
                {
                    var key = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                    
                    // Check if keystroke is injected by software (AutoHotkey, SendInput, etc.)
                    bool isInjected = (key.flags & LLKHF_INJECTED) != 0;
                    string targetVidPid = isInjected ? "SOFTWARE_MACRO" : "PHYSICAL_KEYBOARD";

                    // The actual text parsing is complex, so we just feed the timestamp for speed analysis
                    _securityEngine.EvaluateKeystrokeThreat(targetVidPid, isText: false);
                    
                    // The user requested: "just log and generate alert"
                    // So we ALWAYS return CallNextHookEx without blocking.
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[GlobalKeystrokeTelemetry] Hook callback error: {ex.Message}");
                }
            }
            return CallNextHookEx(_hookId, nCode, wParam, lParam);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _securityEngine.EvaluateKeystrokeThreat("SOFTWARE_MACRO", stop: true);
            _securityEngine.EvaluateKeystrokeThreat("PHYSICAL_KEYBOARD", stop: true);
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

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }
}
