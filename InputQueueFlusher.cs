using System;
using System.Runtime.InteropServices;

namespace USBGuardian
{
    /// <summary>
    /// Layer 3 of the 4-layer Rubber Ducky defense: aggressively flushes any input
    /// that may have been queued before the device was frozen (Layer 2).
    ///
    /// Call <see cref="FlushAll"/> immediately after <c>CM_Disable_DevNode</c> returns.
    ///
    /// Three-step flush:
    ///   1. Inject synthetic key-up events for all modifier keys so that no Shift/Ctrl/
    ///      Alt/Win state is "stuck" from a partially-typed payload.
    ///   2. Drain the calling thread's message queue of all pending WM_KEY* and
    ///      WM_MOUSE* messages via a PeekMessage loop (bounded to 512 iterations).
    ///   3. Inject a small relative mouse movement to break any scripted
    ///      absolute-position click sequence that the payload may have queued.
    ///
    /// All steps are best-effort; failures are silently swallowed so a hook/platform
    /// error never blocks the critical freeze → dialog path.
    /// </summary>
    internal static class InputQueueFlusher
    {
        // Modifier virtual-key codes to release: LWin, RWin, Ctrl, Alt, Shift, Esc
        private static readonly ushort[] ModifierVKeys = { 0x5B, 0x5C, 0x11, 0x12, 0x10, 0x1B };

        private const uint INPUT_KEYBOARD = 1;
        private const uint INPUT_MOUSE = 0;
        private const uint KEYEVENTF_KEYUP = 0x0002;
        private const uint MOUSEEVENTF_MOVE = 0x0001; // relative move

        private const uint PM_REMOVE = 0x0001;
        private const uint WM_KEYFIRST = 0x0100;
        private const uint WM_MOUSELAST = 0x020E;
        private const int MaxPeekIterations = 512;

        /// <summary>
        /// Performs all three flush steps.  Safe to call from any thread.
        /// </summary>
        public static void FlushAll()
        {
            try { ReleaseModifierKeys(); } catch { /* best-effort */ }
            try { DrainMessageQueue(); } catch { /* best-effort */ }
            try { BreakMouseScript(); } catch { /* best-effort */ }
        }

        // ── Step 1: inject key-up for all held modifiers ──────────────────────────

        private static void ReleaseModifierKeys()
        {
            INPUT[] inputs = new INPUT[ModifierVKeys.Length];
            for (int i = 0; i < ModifierVKeys.Length; i++)
            {
                inputs[i] = new INPUT
                {
                    type = INPUT_KEYBOARD,
                    U = new INPUTUNION
                    {
                        ki = new KEYBDINPUT
                        {
                            wVk = ModifierVKeys[i],
                            dwFlags = KEYEVENTF_KEYUP
                        }
                    }
                };
            }
            SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        }

        // ── Step 2: drain thread message queue of all queued input messages ───────

        private static void DrainMessageQueue()
        {
            int guard = 0;
            while (PeekMessage(out _, IntPtr.Zero, WM_KEYFIRST, WM_MOUSELAST, PM_REMOVE)
                   && ++guard < MaxPeekIterations)
            {
                // message discarded
            }
        }

        // ── Step 3: 1-pixel jitter to break absolute-position click scripts ───────

        private static void BreakMouseScript()
        {
            INPUT[] move =
            {
                new INPUT
                {
                    type = INPUT_MOUSE,
                    U = new INPUTUNION
                    {
                        mi = new MOUSEINPUT { dx = 1, dy = 1, dwFlags = MOUSEEVENTF_MOVE }
                    }
                }
            };
            SendInput(1, move, Marshal.SizeOf<INPUT>());
        }

        // ── P/Invoke ──────────────────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int ptX;
            public int ptY;
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
            [FieldOffset(0)] public MOUSEINPUT mi;
            [FieldOffset(0)] public KEYBDINPUT ki;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MOUSEINPUT
        {
            public int dx;
            public int dy;
            public uint mouseData;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
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

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekMessage(
            out MSG lpMsg,
            IntPtr hWnd,
            uint wMsgFilterMin,
            uint wMsgFilterMax,
            uint wRemoveMsg);
    }
}
