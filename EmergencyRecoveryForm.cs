using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Security.Principal;
using System.Windows.Forms;

namespace USBGuardian
{
    /// <summary>
    /// Emergency recovery dialog shown when an input-device lockout is detected.
    ///
    /// UI design:
    /// - All controls are large and mouse/touchscreen-clickable — no keyboard required.
    /// - Four recovery tiers progress from least to most destructive:
    ///     Tier 1 (Green)  – Restore AllowDeviceIDs from last-known-good backup.
    ///     Tier 2 (Orange) – Remove DenyUnspecified only (keeps AllowDeviceIDs).
    ///     Tier 3 (Blue)   – Step-by-step Safe Mode recovery guide (no registry change).
    ///     Tier 4 (Red)    – Nuclear: wipe all device installation policies.
    /// - Keyboard shortcut: Ctrl+Alt+Shift+R triggers Tier 1 (if keyboard partially works).
    /// </summary>
    public class EmergencyRecoveryForm : Form
    {
        private readonly EmergencyRecoveryManager _manager;
        private readonly List<InputDeviceMonitor.BlockedInputDevice> _blockedDevices;
        private readonly bool _isElevated;

        private Label  _lblResult   = new Label();
        private Button _btnBackup   = new Button();
        private Button _btnDenyOnly = new Button();

        public EmergencyRecoveryForm(
            EmergencyRecoveryManager manager,
            List<InputDeviceMonitor.BlockedInputDevice> blockedDevices)
        {
            _manager       = manager       ?? throw new ArgumentNullException(nameof(manager));
            _blockedDevices = blockedDevices ?? new List<InputDeviceMonitor.BlockedInputDevice>();
            _isElevated    = IsRunningAsAdmin();
            InitializeComponent();
        }

        // ---- Form construction ----

        private void InitializeComponent()
        {
            Text            = "USB Guardian — Emergency Input Device Recovery";
            Size            = new Size(700, 680);
            StartPosition   = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox     = false;
            MinimizeBox     = false;
            Icon            = SystemIcons.Warning;
            BackColor       = Color.White;
            KeyPreview      = true;
            KeyDown        += Form_KeyDown;

            int y = 14;
            const int W = 660;
            const int BtnH = 56;

            // ── Title ──────────────────────────────────────────────────────────
            var lblTitle = MakeLabel(
                "🚨  INPUT DEVICE LOCKOUT DETECTED",
                new Font("Arial", 15, FontStyle.Bold),
                Color.DarkRed, 12, y, W, 36);
            y += 44;

            // ── Subtitle explanation ───────────────────────────────────────────
            var lblSub = MakeLabel(
                "USB Guardian detected that one or more keyboard or mouse devices are blocked\r\n" +
                "by the DenyUnspecified policy. Use the recovery options below — all can be\r\n" +
                "activated with a single mouse click (no keyboard required).",
                new Font("Arial", 9), Color.Black, 12, y, W, 56);
            y += 64;

            // ── Blocked devices list ───────────────────────────────────────────
            if (_blockedDevices.Count > 0)
            {
                var lblBlockedTitle = MakeLabel(
                    "Blocked input devices detected:",
                    new Font("Arial", 9, FontStyle.Bold), Color.DarkRed, 12, y, W, 20);
                y += 24;

                foreach (var dev in _blockedDevices)
                {
                    var lblDev = MakeLabel(
                        $"   • {dev.Description}  [{dev.DeviceClass}]  ({dev.PnpDeviceId})",
                        new Font("Consolas", 8), Color.DarkRed, 12, y, W, 18);
                    Controls.Add(lblDev);
                    y += 20;
                }
                y += 8;
            }

            // ── Admin warning ──────────────────────────────────────────────────
            if (!_isElevated)
            {
                var lblAdmin = new Label
                {
                    Text = "⚠  Administrator privileges are required to modify policies. " +
                           "Please restart USB Guardian as Administrator.",
                    Font = new Font("Arial", 8, FontStyle.Bold),
                    ForeColor = Color.DarkRed,
                    BackColor = Color.MistyRose,
                    Location = new Point(12, y),
                    Size = new Size(W, 36),
                    TextAlign = ContentAlignment.MiddleLeft,
                    BorderStyle = BorderStyle.FixedSingle
                };
                Controls.Add(lblAdmin);
                y += 44;
            }

            // ── Backup metadata ────────────────────────────────────────────────
            string backupInfo = "No backup available.";
            var backup = _manager.BackupManager.LoadBackup();
            if (backup != null)
                backupInfo = $"Backup available (saved {backup.Timestamp:u}, " +
                             $"{backup.AllowedDeviceIDs.Count} device ID(s)).";

            var lblBackup = MakeLabel(backupInfo,
                new Font("Arial", 8, FontStyle.Italic),
                backup != null ? Color.DarkGreen : Color.Gray,
                12, y, W, 18);
            y += 26;

            // ── Tier 1 button ──────────────────────────────────────────────────
            var lblT1 = MakeLabel(
                "TIER 1 — Safest: Restore AllowDeviceIDs from backup",
                new Font("Arial", 8, FontStyle.Bold), Color.DarkGreen, 12, y, W, 18);
            y += 22;

            _btnBackup = MakeTierButton(
                "✅  Restore from Backup  (one-click, keeps your whitelist)",
                Color.FromArgb(0, 130, 60), y, BtnH);
            _btnBackup.Enabled = _isElevated && _manager.BackupAvailable();
            _btnBackup.Click  += BtnBackup_Click;
            y += BtnH + 10;

            // ── Tier 2 button ──────────────────────────────────────────────────
            var lblT2 = MakeLabel(
                "TIER 2 — Remove DenyUnspecified restriction (policy becomes permissive, AllowDeviceIDs kept)",
                new Font("Arial", 8, FontStyle.Bold), Color.DarkOrange, 12, y, W, 18);
            y += 22;

            _btnDenyOnly = MakeTierButton(
                "🔓  Remove DenyUnspecified  (all new devices allowed to install)",
                Color.DarkOrange, y, BtnH);
            _btnDenyOnly.Enabled = _isElevated;
            _btnDenyOnly.Click  += BtnDenyOnly_Click;
            y += BtnH + 10;

            // ── Tier 3 button (informational — no registry change) ─────────────
            var lblT3 = MakeLabel(
                "TIER 3 — Manual Safe Mode guide (no changes made now — prints instructions)",
                new Font("Arial", 8, FontStyle.Bold), Color.SteelBlue, 12, y, W, 18);
            y += 22;

            var btnSafeMode = MakeTierButton(
                "ℹ  Safe Mode Recovery Guide  (step-by-step, usable without keyboard)",
                Color.SteelBlue, y, BtnH);
            btnSafeMode.Click += BtnSafeMode_Click;
            y += BtnH + 10;

            // ── Tier 4 button ──────────────────────────────────────────────────
            var lblT4 = MakeLabel(
                "TIER 4 — NUCLEAR: wipe ALL device installation policies (IRREVERSIBLE — last resort only)",
                new Font("Arial", 8, FontStyle.Bold), Color.DarkRed, 12, y, W, 18);
            y += 22;

            var btnNuclear = MakeTierButton(
                "☢  NUCLEAR WIPE  (removes DenyUnspecified + ALL AllowDeviceIDs — CANNOT BE UNDONE)",
                Color.FromArgb(180, 0, 0), y, BtnH);
            btnNuclear.Enabled = _isElevated;
            btnNuclear.Click  += BtnNuclear_Click;
            y += BtnH + 10;

            // ── Result label ───────────────────────────────────────────────────
            _lblResult = MakeLabel(string.Empty,
                new Font("Arial", 9, FontStyle.Bold), Color.DarkGreen, 12, y, W, 24);
            y += 32;

            // ── Close button ───────────────────────────────────────────────────
            var btnClose = new Button
            {
                Text      = "Close",
                Location  = new Point(W - 78, y),
                Size      = new Size(90, 32),
                FlatStyle = FlatStyle.Flat
            };
            btnClose.Click += (_, _) => Close();

            // ── Hotkey hint ────────────────────────────────────────────────────
            var lblHotkey = MakeLabel(
                "Keyboard shortcut: Ctrl+Alt+Shift+R = Tier 1 (restore from backup)",
                new Font("Arial", 7, FontStyle.Italic), Color.Gray, 12, y + 6, 500, 18);

            Controls.AddRange(new Control[]
            {
                lblTitle, lblSub, lblBackup,
                lblT1, _btnBackup,
                lblT2, _btnDenyOnly,
                lblT3, btnSafeMode,
                lblT4, btnNuclear,
                _lblResult, btnClose, lblHotkey
            });
        }

        // ---- Event handlers ----

        private void BtnBackup_Click(object? sender, EventArgs e)
        {
            if (ConfirmAction(
                    "Restore AllowDeviceIDs from backup?\r\n\r\n" +
                    "This will replace the current AllowDeviceIDs registry values with the last saved " +
                    "backup. Your keyboard/mouse should work again after reconnecting the device.",
                    "Confirm: Restore from Backup",
                    dangerLevel: false))
            {
                RunAction(() => _manager.RestoreFromBackup(), successColor: true);
            }
        }

        private void BtnDenyOnly_Click(object? sender, EventArgs e)
        {
            if (ConfirmAction(
                    "Remove the DenyUnspecified policy restriction?\r\n\r\n" +
                    "This will allow ALL new devices to install automatically again. Your AllowDeviceIDs " +
                    "list is kept intact. Reconnect your keyboard/mouse after clicking OK.",
                    "Confirm: Remove DenyUnspecified",
                    dangerLevel: false))
            {
                RunAction(() => _manager.RemoveDenyUnspecified(), successColor: true);
            }
        }

        private void BtnSafeMode_Click(object? sender, EventArgs e)
        {
            const string guide =
                "SAFE MODE RECOVERY GUIDE\r\n" +
                "═══════════════════════════════════════════════════════════\r\n\r\n" +
                "If you cannot use your keyboard or mouse right now, note these steps on another device " +
                "or take a photo of this screen, then follow them:\r\n\r\n" +
                "1.  Hold the POWER button for 10 seconds to force-shutdown the PC.\r\n\r\n" +
                "2.  Boot into Windows Recovery:\r\n" +
                "    • Power on → immediately hold F8 (or Shift+F8) before Windows logo\r\n" +
                "    • OR: Settings → System → Recovery → Advanced startup → Restart now\r\n\r\n" +
                "3.  Choose: Troubleshoot → Advanced options → Command Prompt\r\n\r\n" +
                "4.  In the Command Prompt, type one of the following commands:\r\n\r\n" +
                "    ─ Option A (remove DenyUnspecified only) ─\r\n" +
                @"    reg delete ""HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"" /v DenyUnspecified /f" +
                "\r\n\r\n" +
                "    ─ Option B (wipe ALL device install policies) ─\r\n" +
                @"    reg delete ""HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"" /f" +
                "\r\n\r\n" +
                "5.  Type 'exit' and choose Continue to restart Windows.\r\n\r\n" +
                "6.  Your keyboard/mouse should now work normally.\r\n\r\n" +
                "═══════════════════════════════════════════════════════════\r\n" +
                "Registry path (for manual edit via regedit):\r\n" +
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" +
                "\r\nDelete value: DenyUnspecified";

            using var dlg = new Form
            {
                Text            = "USB Guardian — Safe Mode Recovery Guide",
                Size            = new Size(680, 560),
                StartPosition   = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox     = false
            };

            var txt = new RichTextBox
            {
                Text       = guide,
                ReadOnly   = true,
                Font       = new Font("Consolas", 9),
                Location   = new Point(8, 8),
                Size       = new Size(648, 450),
                BackColor  = Color.WhiteSmoke,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };

            var btnCopy = new Button
            {
                Text      = "📋  Copy",
                Location  = new Point(8, 470),
                Size      = new Size(100, 32),
                FlatStyle = FlatStyle.Flat
            };
            btnCopy.Click += (_, _) =>
            {
                try { Clipboard.SetText(txt.Text); }
                catch { /* clipboard unavailable — no-op */ }
            };

            var btnCloseGuide = new Button
            {
                Text      = "Close",
                Location  = new Point(556, 470),
                Size      = new Size(100, 32),
                FlatStyle = FlatStyle.Flat
            };
            btnCloseGuide.Click += (_, _) => dlg.Close();

            dlg.Controls.AddRange(new Control[] { txt, btnCopy, btnCloseGuide });
            dlg.ShowDialog(this);
        }

        private void BtnNuclear_Click(object? sender, EventArgs e)
        {
            // Double-confirmation for the nuclear option
            var first = MessageBox.Show(
                "⚠  WARNING: IRREVERSIBLE ACTION  ⚠\r\n\r\n" +
                "This will permanently delete ALL device installation policies, including:\r\n" +
                "  • DenyUnspecified restriction\r\n" +
                "  • ALL AllowDeviceIDs entries (your entire device whitelist)\r\n\r\n" +
                "This CANNOT be undone. USB Guardian's policy-based protection will be completely removed.\r\n\r\n" +
                "Are you sure you want to continue?",
                "⚠  NUCLEAR WIPE — First Confirmation",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (first != DialogResult.Yes) return;

            var second = MessageBox.Show(
                "FINAL CONFIRMATION:\r\n\r\nAll device installation policies WILL BE PERMANENTLY DELETED.\r\n\r\nProceed?",
                "⚠  NUCLEAR WIPE — Final Confirmation",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Stop,
                MessageBoxDefaultButton.Button2);

            if (second != DialogResult.Yes) return;

            RunAction(() => _manager.NuclearWipe(), successColor: false);
        }

        private void Form_KeyDown(object? sender, KeyEventArgs e)
        {
            // Ctrl+Alt+Shift+R → Tier 1 (backup restore)
            if (e.Control && e.Alt && e.Shift && e.KeyCode == Keys.R)
            {
                e.Handled = true;
                if (_btnBackup.Enabled)
                    _btnBackup.PerformClick();
            }
        }

        // ---- Helpers ----

        private void RunAction(Func<string> action, bool successColor)
        {
            try
            {
                Cursor = Cursors.WaitCursor;
                string result = action();
                Cursor = Cursors.Default;

                _lblResult.Text      = result;
                _lblResult.ForeColor = successColor ? Color.DarkGreen : Color.DarkRed;

                MessageBox.Show(result, "Recovery Result", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Cursor = Cursors.Default;
                _lblResult.Text      = $"Error: {ex.Message}";
                _lblResult.ForeColor = Color.DarkRed;
                MessageBox.Show($"Recovery action failed:\r\n{ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static bool ConfirmAction(string message, string title, bool dangerLevel)
        {
            return MessageBox.Show(
                message, title,
                MessageBoxButtons.YesNo,
                dangerLevel ? MessageBoxIcon.Stop : MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2)
                == DialogResult.Yes;
        }

        private Button MakeTierButton(string text, Color backColor, int y, int height)
        {
            var btn = new Button
            {
                Text      = text,
                Location  = new Point(12, y),
                Size      = new Size(660, height),
                BackColor = backColor,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font      = new Font("Arial", 10, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft,
                Padding   = new Padding(8, 0, 0, 0)
            };
            Controls.Add(btn);
            return btn;
        }

        private Label MakeLabel(string text, Font font, Color foreColor, int x, int y, int w, int h)
        {
            return new Label
            {
                Text      = text,
                Font      = font,
                ForeColor = foreColor,
                Location  = new Point(x, y),
                Size      = new Size(w, h),
                TextAlign = ContentAlignment.TopLeft
            };
        }

        private static bool IsRunningAsAdmin()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }
}
