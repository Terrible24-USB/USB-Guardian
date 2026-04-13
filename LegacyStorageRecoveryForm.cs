using System;
using System.Diagnostics;
using System.Drawing;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// Guided recovery dialog for legacy USB storage blocks.
    ///
    /// Shown when USBSTOR\Start == 4 and there is no recorded previous value that the
    /// standard unblock path could restore — typically caused by an older version of
    /// USB Guardian that disabled the service without recording the original value.
    ///
    /// Recovery action: set USBSTOR\Start to 3 (Demand/Manual), which is the safest
    /// default that restores USB storage without needing to know the original value.
    ///
    /// Requires Administrator privileges; offers to restart elevated if not running as admin.
    /// Respects DryRun mode.
    /// </summary>
    public class LegacyStorageRecoveryForm : Form
    {
        private readonly UnblockManager _unblockManager;
        private readonly bool _isElevated;

        private Label _lblCurrentValue;
        private Button _btnRestore;
        private Label _lblResult;

        public LegacyStorageRecoveryForm(UnblockManager unblockManager)
        {
            _unblockManager = unblockManager ?? throw new ArgumentNullException(nameof(unblockManager));
            _isElevated = IsRunningAsAdmin();
            InitializeComponent();
            RefreshCurrentValue();
        }

        // ---- Form construction ----

        private void InitializeComponent()
        {
            Text = "USB Guardian – Restore USB Storage";
            Size = new Size(580, 430);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            Icon = SystemIcons.Warning;

            int y = 12;

            // Title
            var lblTitle = new Label
            {
                Text = "⚠  Legacy USB Storage Block Detected",
                Font = new Font("Arial", 13, FontStyle.Bold),
                ForeColor = Color.DarkRed,
                Location = new Point(12, y),
                Size = new Size(550, 30),
                TextAlign = ContentAlignment.MiddleLeft
            };
            y += 38;

            // Dry-run badge
            var lblDryRun = new Label
            {
                Visible = _unblockManager.DryRun,
                Text = "⚠ DRY RUN MODE – no system changes will be made",
                ForeColor = Color.DarkOrange,
                Font = new Font("Arial", 9, FontStyle.Bold),
                Location = new Point(12, y),
                Size = new Size(550, 20),
                TextAlign = ContentAlignment.MiddleLeft
            };
            if (_unblockManager.DryRun) y += 26;

            // Explanation
            var lblExplain = new Label
            {
                Text =
                    "The USB Mass Storage driver (USBSTOR) is currently disabled globally on this system.\r\n\r\n" +
                    "This was most likely done by an older version of USB Guardian that did not record\r\n" +
                    "the original value, so the normal unblock path cannot restore it automatically.\r\n\r\n" +
                    "⚠  This is a GLOBAL setting — it affects ALL USB storage devices on this PC,\r\n" +
                    "    not just one specific device.",
                Font = new Font("Arial", 9),
                Location = new Point(12, y),
                Size = new Size(550, 110),
                TextAlign = ContentAlignment.TopLeft
            };
            y += 118;

            // Current value indicator
            _lblCurrentValue = new Label
            {
                Font = new Font("Consolas", 10, FontStyle.Bold),
                ForeColor = Color.DarkRed,
                Location = new Point(12, y),
                Size = new Size(550, 24),
                TextAlign = ContentAlignment.MiddleLeft
            };
            y += 32;

            // Recovery explanation
            var lblRecovery = new Label
            {
                Text =
                    "Clicking \"Restore USB Storage\" will set USBSTOR\\Start to 3 (Manual/Demand),\r\n" +
                    "which is the standard safe value. You should unplug and reconnect your USB\r\n" +
                    "storage device (or reboot) after restoring.",
                Font = new Font("Arial", 9),
                Location = new Point(12, y),
                Size = new Size(550, 60),
                TextAlign = ContentAlignment.TopLeft
            };
            y += 68;

            // Admin warning (shown when not elevated)
            var lblAdminWarn = new Label
            {
                Visible = !_isElevated,
                Text = "⚠  Administrator rights are required to modify registry service keys.",
                ForeColor = Color.DarkRed,
                BackColor = Color.MistyRose,
                Font = new Font("Arial", 9, FontStyle.Bold),
                Location = new Point(12, y),
                Size = new Size(550, 24),
                TextAlign = ContentAlignment.MiddleLeft,
                BorderStyle = BorderStyle.FixedSingle
            };
            if (!_isElevated) y += 32;

            // Result label
            _lblResult = new Label
            {
                Text = string.Empty,
                Font = new Font("Arial", 9),
                ForeColor = Color.DarkGreen,
                Location = new Point(12, y),
                Size = new Size(550, 20),
                TextAlign = ContentAlignment.MiddleLeft
            };
            y += 28;

            // Buttons row
            _btnRestore = new Button
            {
                Text = "✅ Restore USB Storage (set Start=3)",
                Location = new Point(12, y),
                Size = new Size(260, 36),
                BackColor = Color.FromArgb(0, 140, 70),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Enabled = _isElevated || _unblockManager.DryRun
            };
            _btnRestore.Click += BtnRestore_Click;

            var btnRestartAdmin = new Button
            {
                Visible = !_isElevated,
                Text = "🔒 Restart as Administrator",
                Location = new Point(282, y),
                Size = new Size(200, 36),
                BackColor = Color.DarkOrange,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnRestartAdmin.Click += BtnRestartAdmin_Click;

            var btnClose = new Button
            {
                Text = "Close",
                Location = new Point(490, y),
                Size = new Size(78, 36),
                FlatStyle = FlatStyle.Flat
            };
            btnClose.Click += (_, _) => Close();

            Controls.AddRange(new Control[]
            {
                lblTitle, lblDryRun, lblExplain,
                _lblCurrentValue, lblRecovery,
                lblAdminWarn, _lblResult,
                _btnRestore, btnRestartAdmin, btnClose
            });
        }

        private void RefreshCurrentValue()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\usbstor");
                if (key == null)
                {
                    _lblCurrentValue.Text = "USBSTOR service key not found.";
                    _lblCurrentValue.ForeColor = Color.DimGray;
                    _btnRestore.Enabled = false;
                    return;
                }

                int start = key.GetValue("Start") is int s ? s : -1;
                _lblCurrentValue.Text = $"Current USBSTOR\\Start = {start}" +
                                        (start == 4 ? "  (DISABLED — USB storage is globally blocked)" : "  (not disabled)");
                _lblCurrentValue.ForeColor = start == 4 ? Color.DarkRed : Color.DarkGreen;

                // Only enable restore button if currently disabled and user is elevated (or dry-run)
                _btnRestore.Enabled = start == 4 && (_isElevated || _unblockManager.DryRun);
            }
            catch (Exception ex)
            {
                _lblCurrentValue.Text = $"Could not read USBSTOR\\Start: {ex.Message}";
                _lblCurrentValue.ForeColor = Color.DimGray;
            }
        }

        // ---- Event handlers ----

        private void BtnRestore_Click(object? sender, EventArgs e)
        {
            string dryNote = _unblockManager.DryRun ? "\n\n(DRY RUN: no actual changes will be made)" : string.Empty;
            var confirm = MessageBox.Show(
                "This will set HKLM\\SYSTEM\\CurrentControlSet\\Services\\usbstor\\Start = 3 (Manual).\r\n\r\n" +
                "⚠  This affects ALL USB storage devices on this system — not just one device.\r\n\r\n" +
                "After restoring, unplug and reconnect your USB storage device (or reboot) " +
                "for the change to take effect." + dryNote + "\r\n\r\nContinue?",
                "Confirm: Restore USB Storage",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes) return;

            try
            {
                Cursor = Cursors.WaitCursor;
                string resultMsg = _unblockManager.RestoreLegacyUsbStor(targetStart: 3);
                Cursor = Cursors.Default;

                _lblResult.Text = resultMsg;
                _lblResult.ForeColor = resultMsg.StartsWith("USBSTOR Start restored") ? Color.DarkGreen : Color.DarkRed;
                RefreshCurrentValue();

                MessageBox.Show(
                    resultMsg + "\r\n\r\nPlease unplug and reconnect your USB storage device,\r\n" +
                    "or restart Windows, to complete the recovery.",
                    _unblockManager.DryRun ? "Dry Run – Restore USB Storage" : "USB Storage Restored",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Cursor = Cursors.Default;
                string err = $"Error: {ex.Message}";
                _lblResult.Text = err;
                _lblResult.ForeColor = Color.DarkRed;
                MessageBox.Show(err, "Restore Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnRestartAdmin_Click(object? sender, EventArgs e)
        {
            var confirm = MessageBox.Show(
                "USB Guardian will restart with Administrator privileges.\r\n\r\nContinue?",
                "Restart as Administrator",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (confirm != DialogResult.Yes) return;

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    Verb = "runas",
                    UseShellExecute = true
                };
                Process.Start(psi);
                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not restart as administrator:\r\n{ex.Message}",
                    "Restart Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        // ---- Helper ----

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
