using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

namespace USBGuardian
{
    /// <summary>
    /// WinForms dialog that lists all blocked devices and lets the user
    /// select one to unblock.
    ///
    /// Safety design:
    /// - Shows a built-in device warning (via <see cref="BuiltInDeviceSafetyChecker"/>)
    ///   and requires explicit confirmation before unblocking.
    /// - If the process is not elevated, the list is still shown (read-only),
    ///   but unblock is disabled with a clear message offering to restart as admin.
    /// - Dry-run mode: when <see cref="UnblockManager.DryRun"/> is true the form
    ///   shows "[DRY RUN]" labels and unblock actions are only logged.
    /// - After a successful unblock the form indicates whether an immediate
    ///   re-enable was possible or the user should unplug/replug the device.
    /// - If a legacy USB storage block is detected (USBSTOR\Start==4 with no
    ///   recorded previous value), a "Restore USB Storage" button is shown.
    /// </summary>
    public class UnblockDevicesForm : Form
    {
        private readonly BlockedDeviceStore _store;
        private readonly UnblockManager _unblockManager;
        private readonly bool _isElevated;

        private ListView _listView;
        private Button _btnUnblock;
        private Button _btnClearLegacy;
        private Button _btnRestoreUsbStor;
        private Button _btnClose;
        private Label _lblStatus;
        private Label _lblPrivilegeWarning;

        public UnblockDevicesForm(BlockedDeviceStore store, UnblockManager unblockManager)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _unblockManager = unblockManager ?? throw new ArgumentNullException(nameof(unblockManager));
            _isElevated = IsRunningAsAdmin();

            InitializeComponent();
            PopulateList();
            RefreshLegacyBanner();
        }

        // ---- Form construction ----

        private void InitializeComponent()
        {
            Text = "USB Guardian – Unblock Devices";
            Size = new Size(780, 560);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            Icon = SystemIcons.Shield;

            // Title label
            var lblTitle = new Label
            {
                Text = "Blocked Devices",
                Font = new Font("Arial", 13, FontStyle.Bold),
                Location = new Point(12, 10),
                Size = new Size(300, 28)
            };

            // Dry-run badge
            var lblDryRun = new Label
            {
                Visible = _unblockManager.DryRun,
                Text = "⚠ DRY RUN MODE – no system changes will be made",
                ForeColor = Color.DarkOrange,
                Font = new Font("Arial", 9, FontStyle.Bold),
                Location = new Point(320, 14),
                Size = new Size(440, 22),
                TextAlign = ContentAlignment.MiddleRight
            };

            // Privilege warning
            _lblPrivilegeWarning = new Label
            {
                Visible = !_isElevated,
                Text = "⚠  Administrator rights are required to unblock devices.  " +
                       "The list is shown for reference.",
                ForeColor = Color.DarkRed,
                BackColor = Color.MistyRose,
                Font = new Font("Arial", 9, FontStyle.Bold),
                Location = new Point(12, 42),
                Size = new Size(740, 26),
                TextAlign = ContentAlignment.MiddleLeft,
                BorderStyle = BorderStyle.FixedSingle
            };

            // ListView
            _listView = new ListView
            {
                Location = new Point(12, _isElevated ? 46 : 76),
                Size = new Size(740, _isElevated ? 330 : 300),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                MultiSelect = false,
                Font = new Font("Consolas", 9)
            };
            _listView.Columns.Add("Description", 200);
            _listView.Columns.Add("VID:PID", 90);
            _listView.Columns.Add("Instance ID", 180);
            _listView.Columns.Add("Blocked At (UTC)", 140);
            _listView.Columns.Add("Reason", 120);
            _listView.SelectedIndexChanged += ListView_SelectedIndexChanged;

            // Status label
            _lblStatus = new Label
            {
                Location = new Point(12, _isElevated ? 386 : 386),
                Size = new Size(740, 20),
                ForeColor = Color.DimGray,
                Text = string.Empty
            };

            // Unblock button
            _btnUnblock = new Button
            {
                Text = "Unblock Selected Device",
                Location = new Point(12, 412),
                Size = new Size(200, 36),
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Enabled = false
            };
            _btnUnblock.Click += BtnUnblock_Click;

            // Clear legacy ConfigFlags button
            _btnClearLegacy = new Button
            {
                Text = "Clear Legacy ConfigFlags",
                Location = new Point(220, 412),
                Size = new Size(180, 36),
                BackColor = Color.FromArgb(180, 100, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Enabled = false,
                Visible = true
            };
            _btnClearLegacy.Click += BtnClearLegacy_Click;

            // Restore USB Storage button (shown when legacy block detected)
            _btnRestoreUsbStor = new Button
            {
                Text = "⚠ Restore USB Storage",
                Location = new Point(12, 454),
                Size = new Size(200, 36),
                BackColor = Color.DarkRed,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Visible = false
            };
            _btnRestoreUsbStor.Click += BtnRestoreUsbStor_Click;

            // Restart-as-admin button (only shown when not elevated)
            var btnRestart = new Button
            {
                Visible = !_isElevated,
                Text = "🔒 Restart as Administrator",
                Location = new Point(220, 454),
                Size = new Size(200, 36),
                BackColor = Color.DarkOrange,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnRestart.Click += BtnRestart_Click;

            // Refresh button
            var btnRefresh = new Button
            {
                Text = "Refresh",
                Location = new Point(430, 412),
                Size = new Size(100, 36),
                FlatStyle = FlatStyle.Flat
            };
            btnRefresh.Click += (_, _) => { PopulateList(); RefreshLegacyBanner(); };

            // Close button
            _btnClose = new Button
            {
                Text = "Close",
                Location = new Point(652, 412),
                Size = new Size(100, 36),
                FlatStyle = FlatStyle.Flat
            };
            _btnClose.Click += (_, _) => Close();

            Controls.AddRange(new Control[]
            {
                lblTitle, lblDryRun, _lblPrivilegeWarning,
                _listView, _lblStatus,
                _btnUnblock, _btnClearLegacy, _btnRestoreUsbStor,
                btnRestart, btnRefresh, _btnClose
            });
        }

        // ---- Data binding ----

        private void PopulateList()
        {
            _listView.Items.Clear();
            var records = _store.GetAll();

            foreach (var r in records)
            {
                var item = new ListViewItem(r.Description ?? string.Empty)
                {
                    Tag = r
                };
                item.SubItems.Add($"{r.Vid}:{r.Pid}");
                item.SubItems.Add(r.InstanceId ?? string.Empty);
                item.SubItems.Add(r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
                item.SubItems.Add(r.BlockReason ?? string.Empty);
                _listView.Items.Add(item);
            }

            _lblStatus.Text = records.Count == 0
                ? "No blocked devices on record."
                : $"{records.Count} blocked device(s) found.";

            _btnUnblock.Enabled = false;
            _btnClearLegacy.Enabled = false;
        }

        /// <summary>
        /// Show or hide the "Restore USB Storage" banner based on whether a legacy block
        /// is currently active.
        /// </summary>
        private void RefreshLegacyBanner()
        {
            bool isLegacy = _unblockManager.IsLegacyUsbStorBlock();
            _btnRestoreUsbStor.Visible = isLegacy;
        }

        // ---- Event handlers ----

        private void ListView_SelectedIndexChanged(object? sender, EventArgs e)
        {
            bool hasSelection = _listView.SelectedItems.Count > 0;
            bool canAct = hasSelection && (_isElevated || _unblockManager.DryRun);

            _btnUnblock.Enabled = canAct;
            _btnClearLegacy.Enabled = canAct;
        }

        private void BtnUnblock_Click(object? sender, EventArgs e)
        {
            if (_listView.SelectedItems.Count == 0) return;

            var record = (BlockedDeviceRecord)_listView.SelectedItems[0].Tag;
            if (record == null) return;

            // Build a lightweight DeviceFingerprint just to drive the safety checker
            var fp = new DeviceFingerprint
            {
                Vid = record.Vid,
                Pid = record.Pid,
                InstanceId = record.InstanceId,
                Description = record.Description,
                SerialNumber = record.SerialNumber
            };

            // Safety Gate #1 – definitely built-in
            if (BuiltInDeviceSafetyChecker.IsDefinitelyBuiltIn(fp))
            {
                var warn = MessageBox.Show(
                    "🚨 CRITICAL WARNING 🚨\n\n" +
                    $"The device \"{record.Description}\" appears to be a BUILT-IN component " +
                    "(e.g., internal keyboard, mouse, or trackpad).\n\n" +
                    "Unblocking a wrongly-blocked built-in device is generally safe, but if it " +
                    "was blocked intentionally please verify before continuing.\n\n" +
                    "Continue with unblock?",
                    "CRITICAL WARNING – Built-in Device",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Stop,
                    MessageBoxDefaultButton.Button2);

                if (warn != DialogResult.Yes)
                {
                    _lblStatus.Text = "Unblock cancelled by user (built-in device warning).";
                    return;
                }
            }
            // Safety Gate #2 – might be built-in
            else if (BuiltInDeviceSafetyChecker.MightBeBuiltIn(fp))
            {
                var warn = MessageBox.Show(
                    "⚠ WARNING\n\n" +
                    $"The device \"{record.Description}\" might be an internal component.\n\n" +
                    "Continue with unblock?",
                    "Warning – Possibly Built-in Device",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);

                if (warn != DialogResult.Yes)
                {
                    _lblStatus.Text = "Unblock cancelled by user.";
                    return;
                }
            }

            // Safety warning: if unblocking will restore the USBSTOR service, warn the user
            // that this affects ALL USB storage devices on the system (not just this one).
            bool restoresUsbStorService = record.Actions.Any(a =>
                a.ActionType == "ServiceStart" &&
                string.Equals(a.ServiceName, "usbstor", StringComparison.OrdinalIgnoreCase));

            if (restoresUsbStorService)
            {
                var storageWarn = MessageBox.Show(
                    "⚠  GLOBAL USB STORAGE WARNING  ⚠\n\n" +
                    "This device was blocked by disabling the USB Mass Storage driver (USBSTOR " +
                    "service) system-wide.\n\n" +
                    "Unblocking will RESTORE the USBSTOR service, re-enabling USB mass storage " +
                    "for ALL USB storage devices on this computer — not only this device.\n\n" +
                    "A system re-enumeration will be triggered automatically. If the device still " +
                    "does not appear, unplug and replug it.\n\n" +
                    "Continue?",
                    "⚠ Global USB Storage Impact",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2);

                if (storageWarn != DialogResult.Yes)
                {
                    _lblStatus.Text = "Unblock cancelled by user.";
                    return;
                }
            }

            // Explicit confirmation
            string dryNote = _unblockManager.DryRun ? "\n\n(DRY RUN: no actual changes will be made)" : string.Empty;
            var confirm = MessageBox.Show(
                $"Unblock device:\n  {record.Description}\n  VID:{record.Vid}  PID:{record.Pid}\n\n" +
                $"This will reverse the registry and/or service changes that USB Guardian applied.{dryNote}\n\n" +
                "Proceed?",
                "Confirm Unblock",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes) return;

            // Run unblock
            try
            {
                Cursor = Cursors.WaitCursor;
                UnblockResult result = _unblockManager.UnblockDevice(record);
                Cursor = Cursors.Default;

                string summary = string.Join("\n• ", result.Messages);
                string title = _unblockManager.DryRun ? "Dry Run Results" : "Unblock Results";

                string replugNote = result.NeedsReplug && !_unblockManager.DryRun
                    ? "\n\n📌 Please unplug and plug the device back in to complete recovery."
                    : string.Empty;

                MessageBox.Show(
                    $"Actions performed:\n• {summary}{replugNote}",
                    title,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                // If any action could not restore the USBSTOR service (no recorded previous value),
                // show a targeted recovery dialog with manual restoration instructions.
                var recoveryItems = results
                    .Where(r => r.StartsWith("RECOVERY_REQUIRED:", StringComparison.Ordinal))
                    .ToList();
                if (recoveryItems.Any())
                {
                    MessageBox.Show(
                        "⚠  MANUAL RESTORATION REQUIRED  ⚠\n\n" +
                        "USB Guardian could not automatically restore the USB Mass Storage driver " +
                        "because no previous Start value was recorded at block time.\n\n" +
                        "USB storage will remain unavailable until you restore it manually:\n\n" +
                        "  1. Open Registry Editor as Administrator  (Win+R → regedit → OK)\n" +
                        @"  2. Navigate to:  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbstor" + "\n" +
                        "  3. Double-click  Start  and set the value to  3  (Demand Start — Windows default)\n" +
                        "  4. Click OK and close Registry Editor\n" +
                        "  5. Restart your computer, or unplug and replug the USB device\n\n" +
                        "Value meaning: 3 = Demand Start (Windows default)   4 = Disabled",
                        "⚠ Manual Restoration Required",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                }

                PopulateList();
                RefreshLegacyBanner();
                _lblStatus.Text = _unblockManager.DryRun
                    ? $"[DRY RUN] Unblock simulated for {record.Description}"
                    : $"Device unblocked: {record.Description}" +
                      (result.NeedsReplug ? " (unplug/replug required)" : string.Empty);
            }
            catch (Exception ex)
            {
                Cursor = Cursors.Default;
                MessageBox.Show(
                    $"Unblock failed:\n{ex.Message}",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                _lblStatus.Text = $"Error during unblock: {ex.Message}";
                Debug.WriteLine($"[UnblockDevicesForm] Unblock error: {ex.Message}");
            }
        }

        private void BtnClearLegacy_Click(object? sender, EventArgs e)
        {
            if (_listView.SelectedItems.Count == 0) return;

            var record = (BlockedDeviceRecord)_listView.SelectedItems[0].Tag;
            if (record == null) return;

            string dryNote = _unblockManager.DryRun ? "\n\n(DRY RUN: no actual changes will be made)" : string.Empty;
            var confirm = MessageBox.Show(
                $"Clear legacy ConfigFlags for:\n  {record.Description}\n  VID:{record.Vid}  PID:{record.Pid}\n\n" +
                "This will clear only the disable bits (0x100 and 0x40) from registry ConfigFlags " +
                "on the known registry paths for this device. No other values will be changed." +
                dryNote + "\n\nProceed?",
                "Confirm: Clear Legacy ConfigFlags",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes) return;

            try
            {
                Cursor = Cursors.WaitCursor;
                List<string> results = _unblockManager.ClearLegacyConfigFlags(record);
                Cursor = Cursors.Default;

                string summary = string.Join("\n• ", results);
                MessageBox.Show(
                    $"Results:\n• {summary}\n\n" +
                    "If the device is still not detected, please unplug and reconnect it.",
                    _unblockManager.DryRun ? "Dry Run – Clear Legacy ConfigFlags" : "Clear Legacy ConfigFlags",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                _lblStatus.Text = _unblockManager.DryRun
                    ? $"[DRY RUN] Legacy clear simulated for {record.Description}"
                    : $"Legacy ConfigFlags cleared for {record.Description}";
            }
            catch (Exception ex)
            {
                Cursor = Cursors.Default;
                MessageBox.Show(
                    $"Clear legacy ConfigFlags failed:\n{ex.Message}",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                _lblStatus.Text = $"Error: {ex.Message}";
            }
        }

        private void BtnRestoreUsbStor_Click(object? sender, EventArgs e)
        {
            using var form = new LegacyStorageRecoveryForm(_unblockManager);
            form.ShowDialog(this);
            RefreshLegacyBanner();
        }

        private void BtnRestart_Click(object? sender, EventArgs e)
        {
            var confirm = MessageBox.Show(
                "USB Guardian will restart with Administrator privileges.\n\nContinue?",
                "Restart as Administrator",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (confirm != DialogResult.Yes) return;

            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    Verb = "runas",   // triggers UAC elevation prompt
                    UseShellExecute = true
                };
                System.Diagnostics.Process.Start(psi);
                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not restart as administrator:\n{ex.Message}",
                    "Restart Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        // ---- Helpers ----

        private static bool IsRunningAsAdmin()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}

