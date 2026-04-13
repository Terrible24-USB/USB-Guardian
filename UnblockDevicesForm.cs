using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Security.Principal;
using System.Windows.Forms;

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
    /// </summary>
    public class UnblockDevicesForm : Form
    {
        private readonly BlockedDeviceStore _store;
        private readonly UnblockManager _unblockManager;
        private readonly bool _isElevated;

        private ListView _listView;
        private Button _btnUnblock;
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
        }

        // ---- Form construction ----

        private void InitializeComponent()
        {
            Text = "USB Guardian – Unblock Devices";
            Size = new Size(780, 520);
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
                Size = new Size(740, _isElevated ? 340 : 310),
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
                Location = new Point(12, _isElevated ? 396 : 396),
                Size = new Size(740, 20),
                ForeColor = Color.DimGray,
                Text = string.Empty
            };

            // Unblock button
            _btnUnblock = new Button
            {
                Text = "Unblock Selected Device",
                Location = new Point(12, 422),
                Size = new Size(200, 36),
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Enabled = false
            };
            _btnUnblock.Click += BtnUnblock_Click;

            // Restart-as-admin button (only shown when not elevated)
            var btnRestart = new Button
            {
                Visible = !_isElevated,
                Text = "🔒 Restart as Administrator",
                Location = new Point(220, 422),
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
                Location = new Point(430, 422),
                Size = new Size(100, 36),
                FlatStyle = FlatStyle.Flat
            };
            btnRefresh.Click += (_, _) => PopulateList();

            // Close button
            _btnClose = new Button
            {
                Text = "Close",
                Location = new Point(652, 422),
                Size = new Size(100, 36),
                FlatStyle = FlatStyle.Flat
            };
            _btnClose.Click += (_, _) => Close();

            Controls.AddRange(new Control[]
            {
                lblTitle, lblDryRun, _lblPrivilegeWarning,
                _listView, _lblStatus,
                _btnUnblock, btnRestart, btnRefresh, _btnClose
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
        }

        // ---- Event handlers ----

        private void ListView_SelectedIndexChanged(object? sender, EventArgs e)
        {
            // Only enable unblock when elevated (or dry-run mode)
            _btnUnblock.Enabled =
                _listView.SelectedItems.Count > 0 &&
                (_isElevated || _unblockManager.DryRun);
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
                List<string> results = _unblockManager.UnblockDevice(record);
                Cursor = Cursors.Default;

                string summary = string.Join("\n• ", results);
                string title = _unblockManager.DryRun ? "Dry Run Results" : "Unblock Results";
                MessageBox.Show(
                    $"Actions performed:\n• {summary}",
                    title,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                PopulateList();
                _lblStatus.Text = _unblockManager.DryRun
                    ? $"[DRY RUN] Unblock simulated for {record.Description}"
                    : $"Device unblocked: {record.Description}";
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
                var psi = new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    Verb = "runas",   // triggers UAC elevation prompt
                    UseShellExecute = true
                };
                Process.Start(psi);
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
