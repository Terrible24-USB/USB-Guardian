using System;
using System.Drawing;
using System.Windows.Forms;

namespace USBGuardian
{
    public enum DeviceDecisionAction
    {
        AllowOnce,
        AllowAndWhitelist,
        Block,
        Ignore
    }

    public sealed class DeviceDecisionRequest
    {
        public DeviceInformationSnapshot DeviceInformation { get; set; } = new();
        public ThreatLevel ThreatLevel { get; set; }
        public string RiskAssessment { get; set; } = "Unknown risk";
        public string SuggestedAction { get; set; } = "Review device details before choosing.";
    }

    public sealed class DeviceDecisionResult
    {
        public DeviceDecisionAction Action { get; set; } = DeviceDecisionAction.Block;
        public bool NeverAskAgain { get; set; }
        public bool TimedOut { get; set; }
        public bool PromptFailed { get; set; }
    }

    public static class DeviceDecisionDialog
    {
        public static DeviceDecisionResult ShowDecision(DeviceDecisionRequest request)
            => ShowDecision(request, 20);

        public static DeviceDecisionResult ShowDecision(
            DeviceDecisionRequest request,
            int timeoutSeconds = 20,
            Action<IntPtr>? onDialogShown = null,
            Action<IntPtr>? onDialogClosed = null)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            if (timeoutSeconds < 1) throw new ArgumentOutOfRangeException(nameof(timeoutSeconds));

            var result = new DeviceDecisionResult();
            using var form = new DecisionForm
            {
                Text = "USB Guardian - Device Decision Required",
                Size = new Size(660, 500),
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                TopMost = true,
                ShowInTaskbar = true,
                KeyPreview = true
            };
            form.Shown += (_, _) =>
            {
                try
                {
                    form.WindowState = FormWindowState.Normal;
                    form.Activate();
                    form.BringToFront();
                    onDialogShown?.Invoke(form.Handle);
                }
                catch { }
            };
            form.FormClosed += (_, _) =>
            {
                try { onDialogClosed?.Invoke(form.Handle); } catch { }
            };

            var txtDetails = new TextBox
            {
                Location = new Point(20, 20),
                Size = new Size(610, 310),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Text = BuildDetailsText(request),
                TabStop = false
            };

            var chkNeverAsk = new CheckBox
            {
                Text = "Trust this device and never ask again",
                Location = new Point(20, 345),
                Size = new Size(420, 24),
                Checked = false
            };

            var btnAllow = new Button { Text = "Allow Once", Location = new Point(20, 385), Size = new Size(140, 40), BackColor = Color.LightGreen };
            btnAllow.Click += (_, _) => { result.Action = DeviceDecisionAction.AllowOnce; result.NeverAskAgain = chkNeverAsk.Checked; form.DialogResult = DialogResult.OK; form.Close(); };

            var btnWhitelist = new Button { Text = "Allow & Whitelist", Location = new Point(175, 385), Size = new Size(140, 40), BackColor = Color.LightBlue };
            btnWhitelist.Click += (_, _) => { result.Action = DeviceDecisionAction.AllowAndWhitelist; result.NeverAskAgain = true; form.DialogResult = DialogResult.Yes; form.Close(); };

            var btnBlock = new Button { Text = "Block Device", Location = new Point(330, 385), Size = new Size(140, 40), BackColor = Color.LightCoral };
            btnBlock.Click += (_, _) => { result.Action = DeviceDecisionAction.Block; result.NeverAskAgain = false; form.DialogResult = DialogResult.No; form.Close(); };

            var btnIgnore = new Button { Text = "Ignore", Location = new Point(490, 385), Size = new Size(140, 40), BackColor = Color.Gainsboro };
            btnIgnore.Click += (_, _) => { result.Action = DeviceDecisionAction.Ignore; result.NeverAskAgain = false; form.DialogResult = DialogResult.Cancel; form.Close(); };

            form.BindShortcuts(btnAllow, btnWhitelist, btnBlock, btnIgnore);

            var lblShortcuts = new Label
            {
                Text = "Shortcuts: A = Allow Once, W = Allow & Whitelist, B = Block, I = Ignore",
                Location = new Point(20, 430),
                Size = new Size(610, 22),
                ForeColor = Color.DimGray
            };


            var lblShortcuts = new Label
            {
                Text = "Shortcuts: A = Allow Once, W = Allow & Whitelist, B = Block, I = Ignore",
                Location = new Point(20, 430),
                Size = new Size(610, 22),
                ForeColor = Color.DimGray
            };

            form.KeyDown += (_, e) =>
            {
                if (e.KeyCode == Keys.A)
                {
                    btnAllow.PerformClick();
                    e.Handled = true;
                }
                else if (e.KeyCode == Keys.W)
                {
                    btnWhitelist.PerformClick();
                    e.Handled = true;
                }
                else if (e.KeyCode == Keys.B)
                {
                    btnBlock.PerformClick();
                    e.Handled = true;
                }
                else if (e.KeyCode == Keys.I)
                {
                    btnIgnore.PerformClick();
                    e.Handled = true;
                }
            };

            form.Controls.AddRange(new Control[]
            {
                txtDetails, chkNeverAsk, btnAllow, btnWhitelist, btnBlock, btnIgnore, lblShortcuts
            });

            using var timeoutTimer = new Timer { Interval = timeoutSeconds * 1000 };
            timeoutTimer.Tick += (_, _) =>
            {
                timeoutTimer.Stop();
                result.Action = DeviceDecisionAction.Block;
                result.TimedOut = true;
                form.DialogResult = DialogResult.No;
                form.Close();
            };

            timeoutTimer.Start();
            form.ShowDialog();
            return result;
        }

        private sealed class DecisionForm : Form
        {
            private Button? _allow;
            private Button? _whitelist;
            private Button? _block;
            private Button? _ignore;

            public void BindShortcuts(Button allow, Button whitelist, Button block, Button ignore)
            {
                _allow = allow; _whitelist = whitelist; _block = block; _ignore = ignore;
            }

            protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
            {
                Keys key = keyData & Keys.KeyCode;
                if (key == Keys.A) { _allow?.PerformClick(); return true; }
                if (key == Keys.W) { _whitelist?.PerformClick(); return true; }
                if (key == Keys.B) { _block?.PerformClick(); return true; }
                if (key == Keys.I) { _ignore?.PerformClick(); return true; }
                return base.ProcessCmdKey(ref msg, keyData);
            }
        }

        private static string BuildDetailsText(DeviceDecisionRequest request)
        {
            var info = request.DeviceInformation;
            return
                "Unknown USB device detected.\r\n\r\n" +
                $"VID:PID: {info.VidPid}\r\n" +
                $"Manufacturer: {info.Manufacturer}\r\n" +
                $"Product: {info.ProductName}\r\n" +
                $"Serial: {info.SerialNumber ?? "Not available"}\r\n" +
                $"Class/Subclass: {info.DeviceClass} / 0x{info.DeviceSubClass:X2}\r\n" +
                $"Interface count: {info.InterfaceCount}\r\n" +
                $"Descriptor hash: {info.DescriptorHash}\r\n" +
                $"First seen: {info.InsertionTimestampUtc:yyyy-MM-dd HH:mm:ss} UTC\r\n" +
                $"Port info: {info.PortInformation}\r\n\r\n" +
                $"Threat level: {request.ThreatLevel}\r\n" +
                $"Risk assessment: {request.RiskAssessment}\r\n" +
                $"Suggested action: {request.SuggestedAction}\r\n\r\n" +
                "Important: Blocking here is per-device only. USB Guardian does NOT disable the global USBSTOR service.";
        }
    }
}
