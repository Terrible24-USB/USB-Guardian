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
    }

    public static class DeviceDecisionDialog
    {
        public static DeviceDecisionResult ShowDecision(DeviceDecisionRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            var result = new DeviceDecisionResult();
            using var form = new Form
            {
                Text = "USB Guardian - Device Decision Required",
                Size = new Size(660, 500),
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var txtDetails = new TextBox
            {
                Location = new Point(20, 20),
                Size = new Size(610, 310),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Text = BuildDetailsText(request)
            };

            var chkNeverAsk = new CheckBox
            {
                Text = "Trust this device and never ask again",
                Location = new Point(20, 345),
                Size = new Size(420, 24),
                Checked = false
            };

            var btnAllow = new Button
            {
                Text = "Allow Once",
                Location = new Point(20, 385),
                Size = new Size(140, 40),
                BackColor = Color.LightGreen
            };
            btnAllow.Click += (_, _) =>
            {
                result.Action = DeviceDecisionAction.AllowOnce;
                result.NeverAskAgain = chkNeverAsk.Checked;
                form.DialogResult = DialogResult.OK;
                form.Close();
            };

            var btnWhitelist = new Button
            {
                Text = "Whitelist Device",
                Location = new Point(175, 385),
                Size = new Size(140, 40),
                BackColor = Color.LightBlue
            };
            btnWhitelist.Click += (_, _) =>
            {
                result.Action = DeviceDecisionAction.AllowAndWhitelist;
                result.NeverAskAgain = true;
                form.DialogResult = DialogResult.Yes;
                form.Close();
            };

            var btnBlock = new Button
            {
                Text = "Block Device",
                Location = new Point(330, 385),
                Size = new Size(140, 40),
                BackColor = Color.LightCoral
            };
            btnBlock.Click += (_, _) =>
            {
                result.Action = DeviceDecisionAction.Block;
                result.NeverAskAgain = false;
                form.DialogResult = DialogResult.No;
                form.Close();
            };

            var btnIgnore = new Button
            {
                Text = "Ignore",
                Location = new Point(490, 385),
                Size = new Size(140, 40),
                BackColor = Color.Gainsboro
            };
            btnIgnore.Click += (_, _) =>
            {
                result.Action = DeviceDecisionAction.Ignore;
                result.NeverAskAgain = false;
                form.DialogResult = DialogResult.Cancel;
                form.Close();
            };

            form.Controls.AddRange(new Control[]
            {
                txtDetails, chkNeverAsk, btnAllow, btnWhitelist, btnBlock, btnIgnore
            });

            form.ShowDialog();
            return result;
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
