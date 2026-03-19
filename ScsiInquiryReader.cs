using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using USBGuardian; // if ScsiInquiryReader is in the USBGuardian namespace
public static class ScsiInquiryReader
{
    // =========================
    // Constants
    // =========================
    const uint GENERIC_READ  = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const int FILE_SHARE_READ = 1;
    const int FILE_SHARE_WRITE = 2;
    const int OPEN_EXISTING = 3;

    const uint IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014;

    // =========================
    // Detect USB Physical Drive
    // =========================
    public static string GetUsbPhysicalDrive(string vid, string pid)
    {
        using (var searcher = new ManagementObjectSearcher(
            "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'"))
        {
            foreach (ManagementObject drive in searcher.Get())
            {
                string pnpDeviceId = drive["PNPDeviceID"]?.ToString() ?? "";

                if (pnpDeviceId.IndexOf($"VID_{vid}", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    pnpDeviceId.IndexOf($"PID_{pid}", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string deviceId = drive["DeviceID"]?.ToString();
                    if (!string.IsNullOrEmpty(deviceId))
                        return deviceId; // Example: \\.\PHYSICALDRIVE2
                }
            }
        }

        return null;
    }

    // =========================
    // Read SCSI Inquiry
    // =========================
    public static bool ReadScsiInquiry(string physicalDrivePath, out string vendor, out string product, out string revision)
    {
        vendor = null;
        product = null;
        revision = null;

        IntPtr handle = CreateFile(
            physicalDrivePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            return false;

        try
        {
            byte[] inquiryCommand = new byte[6];

            inquiryCommand[0] = 0x12; // INQUIRY
            inquiryCommand[4] = 36;   // response length

            byte[] buffer = new byte[36];

            bool result = DeviceIoControl(
                handle,
                IOCTL_SCSI_PASS_THROUGH_DIRECT,
                inquiryCommand,
                inquiryCommand.Length,
                buffer,
                buffer.Length,
                out int bytesReturned,
                IntPtr.Zero);

            if(!result)
{
                Console.WriteLine("[SCSI] Inquiry failed.");
                return false;
            }

            vendor = Encoding.ASCII.GetString(buffer, 8, 8).Trim();
            product = Encoding.ASCII.GetString(buffer, 16, 16).Trim();
            revision = Encoding.ASCII.GetString(buffer, 32, 4).Trim();

            Console.WriteLine($"[SCSI] Vendor: {vendor}");
            Console.WriteLine($"[SCSI] Product: {product}");
            Console.WriteLine($"[SCSI] Revision: {revision}");

            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    // =========================
    // Windows API Imports
    // =========================

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        int dwShareMode,
        IntPtr lpSecurityAttributes,
        int dwCreationDisposition,
        int dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        byte[] lpInBuffer,
        int nInBufferSize,
        byte[] lpOutBuffer,
        int nOutBufferSize,
        out int lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
}