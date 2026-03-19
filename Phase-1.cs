using System;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new USBApplicationContext());
    }
}

class USBApplicationContext : ApplicationContext
{
    public USBApplicationContext()
    {
        new USBMessageWindow();
    }
}

class USBMessageWindow : NativeWindow
{
    // =============================
    // CONSTANTS
    // =============================
    private const int WM_DEVICECHANGE = 0x0219;
    private const int DBT_DEVICEARRIVAL = 0x8000;
    private const int DBT_DEVTYP_DEVICEINTERFACE = 0x00000005;
    private const int DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000;

    private static readonly Guid GUID_DEVINTERFACE_USB_DEVICE =
        new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED");

    public USBMessageWindow()
    {
        CreateHandle(new CreateParams());
        RegisterUsbNotifications();
    }

    // =============================
    // REGISTER USB NOTIFICATIONS
    // =============================
    private void RegisterUsbNotifications()
    {
        DEV_BROADCAST_DEVICEINTERFACE filter = new DEV_BROADCAST_DEVICEINTERFACE
        {
            dbcc_size = Marshal.SizeOf<DEV_BROADCAST_DEVICEINTERFACE>(),
            dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE,
            dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE
        };

        IntPtr buffer = Marshal.AllocHGlobal(filter.dbcc_size);
        Marshal.StructureToPtr(filter, buffer, false);

        RegisterDeviceNotification(
            this.Handle,
            buffer,
            DEVICE_NOTIFY_WINDOW_HANDLE);

        Marshal.FreeHGlobal(buffer);
    }

    // =============================
    // MESSAGE HANDLER
    // =============================
    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_DEVICECHANGE && m.WParam.ToInt32() == DBT_DEVICEARRIVAL)
        {
            if (m.LParam == IntPtr.Zero)
                return;

            DEV_BROADCAST_DEVICEINTERFACE info =
                Marshal.PtrToStructure<DEV_BROADCAST_DEVICEINTERFACE>(m.LParam);

            if (info.dbcc_devicetype != DBT_DEVTYP_DEVICEINTERFACE)
                return;

            IntPtr namePtr = IntPtr.Add(
                m.LParam,
                Marshal.OffsetOf<DEV_BROADCAST_DEVICEINTERFACE>("dbcc_name").ToInt32());

            string devicePath = Marshal.PtrToStringAuto(namePtr);

            Debug.WriteLine("USB insertion detected");
            Debug.WriteLine(devicePath);

            HandleUsbInsertion(devicePath);
        }

        base.WndProc(ref m);
    }

    // =============================
    // PHASE-1: VID / PID
    // =============================
    private static void HandleUsbInsertion(string devicePath)
    {
        int vidIndex = devicePath.IndexOf("VID_", StringComparison.OrdinalIgnoreCase);
        int pidIndex = devicePath.IndexOf("PID_", StringComparison.OrdinalIgnoreCase);

        if (vidIndex < 0 || pidIndex < 0)
            return;

        string vid = devicePath.Substring(vidIndex + 4, 4);
        string pid = devicePath.Substring(pidIndex + 4, 4);

        string instanceId = ExtractInstanceId(devicePath);

        Debug.WriteLine("---- INSERTED USB DEVICE ----");
        Debug.WriteLine($"VID        : {vid}");
        Debug.WriteLine($"PID        : {pid}");
        Debug.WriteLine($"InstanceID : {instanceId}");

        ThreadPool.QueueUserWorkItem(_ =>
        {
            Thread.Sleep(1200);
            IdentifyDeviceType(instanceId);
        });
    }

    // =============================
    // PHASE-2: DEVICE TYPE (SetupAPI)
    // =============================
    private static void IdentifyDeviceType(string instanceId)
    {
        IntPtr set = SetupDiGetClassDevs(
            ref GUID_DEVINTERFACE_USB_DEVICE,
            null,
            IntPtr.Zero,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

        SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA
        {
            cbSize = Marshal.SizeOf<SP_DEVINFO_DATA>()
        };

        uint index = 0;

        while (SetupDiEnumDeviceInfo(set, index++, ref devInfo))
        {
            string devInst = GetDeviceInstanceId(set, devInfo);

            if (!string.Equals(devInst, instanceId, StringComparison.OrdinalIgnoreCase))
                continue;

            string service = GetDeviceProperty(set, devInfo, SPDRP_SERVICE);
            string name = GetDeviceProperty(set, devInfo, SPDRP_FRIENDLYNAME);

            Debug.WriteLine("---- DEVICE TYPE IDENTIFIED ----");
            Debug.WriteLine($"Service : {service}");
            Debug.WriteLine($"Name    : {name}");
            Debug.WriteLine($"Type    : {MapService(service)}");
            break;
        }

        SetupDiDestroyDeviceInfoList(set);
    }

    // =============================
    // HELPERS
    // =============================
    private static string ExtractInstanceId(string path)
    {
        // \\?\USB#VID_xxxx&PID_yyyy#INSTANCE#{GUID}
        var parts = path.Split('#');
        return parts.Length >= 3 ? $"{parts[1]}\\{parts[2]}" : null;
    }

    private static string GetDeviceProperty(IntPtr set, SP_DEVINFO_DATA info, uint prop)
    {
        byte[] buffer = new byte[512];
        SetupDiGetDeviceRegistryProperty(
            set, ref info, prop, out _, buffer, (uint)buffer.Length, out _);

        return Encoding.Unicode.GetString(buffer).TrimEnd('\0');
    }

    private static string GetDeviceInstanceId(IntPtr set, SP_DEVINFO_DATA info)
    {
        StringBuilder sb = new StringBuilder(512);
        SetupDiGetDeviceInstanceId(set, ref info, sb, sb.Capacity, out _);
        return sb.ToString();
    }

    private static string MapService(string service) => service switch
    {
        "USBSTOR" => "USB Mass Storage 💾",
        "HidUsb" => "HID (Keyboard / Mouse) ⚠️",
        "WUDFWpdMtp" => "Mobile / MTP Device 📱",
        "usbrndis6" => "USB Network Device 🌐",
        _ => "Other USB Device"
    };

    // =============================
    // STRUCTS & PINVOKE
    // =============================
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct DEV_BROADCAST_DEVICEINTERFACE
    {
        public int dbcc_size;
        public int dbcc_devicetype;
        public int dbcc_reserved;
        public Guid dbcc_classguid;
        public short dbcc_name;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public int cbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    private const uint DIGCF_PRESENT = 0x2;
    private const uint DIGCF_DEVICEINTERFACE = 0x10;

    private const uint SPDRP_SERVICE = 0x4;
    private const uint SPDRP_FRIENDLYNAME = 0xC;

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr RegisterDeviceNotification(
        IntPtr hRecipient, IntPtr filter, int flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(
        ref Guid g, string e, IntPtr hwnd, uint flags);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiEnumDeviceInfo(
        IntPtr set, uint index, ref SP_DEVINFO_DATA data);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiGetDeviceRegistryProperty(
        IntPtr set, ref SP_DEVINFO_DATA data, uint prop,
        out uint type, byte[] buffer, uint size, out uint needed);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiGetDeviceInstanceId(
        IntPtr set, ref SP_DEVINFO_DATA data,
        StringBuilder id, int size, out int needed);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
}
