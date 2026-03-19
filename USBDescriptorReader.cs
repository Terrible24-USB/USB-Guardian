using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace USBGuardian
{
    public class USBDescriptorReader
    {
        [DllImport("kernel32.dll", SetLastError = true)]


        private static extern bool DeviceIoControl(
           IntPtr hDevice,
           uint dwIoControlCode,
           IntPtr lpInBuffer,
           int nInBufferSize,
           IntPtr lpOutBuffer,
           int nOutBufferSize,
           out int lpBytesReturned,
           IntPtr lpOverlapped);
        public static bool ReadScsiInquiry(string physicalDrivePath, out string vendor, out string product, out string revision)
        {
            vendor = null;
            product = null;
            revision = null;

            IntPtr handle = CreateFile(
                physicalDrivePath,
                0,
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
                inquiryCommand[4] = 36;   // allocation length

                byte[] buffer = new byte[36];

                [DllImport("kernel32.dll", SetLastError = true)]
                static extern bool DeviceIoControl(
    IntPtr hDevice,
    uint dwIoControlCode,
    IntPtr lpInBuffer,
    int nInBufferSize,
    IntPtr lpOutBuffer,
    int nOutBufferSize,
    out int lpBytesReturned,
    IntPtr lpOverlapped);

                vendor = Encoding.ASCII.GetString(buffer, 8, 8).Trim();
                product = Encoding.ASCII.GetString(buffer, 16, 16).Trim();
                revision = Encoding.ASCII.GetString(buffer, 32, 4).Trim();

                return true;
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        private static byte[] ReadBosDescriptor(IntPtr hHub, uint port)
        {
            int requestSize = Marshal.SizeOf(typeof(USB_DESCRIPTOR_REQUEST));
            IntPtr buffer = Marshal.AllocHGlobal(requestSize + 256);

            try
            {
                USB_DESCRIPTOR_REQUEST request = new USB_DESCRIPTOR_REQUEST
                {
                    ConnectionIndex = port,
                    SetupPacket = new SETUP_PACKET
                    {
                        bmRequest = 0x80,
                        bRequest = 0x06,
                        wValue = (ushort)((USB_BOS_DESCRIPTOR_TYPE << 8)),
                        wIndex = 0,
                        wLength = 256
                    },
                    Data = new byte[256]
                };

                Marshal.StructureToPtr(request, buffer, false);

                bool result = DeviceIoControl(
                    hHub,
                    IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                    buffer,
                    requestSize + 256,
                    buffer,
                    requestSize + 256,
                    out int bytesReturned,
                    IntPtr.Zero);

                if (!result)
                    return null;

                IntPtr descPtr = IntPtr.Add(buffer, Marshal.OffsetOf<USB_DESCRIPTOR_REQUEST>("Data").ToInt32());

                byte length = Marshal.ReadByte(descPtr);
                if (length == 0)
                    return null;

                byte[] bos = new byte[length];
                Marshal.Copy(descPtr, bos, 0, length);

                return bos;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string ReadUsbStringDescriptor(IntPtr hHub, uint port, byte index)
        {
            if (index == 0)
                return null;

            int requestSize = Marshal.SizeOf(typeof(USB_DESCRIPTOR_REQUEST));
            IntPtr buffer = Marshal.AllocHGlobal(requestSize + 256);

            try
            {
                USB_DESCRIPTOR_REQUEST request = new USB_DESCRIPTOR_REQUEST
                {
                    ConnectionIndex = port,
                    SetupPacket = new SETUP_PACKET
                    {
                        bmRequest = 0x80,
                        bRequest = 0x06,
                        wValue = (ushort)((0x03 << 8) | index), // STRING descriptor
                        wIndex = 0x0409, // English language
                        wLength = 255
                    },
                    Data = new byte[256]
                };

                Marshal.StructureToPtr(request, buffer, false);

                if (!DeviceIoControl(
                    hHub,
                    IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                    buffer,
                    requestSize + 256,
                    buffer,
                    requestSize + 256,
                    out int bytesReturned,
                    IntPtr.Zero))
                {
                    return null;
                }

                IntPtr descPtr = IntPtr.Add(buffer, Marshal.OffsetOf<USB_DESCRIPTOR_REQUEST>("Data").ToInt32());

                byte length = Marshal.ReadByte(descPtr);
                byte type = Marshal.ReadByte(descPtr, 1);

                if (type != 3) // string descriptor
                    return null;

                byte[] raw = new byte[length - 2];
                Marshal.Copy(IntPtr.Add(descPtr, 2), raw, 0, raw.Length);

                return Encoding.Unicode.GetString(raw);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private const int FILE_SHARE_READ = 0x00000001;
        private const int FILE_SHARE_WRITE = 0x00000002;
        private const int OPEN_EXISTING = 3;

        // ===== SCSI IOCTL =====
        private const uint IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014;

        // ===== IOCTL codes =====
        private const uint IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX = 0x220448;
        private const uint IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION = 0x220410;
        private const uint IOCTL_USB_GET_NODE_CONNECTION_NAME = 0x220414;
        private const byte USB_BOS_DESCRIPTOR_TYPE = 0x0F;

        // ===== Hub device interface GUID =====
        private static readonly Guid GUID_DEVINTERFACE_USB_HUB = new Guid("f18a0e88-c30c-11d0-8815-00a0c906bed8");

        // ===== SetupAPI constants =====
        private const int DIGCF_PRESENT = 0x2;
        private const int DIGCF_DEVICEINTERFACE = 0x10;

        // ===== Structures =====

        [StructLayout(LayoutKind.Sequential)]
        public struct SCSI_INQUIRY_DATA
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] VendorId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ProductId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] ProductRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct USB_BOS_DESCRIPTOR
        {
            public byte bLength;
            public byte bDescriptorType;
            public ushort wTotalLength;
            public byte bNumDeviceCaps;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVICE_INTERFACE_DATA
        {
            public int cbSize;
            public Guid InterfaceClassGuid;
            public int Flags;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct SP_DEVICE_INTERFACE_DETAIL_DATA
        {
            public int cbSize;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DevicePath;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct USB_DEVICE_DESCRIPTOR
        {
            public byte bLength;
            public byte bDescriptorType;
            public ushort bcdUSB;
            public byte bDeviceClass;
            public byte bDeviceSubClass;
            public byte bDeviceProtocol;
            public byte bMaxPacketSize0;
            public ushort idVendor;
            public ushort idProduct;
            public ushort bcdDevice;
            public byte iManufacturer;
            public byte iProduct;
            public byte iSerialNumber;
            public byte bNumConfigurations;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct USB_CONFIGURATION_DESCRIPTOR
        {
            public byte bLength;
            public byte bDescriptorType;
            public ushort wTotalLength;
            public byte bNumInterfaces;
            public byte bConfigurationValue;
            public byte iConfiguration;
            public byte bmAttributes;
            public byte MaxPower;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct USB_INTERFACE_DESCRIPTOR
        {
            public byte bLength;
            public byte bDescriptorType;
            public byte bInterfaceNumber;
            public byte bAlternateSetting;
            public byte bNumEndpoints;
            public byte bInterfaceClass;
            public byte bInterfaceSubClass;
            public byte bInterfaceProtocol;
            public byte iInterface;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct USB_ENDPOINT_DESCRIPTOR
        {
            public byte bLength;
            public byte bDescriptorType;
            public byte bEndpointAddress;
            public byte bmAttributes;
            public ushort wMaxPacketSize;
            public byte bInterval;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct USB_DESCRIPTOR_REQUEST
        {
            public uint ConnectionIndex;
            public SETUP_PACKET SetupPacket;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SETUP_PACKET
        {
            public byte bmRequest;
            public byte bRequest;
            public ushort wValue;
            public ushort wIndex;
            public ushort wLength;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
       

        
        private struct SP_DEVINFO_DATA
        {
            public uint cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        // ===== P/Invoke declarations =====

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInterfaces(
    IntPtr DeviceInfoSet,
    IntPtr DeviceInfoData,
    ref Guid InterfaceClassGuid,
    int MemberIndex,
    ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInterfaceDetail(
            IntPtr DeviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            IntPtr DeviceInterfaceDetailData,
            int DeviceInterfaceDetailDataSize,
            ref int RequiredSize,
            IntPtr DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInterfaceDetail(
            IntPtr DeviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData,
            int DeviceInterfaceDetailDataSize,
            ref int RequiredSize,
            IntPtr DeviceInfoData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);


       

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            IntPtr Enumerator,
            IntPtr hwndParent,
            uint Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            uint MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiGetDeviceInstanceId(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            StringBuilder DeviceInstanceId,
            uint DeviceInstanceIdSize,
            out uint RequiredSize);



        // ===== Main method with diagnostic output =====
        public static bool ReadDescriptors(DeviceFingerprint fingerprint)
        {
            Debug.WriteLine("[USBDescriptorReader] Starting ReadDescriptors...");
            try
            {
                // 1. Find the hub and port for this device
                Debug.WriteLine("[USBDescriptorReader] Calling FindHubAndPort...");
                if (!FindHubAndPort(fingerprint, out string hubDevicePath, out uint port))
                {
                    Debug.WriteLine("[USBDescriptorReader] FindHubAndPort failed. Using fallback.");
                    return false;
                }
                Debug.WriteLine($"[USBDescriptorReader] Found hub path: {hubDevicePath}, port: {port}");

                // 2. Open the hub
                Debug.WriteLine("[USBDescriptorReader] Opening hub with CreateFile...");
                IntPtr hHub = CreateFile(
                    hubDevicePath,
                    0x40000000, // GENERIC_WRITE
                    0x00000001 | 0x00000002, // FILE_SHARE_READ | FILE_SHARE_WRITE
                    IntPtr.Zero,
                    3, // OPEN_EXISTING
                    0,
                    IntPtr.Zero
                );

                if (hHub == IntPtr.Zero || hHub == new IntPtr(-1))
                {
                    int error = Marshal.GetLastWin32Error();
                    Debug.WriteLine($"[USBDescriptorReader] Failed to open hub, error: {error}");
                    return false;
                }
                Debug.WriteLine("[USBDescriptorReader] Hub opened successfully.");

                try
                {
                    // 3. Get connection information
                    Debug.WriteLine("[USBDescriptorReader] Getting connection info...");
                    if (!GetConnectionInfo(hHub, port))
                    {
                        Debug.WriteLine("[USBDescriptorReader] Failed to get connection info");
                        return false;
                    }
                    Debug.WriteLine("[USBDescriptorReader] Connection info retrieved successfully.");

                    // 4. Read device descriptor
                    Debug.WriteLine("[USBDescriptorReader] Reading device descriptor...");
                    if (!ReadDeviceDescriptor(hHub, port, out USB_DEVICE_DESCRIPTOR devDesc))
                    {
                        Debug.WriteLine("[USBDescriptorReader] Failed to read device descriptor");

                        return false;
                    }

                    string manufacturer = null;
                    string product = null;
                    string serial = null;

                    if (devDesc.iManufacturer > 0)
                        manufacturer = ReadUsbStringDescriptor(hHub, port, devDesc.iManufacturer);

                    if (devDesc.iProduct > 0)
                        product = ReadUsbStringDescriptor(hHub, port, devDesc.iProduct);

                    if (devDesc.iSerialNumber > 0)
                        serial = ReadUsbStringDescriptor(hHub, port, devDesc.iSerialNumber);

                    Debug.WriteLine($"[USBDescriptorReader] Manufacturer: {manufacturer}");
                    Debug.WriteLine($"[USBDescriptorReader] Product: {product}");
                    Debug.WriteLine($"[USBDescriptorReader] Serial: {serial}");
                    Debug.WriteLine($"[USBDescriptorReader] Device descriptor: bcdUSB=0x{devDesc.bcdUSB:X4}, bcdDevice=0x{devDesc.bcdDevice:X4}, class={devDesc.bDeviceClass}");

                    // 5. Populate fingerprint
                    fingerprint.UsbDeviceClass = devDesc.bDeviceClass;
                    fingerprint.UsbDeviceSubClass = devDesc.bDeviceSubClass;
                    fingerprint.UsbDeviceProtocol = devDesc.bDeviceProtocol;
                    fingerprint.MaxPacketSize0 = devDesc.bMaxPacketSize0;
                    fingerprint.BcdUSB = devDesc.bcdUSB;
                    fingerprint.BcdDevice = devDesc.bcdDevice;
                    fingerprint.NumConfigurations = devDesc.bNumConfigurations;
                    fingerprint.Manufacturer = manufacturer;
                    fingerprint.Description = product;

                    if (!string.IsNullOrEmpty(serial))
                        fingerprint.SerialNumber = serial;

                    // 6. Read configuration descriptor
                    Debug.WriteLine("[USBDescriptorReader] Reading configuration descriptor...");
                    if (!ReadConfigurationDescriptor(hHub, port, out List<USB_INTERFACE_DESCRIPTOR> interfaces,
                                                     out List<USB_ENDPOINT_DESCRIPTOR> endpoints,
                                                     out USB_CONFIGURATION_DESCRIPTOR configDesc))
                    {
                        Debug.WriteLine("[USBDescriptorReader] Failed to read configuration descriptor");
                    }
                    else
                    {
                        fingerprint.NumInterfaces = configDesc.bNumInterfaces;
                        fingerprint.ConfigurationAttributes = configDesc.bmAttributes;
                        fingerprint.MaxPower = configDesc.MaxPower;
                        Debug.WriteLine($"[USBDescriptorReader] Config: {configDesc.bNumInterfaces} interfaces, {endpoints.Count} endpoints");

                        fingerprint.InterfaceDescriptorHash = ComputeDescriptorHash(interfaces);
                        fingerprint.EndpointDescriptorHash = ComputeDescriptorHash(endpoints);
                    }

                    // ===== Read BOS Descriptor =====
                    Debug.WriteLine("[USBDescriptorReader] Reading BOS descriptor...");

                    byte[] bos = ReadBosDescriptor(hHub, port);

                    if (bos != null)
                    {
                        string bosHash = ComputeBosHash(bos);
                        fingerprint.BosHash = bosHash;

                        Debug.WriteLine($"[USBDescriptorReader] BOS Hash: {bosHash}");
                    }
                    else
                    {
                        Debug.WriteLine("[USBDescriptorReader] No BOS descriptor available.");
                    }

                    // 7. Compute final descriptor hash
                    fingerprint.DescriptorHash = ComputeFullDescriptorHash(devDesc, configDesc, interfaces, endpoints);
                    Debug.WriteLine("[USBDescriptorReader] Descriptor hash computed successfully.");

                    return true;
                }
                finally
                {
                    CloseHandle(hHub);
                    Debug.WriteLine("[USBDescriptorReader] Hub handle closed.");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[USBDescriptorReader] Exception: {ex.Message}");
                return false;
            }
        }

        // ===== Hub/port location with diagnostics =====
        private static bool FindHubAndPort(DeviceFingerprint fingerprint, out string hubDevicePath, out uint port)
        {
            hubDevicePath = null;
            port = 0;

            try
            {
                string regPath = $@"SYSTEM\CurrentControlSet\Enum\USB\VID_{fingerprint.Vid}&PID_{fingerprint.Pid}\{fingerprint.InstanceId}";

                Debug.WriteLine($"[FindHubAndPort] Opening registry key: {regPath}");

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath))
                {
                    if (key == null)
                    {
                        Debug.WriteLine("[FindHubAndPort] Registry key not found.");
                        return false;
                    }

                    string location = key.GetValue("LocationInformation")?.ToString();

                    Debug.WriteLine($"[FindHubAndPort] LocationInformation = {location}");

                    if (string.IsNullOrEmpty(location))
                        return false;

                    // Example: Port_#0002.Hub_#0001
                    int portIndex = location.IndexOf("Port_#");
                    if (portIndex < 0)
                        return false;

                    string portString = location.Substring(portIndex + 6, 4);

                    if (!uint.TryParse(portString, out port))
                        return false;

                    Debug.WriteLine($"[FindHubAndPort] Parsed Port={port}");
                }

                // Now enumerate real USB hubs
                Guid hubGuid = new Guid("f18a0e88-c30c-11d0-8815-00a0c906bed8");

                IntPtr deviceInfo = SetupDiGetClassDevs(
                    ref hubGuid,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

                if (deviceInfo == IntPtr.Zero || deviceInfo == new IntPtr(-1))
                {
                    Debug.WriteLine("[FindHubAndPort] SetupDiGetClassDevs failed.");
                    return false;
                }

                try
                {
                    SP_DEVICE_INTERFACE_DATA interfaceData = new SP_DEVICE_INTERFACE_DATA();
                    interfaceData.cbSize = Marshal.SizeOf(interfaceData);

                    if (!SetupDiEnumDeviceInterfaces(deviceInfo, IntPtr.Zero, ref hubGuid, 0, ref interfaceData))
                    {
                        Debug.WriteLine("[FindHubAndPort] No USB hub interfaces found.");
                        return false;
                    }

                    int requiredSize = 0;

                    SetupDiGetDeviceInterfaceDetail(
                        deviceInfo,
                        ref interfaceData,
                        IntPtr.Zero,
                        0,
                        ref requiredSize,
                        IntPtr.Zero);

                    IntPtr detailBuffer = Marshal.AllocHGlobal(requiredSize);

                    try
                    {
                        Marshal.WriteInt32(detailBuffer, IntPtr.Size == 8 ? 8 : 6);

                        if (!SetupDiGetDeviceInterfaceDetail(
                            deviceInfo,
                            ref interfaceData,
                            detailBuffer,
                            requiredSize,
                            ref requiredSize,
                            IntPtr.Zero))
                        {
                            Debug.WriteLine("[FindHubAndPort] Failed to get hub device interface detail.");
                            return false;
                        }

                        IntPtr pDevicePath = IntPtr.Add(detailBuffer, 4);

                        hubDevicePath = Marshal.PtrToStringAuto(pDevicePath);

                        Debug.WriteLine($"[FindHubAndPort] Hub device path = {hubDevicePath}");
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(detailBuffer);
                    }
                }
                finally
                {
                    SetupDiDestroyDeviceInfoList(deviceInfo);
                }

                return !string.IsNullOrEmpty(hubDevicePath);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[FindHubAndPort] Exception: {ex.Message}");
                return false;
            }
        }

        private static string GetParentInstanceId(string childInstanceId)
        {
            try
            {
                string childKeyPath = $@"SYSTEM\CurrentControlSet\Enum\{childInstanceId}";
                Debug.WriteLine($"[GetParentInstanceId] Opening registry key: {childKeyPath}");
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(childKeyPath))
                {
                    if (key != null)
                    {
                        string parentId = key.GetValue("ParentId")?.ToString();
                        Debug.WriteLine($"[GetParentInstanceId] ParentId = {parentId ?? "null"}");
                        return parentId;
                    }
                    else
                    {
                        Debug.WriteLine($"[GetParentInstanceId] Registry key not found: {childKeyPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[GetParentInstanceId] Exception: {ex.Message}");
            }
            return null;
        }

        private static string GetHubDevicePath(string hubInstanceId)
        {
            string[] parts = hubInstanceId.Split('\\');
            if (parts.Length != 3)
            {
                Debug.WriteLine($"[GetHubDevicePath] Invalid hub instance ID: {hubInstanceId}");
                return null;
            }
            string path = $@"\\.\{parts[0]}#{parts[1]}#{parts[2]}#{GUID_DEVINTERFACE_USB_HUB:B}";
            Debug.WriteLine($"[GetHubDevicePath] Hub device path: {path}");
            return path;
        }

        private static uint ExtractPortNumber(string instanceId)
        {
            try
            {
                string keyPath = $@"SYSTEM\CurrentControlSet\Enum\{instanceId}";
                Debug.WriteLine($"[ExtractPortNumber] Opening registry key: {keyPath}");
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        object address = key.GetValue("Address");
                        if (address != null)
                        {
                            uint port = Convert.ToUInt32(address);
                            Debug.WriteLine($"[ExtractPortNumber] Address = {port}");
                            return port;
                        }

                        object locationObj = key.GetValue("LocationInformation");

                        Debug.WriteLine($"[FindHubAndPort] Raw LocationInformation value = {locationObj}");

                        string location = locationObj?.ToString();

                        Debug.WriteLine($"[FindHubAndPort] LocationInformation = {location}");

                        foreach (var valueName in key.GetValueNames())
                        {
                            Debug.WriteLine($"[FindHubAndPort] Registry value: {valueName} = {key.GetValue(valueName)}");
                        }

                        if (!string.IsNullOrEmpty(location))
                        {
                            Debug.WriteLine($"[ExtractPortNumber] LocationInformation = {location}");
                            int portIndex = location.IndexOf("Port_#");
                            if (portIndex >= 0)
                            {
                                string portPart = location.Substring(portIndex + 6, 4);
                                if (uint.TryParse(portPart.TrimStart('#'), out uint p))
                                {
                                    Debug.WriteLine($"[ExtractPortNumber] Parsed port = {p}");
                                    return p;
                                }
                            }
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"[ExtractPortNumber] Registry key not found: {keyPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ExtractPortNumber] Exception: {ex.Message}");
            }
            return 0;
        }

        // ===== The rest of the methods (GetConnectionInfo, ReadDeviceDescriptor, etc.) remain unchanged =====
        // ... (include all the previous helper methods) ...

        // For brevity, I'm not repeating the entire file, but you must keep all the existing helper methods:
        // GetConnectionInfo, ReadDeviceDescriptor, ReadConfigurationDescriptor, ComputeDescriptorHash, ComputeFullDescriptorHash, StructureToBytes.
        // They are already in your code; just leave them as they are.


        // ===== Helper methods for descriptor reading =====

        private static string ComputeBosHash(byte[] bosData)
        {
            if (bosData == null || bosData.Length == 0)
                return null;

            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(bosData);
                return Convert.ToBase64String(hash);
            }
        }
        private static bool GetConnectionInfo(IntPtr hHub, uint port)
        {
            IntPtr inBuffer = IntPtr.Zero;
            IntPtr outBuffer = IntPtr.Zero;

            try
            {
                // Input buffer = just the port number
                inBuffer = Marshal.AllocHGlobal(sizeof(uint));
                Marshal.WriteInt32(inBuffer, (int)port);

                // Output buffer large enough to receive the structure
                int outSize = 512;
                outBuffer = Marshal.AllocHGlobal(outSize);

                bool success = DeviceIoControl(
                    hHub,
                    IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
                    inBuffer,
                    sizeof(uint),
                    outBuffer,
                    outSize,
                    out int bytesReturned,
                    IntPtr.Zero
                );

                if (!success)
                {
                    int err = Marshal.GetLastWin32Error();
                    Debug.WriteLine($"[USBDescriptorReader] DeviceIoControl failed: {err}");
                    return false;
                }

                Debug.WriteLine("[USBDescriptorReader] Connection info retrieved.");
                return true;
            }
            finally
            {
                if (inBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inBuffer);

                if (outBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(outBuffer);
            }
        }

        private static bool ReadDeviceDescriptor(IntPtr hHub, uint port, out USB_DEVICE_DESCRIPTOR desc)
        {
            desc = new USB_DEVICE_DESCRIPTOR();
            int size = Marshal.SizeOf(typeof(USB_DEVICE_DESCRIPTOR));
            int requestSize = Marshal.SizeOf(typeof(USB_DESCRIPTOR_REQUEST));
            IntPtr buffer = Marshal.AllocHGlobal(requestSize + 256);
            try
            {
                USB_DESCRIPTOR_REQUEST request = new USB_DESCRIPTOR_REQUEST
                {
                    ConnectionIndex = port,
                    SetupPacket = new SETUP_PACKET
                    {
                        bmRequest = 0x80,
                        bRequest = 0x06,
                        wValue = (ushort)(0x0100),
                        wIndex = 0,
                        wLength = (ushort)size
                    },
                    Data = new byte[256]
                };
                Marshal.StructureToPtr(request, buffer, false);

                if (DeviceIoControl(hHub, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                                    buffer, requestSize + 256, buffer, requestSize + 256,
                                    out int bytesReturned, IntPtr.Zero))
                {
                    IntPtr descPtr = IntPtr.Add(buffer, Marshal.OffsetOf<USB_DESCRIPTOR_REQUEST>("Data").ToInt32());
                    desc = Marshal.PtrToStructure<USB_DEVICE_DESCRIPTOR>(descPtr);
                    return true;
                }
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string GetFirstUsbHubPath()
        {
            Guid hubGuid = new Guid("f18a0e88-c30c-11d0-8815-00a0c906bed8");

            IntPtr deviceInfo = SetupDiGetClassDevs(
                ref hubGuid,
                IntPtr.Zero,
                IntPtr.Zero,
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

            if (deviceInfo == IntPtr.Zero || deviceInfo == new IntPtr(-1))
                return null;

            SP_DEVICE_INTERFACE_DATA interfaceData = new SP_DEVICE_INTERFACE_DATA();
            interfaceData.cbSize = Marshal.SizeOf(interfaceData);

            if (!SetupDiEnumDeviceInterfaces(deviceInfo, IntPtr.Zero, ref hubGuid, 0, ref interfaceData))
                return null;

            int requiredSize = 0;

            SetupDiGetDeviceInterfaceDetail(
                deviceInfo,
                ref interfaceData,
                IntPtr.Zero,
                0,
                ref requiredSize,
                IntPtr.Zero);

            IntPtr detailBuffer = Marshal.AllocHGlobal(requiredSize);

            Marshal.WriteInt32(detailBuffer, IntPtr.Size == 8 ? 8 : 6);

            if (!SetupDiGetDeviceInterfaceDetail(
                deviceInfo,
                ref interfaceData,
                detailBuffer,
                requiredSize,
                ref requiredSize,
                IntPtr.Zero))
                return null;

            IntPtr pDevicePath = IntPtr.Add(detailBuffer, 4);
            string devicePath = Marshal.PtrToStringAuto(pDevicePath);

            Marshal.FreeHGlobal(detailBuffer);
            SetupDiDestroyDeviceInfoList(deviceInfo);

            return devicePath;
        }

        private static bool ReadConfigurationDescriptor(IntPtr hHub, uint port,
            out List<USB_INTERFACE_DESCRIPTOR> interfaces,
            out List<USB_ENDPOINT_DESCRIPTOR> endpoints,
            out USB_CONFIGURATION_DESCRIPTOR configDesc)
        {
            interfaces = new List<USB_INTERFACE_DESCRIPTOR>();
            endpoints = new List<USB_ENDPOINT_DESCRIPTOR>();
            configDesc = new USB_CONFIGURATION_DESCRIPTOR();

            int configSize = 9;
            int requestSize = Marshal.SizeOf(typeof(USB_DESCRIPTOR_REQUEST));
            IntPtr buffer = Marshal.AllocHGlobal(requestSize + 512);
            try
            {
                // First get the configuration descriptor to know total length
                USB_DESCRIPTOR_REQUEST request = new USB_DESCRIPTOR_REQUEST
                {
                    ConnectionIndex = port,
                    SetupPacket = new SETUP_PACKET
                    {
                        bmRequest = 0x80,
                        bRequest = 0x06,
                        wValue = (ushort)(0x0200),
                        wIndex = 0,
                        wLength = (ushort)configSize
                    },
                    Data = new byte[512]
                };
                Marshal.StructureToPtr(request, buffer, false);

                if (!DeviceIoControl(hHub, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                                     buffer, requestSize + 512, buffer, requestSize + 512,
                                     out int bytesReturned, IntPtr.Zero))
                {
                    return false;
                }

                IntPtr descPtr = IntPtr.Add(buffer, Marshal.OffsetOf<USB_DESCRIPTOR_REQUEST>("Data").ToInt32());
                configDesc = Marshal.PtrToStructure<USB_CONFIGURATION_DESCRIPTOR>(descPtr);
                ushort totalLength = configDesc.wTotalLength;

                // Now read the full configuration descriptor
                request.SetupPacket.wLength = totalLength;
                Marshal.StructureToPtr(request, buffer, false);

                if (!DeviceIoControl(hHub, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                                     buffer, requestSize + totalLength, buffer, requestSize + totalLength,
                                     out bytesReturned, IntPtr.Zero))
                {
                    return false;
                }

                // Parse the concatenated descriptors
                byte[] rawData = new byte[totalLength];
                Marshal.Copy(descPtr, rawData, 0, totalLength);

                int offset = configDesc.bLength;
                while (offset < totalLength)
                {
                    byte descLen = rawData[offset];
                    byte descType = rawData[offset + 1];

                    if (descType == 0x04 && descLen >= 9)
                    {
                        USB_INTERFACE_DESCRIPTOR iface = new USB_INTERFACE_DESCRIPTOR
                        {
                            bLength = rawData[offset],
                            bDescriptorType = rawData[offset + 1],
                            bInterfaceNumber = rawData[offset + 2],
                            bAlternateSetting = rawData[offset + 3],
                            bNumEndpoints = rawData[offset + 4],
                            bInterfaceClass = rawData[offset + 5],
                            bInterfaceSubClass = rawData[offset + 6],
                            bInterfaceProtocol = rawData[offset + 7],
                            iInterface = rawData[offset + 8]
                        };
                        interfaces.Add(iface);
                    }
                    else if (descType == 0x05 && descLen >= 7)
                    {
                        USB_ENDPOINT_DESCRIPTOR ep = new USB_ENDPOINT_DESCRIPTOR
                        {
                            bLength = rawData[offset],
                            bDescriptorType = rawData[offset + 1],
                            bEndpointAddress = rawData[offset + 2],
                            bmAttributes = rawData[offset + 3],
                            wMaxPacketSize = BitConverter.ToUInt16(rawData, offset + 4),
                            bInterval = rawData[offset + 6]
                        };
                        endpoints.Add(ep);
                    }
                    offset += descLen;
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string ComputeDescriptorHash<T>(List<T> descriptors) where T : struct
        {
            if (descriptors == null || descriptors.Count == 0)
                return null;

            using (SHA256 sha = SHA256.Create())
            {
                foreach (var desc in descriptors)
                {
                    byte[] bytes = StructureToBytes(desc);
                    sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return Convert.ToBase64String(sha.Hash).Substring(0, 16);
            }
        }

        private static string ComputeFullDescriptorHash(
            USB_DEVICE_DESCRIPTOR devDesc,

            USB_CONFIGURATION_DESCRIPTOR cfgDesc,
            List<USB_INTERFACE_DESCRIPTOR> ifaces,
            List<USB_ENDPOINT_DESCRIPTOR> endpoints)
        {
            using (SHA256 sha = SHA256.Create())
            {
                sha.TransformBlock(StructureToBytes(devDesc), 0, StructureToBytes(devDesc).Length, null, 0);
                sha.TransformBlock(StructureToBytes(cfgDesc), 0, StructureToBytes(cfgDesc).Length, null, 0);
                foreach (var iface in ifaces)
                    sha.TransformBlock(StructureToBytes(iface), 0, StructureToBytes(iface).Length, null, 0);
                foreach (var ep in endpoints)
                    sha.TransformBlock(StructureToBytes(ep), 0, StructureToBytes(ep).Length, null, 0);
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return Convert.ToBase64String(sha.Hash).Substring(0, 16);
            }
        }

        private static byte[] StructureToBytes<T>(T structure) where T : struct
        {
            int size = Marshal.SizeOf(structure);
            byte[] bytes = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(structure, ptr, false);
                Marshal.Copy(ptr, bytes, 0, size);
                return bytes;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
