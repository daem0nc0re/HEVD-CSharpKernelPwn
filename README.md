# HackSys Extreme Vulnerable Driver Writeups with CSharp
My writeups for [HackSys Exreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).
All writeups are written with CSharp (except for DLL).
Tested on following OS:

* [Windows 7 SP1 x86](./HEVD_Win7x86)
* [Windows 10 Version 1903 x64](./HEVD_Win10x64)

## Description
### Windows 7 SP1 x86
To build codes, open [HEVD_Win7x86.sln](./HEVD_Win7x86/HEVD_Win7x86.sln) and run build. All codes are generated in `bin` folder under the home directory.

| Project Name| Description |
| :--- | :--- |
| [DoubleFetch](./HEVD_Win7x86/DoubleFetch) | Writeup for Double Fetch vulnerability. Multiple CPU core required. |
| [InjectLib](./HEVD_Win7x86/InjectLib) | Sample DLL for Insecure Kernel Resource Access vulnerability. This DLL attempts to add `hevdtest` user with password `Password123!` and add `hevdtest` to `Administrators` group. |
| [InsecureKernelResourceAccess](./HEVD_Win7x86/InsecureKernelResourceAccess) | Writeup for Insecure Kernel Resource Access vulnerability. DLL for DLL Hijacking is required. |
| [IntegerOverflow](./HEVD_Win7x86/IntegerOverflow) | Writeup for Integer Overflow vulnerablity. |
| [NullPointerDereference](./HEVD_Win7x86/NullPointerDereference) | Writeup for Null Pointer Dereference vulnerablity. |
| [PoolOverflow](./HEVD_Win7x86/PoolOverflow) | Writeup for Pool Overflow vulnerablity. |
| [StackOverflow](./HEVD_Win7x86/StackOverflow) | Writeup for Stack Overflow vulnerablity. |
| [StackOverflowGS](./HEVD_Win7x86/StackOverflowGS) | Writeup for Stack Overflow vulnerablity with Stach Canary. |
| [TypeConfusion](./HEVD_Win7x86/TypeConfusion) | Writeup for Type Confusion vulnerablity. |
| [UninitializedHeapVariable](./HEVD_Win7x86/UninitializedHeapVariable) | Writeup for Uninitialized Heap Variable vulnerablity. |
| [UninitializedStackVariable](./HEVD_Win7x86/UninitializedStackVariable) | Writeup for Uninitialized Stack Variable vulnerablity. |
| [UseAfterFree](./HEVD_Win7x86/UseAfterFree) | Writeup for Use-After-Free vulnerablity. |
| [WriteNull](./HEVD_Win7x86/WriteNull) | Writeup for Write NULL vulnerablity. |
| [WriteWhatWhere](./HEVD_Win7x86/WriteWhatWhere) | Writeup for Arbitrary Overwrite vulnerablity. |
| [WriteWhatWhereGDI](./HEVD_Win7x86/WriteWhatWhereGDI) | Writeup for Arbitrary Overwrite vulnerablity with GDI memory leak. |

### Windows 10 Version 1903 x64
To build codes, open [HEVD_Win10x64.sln](./HEVD_Win10x64/HEVD_Win10x64.sln) and run build. All codes are generated in `bin` folder under the home directory.

| Project Name| Description |
| :--- | :--- |
| [ArbitraryReadWrite](./HEVD_Win10x64/ArbitraryReadWrite) | Writeup for Arbitrary Read and Write vulnerablity. |
| [ArbitraryWrite](./HEVD_Win10x64/ArbitraryWrite) | Writeup for Arbitrary Overwrite vulnerablity. |
| [InjectLib](./HEVD_Win10x64/InjectLib) | Sample DLL for Insecure Kernel Resource Access vulnerability. This DLL attempts to add `hevdtest` user with password `Password123!` and add `hevdtest` to `Administrators` group. |
| [InsecureKernelResourceAccess](./HEVD_Win10x64/InsecureKernelResourceAccess) | Writeup for Insecure Kernel Resource Access vulnerability. DLL for DLL Hijacking is required. |

## Acknowledgments
* HackSys Team ([@HackSysTeam](https://twitter.com/HackSysTeam))
* b33f ([@FuzzySec](https://twitter.com/FuzzySec))
