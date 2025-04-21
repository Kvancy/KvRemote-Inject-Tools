#pragma once
#include<Windows.h>
#include<iostream>
#include<TlHelp32.h>
#include<ntstatus.h>
typedef LONG (NTAPI* pNtTestAlert)(VOID);

namespace wr3Tool
{
    static DWORD64 GetModuleBase(DWORD64 pid, const char* ModuleName)//采用多字节编码
    {
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (hModuleSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(hModuleSnap, &me32)) {
                do {
                    if (_stricmp(me32.szModule, ModuleName) == 0) {
                        return (DWORD64)me32.modBaseAddr;
                    }
                } while (Module32Next(hModuleSnap, &me32));
            }
            CloseHandle(hModuleSnap);
        }
        return 0;
    }

    static HANDLE FindProcessByName(const char* processName) {//采用多字节编码
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (strcmp(pe.szExeFile, processName) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        return hProcess;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return FALSE;
    }

    static DWORD64 GetPidByProcName(const char* processName) {//采用多字节编码
        HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
        PROCESSENTRY32 pe32 = { 0 };

        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            return 0;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hProcessSnap, &pe32)) {
            do {
                if (strcmp(pe32.szExeFile, processName) == 0) {
                    CloseHandle(hProcessSnap);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
        return 0;
    }
    
    static BOOL RemoteThreadInjectDll(HANDLE hProcess, LPCSTR dllPath) {

        LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (pRemoteDllPath == NULL) {
            int e = GetLastError();
            printf("VirtualAllocEx Failed:[%d]\n", GetLastError());
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
            printf("WriteProcessMemory Failed:[%d]\n", GetLastError());
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            return FALSE;
        }

        LPTHREAD_START_ROUTINE lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpLoadLibrary, pRemoteDllPath, 0, NULL);
        if (hThread == NULL) {
            printf("CreateRemoteThread Failed:[%d]\n", GetLastError());
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            return FALSE;
        }
        WaitForSingleObject(hThread, INFINITE);

        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);

        return TRUE;
    }
    //必须在目标线程处于可警告状态，SleepEx(...,1),wait...等函数
    static BOOL ApcInjectDll(HANDLE hProcess, LPCSTR dllPath) {
        if (hProcess == NULL || dllPath == NULL) {
            std::cerr << "Invalid input parameters." << std::endl;
            return FALSE;
        }

        FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (loadLibraryAddr == NULL) {
            std::cerr << "Failed to get the address of LoadLibraryA. Error code: " << GetLastError() << std::endl;
            return FALSE;
        }

        SIZE_T dllPathLen = strlen(dllPath) + 1;

        LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remoteDllPath == NULL) {
            std::cerr << "Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, dllPathLen, NULL)) {
            std::cerr << "Failed to write DLL path to the target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
            return FALSE;
        }

        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create thread snapshot. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
            return FALSE;
        }

        THREADENTRY32 threadEntry;
        threadEntry.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hThreadSnapshot, &threadEntry)) {
            do {
                if (threadEntry.th32OwnerProcessID == GetProcessId(hProcess)) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
                    if (hThread != NULL) {
                        QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)remoteDllPath);//用户层只需要该函数APC注入
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &threadEntry));
        }

        CloseHandle(hThreadSnapshot);
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);

        return TRUE;
    }

    static BOOL ReflectiveInjectDll(HANDLE hProcess, BYTE* shellCode,DWORD size) {
        //BYTE shellCode[] = {0x31, 0xC0, 0x40, 0x83, 0xC0, 0x02, 0xEB, 0xFA};
        LPVOID shellCodeAddr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (shellCodeAddr == NULL) {
            std::cerr << "Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, shellCodeAddr, shellCode, size, NULL)) {
            std::cerr << "Failed to write shellcode to the target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, shellCodeAddr, 0, MEM_RELEASE);
            return FALSE;
        }
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellCodeAddr, NULL, 0, NULL);
        if (hThread == NULL) return FALSE;
        CloseHandle(hThread);
        return TRUE;
    }

    
    static BOOL RepairVirtualProtect(HANDLE hProcess)//修复ntProtectVirtualMemory hook
    {
        //计算ZwProtectVirtualMemory函数在模块内的偏移
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        if (hNtdll == NULL) {
      
            return false;
        }
        DWORD64 pZwProtectVirtualMemory = (DWORD64)GetProcAddress(hNtdll, "ZwProtectVirtualMemory");
        if (pZwProtectVirtualMemory == NULL) {
            FreeLibrary(hNtdll);
            return false;
        }
        DWORD64 offset = pZwProtectVirtualMemory - GetModuleBase(GetCurrentProcessId(), "ntdll.dll");
        //ntProtectVirtualMemory hex code
        uint8_t originCode[] = {
        0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,
        0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, 0x2E, 0xC3
        };
        
        DWORD64 pid = GetProcessId(hProcess);
        DWORD64 ntdllBase = GetModuleBase(pid, "ntdll.dll");
        DWORD64 funcAddr =  offset + ntdllBase;
        DWORD oldProtect = 0;
        //写入内存修复hook
        if (!VirtualProtectEx(hProcess, (LPVOID)funcAddr, sizeof(originCode), PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;
        if (!WriteProcessMemory(hProcess, (LPVOID)funcAddr, originCode, sizeof(originCode), NULL))
            return false;

        return TRUE;
    }

    static BOOL EnableDebugPrivilege() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return FALSE;

        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
            return FALSE;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            return FALSE;

        CloseHandle(hToken);
        return TRUE;
    }

}


