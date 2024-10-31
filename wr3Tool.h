#pragma once
#include<Windows.h>
#include<iostream>
#include<TlHelp32.h>
#include <ntstatus.h>
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
    
    static BOOL InjectDll(HANDLE hProcess, LPCSTR dllPath) {

        // 在目标进程中分配内存
        LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (pRemoteDllPath == NULL) {
            int e = GetLastError();
            printf("VirtualAllocEx Failed:[%d]\n", GetLastError());
            return FALSE;
        }

        // 将DLL路径写入目标进程的内存
        if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
            printf("WriteProcessMemory Failed:[%d]\n", GetLastError());
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            return FALSE;
        }

        // 获取LoadLibraryA函数的地址
        LPTHREAD_START_ROUTINE lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        // 创建远程线程执行LoadLibrary
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpLoadLibrary, pRemoteDllPath, 0, NULL);
        if (hThread == NULL) {
            printf("CreateRemoteThread Failed:[%d]\n", GetLastError());
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            return FALSE;
        }

        // 等待远程线程执行完成
        WaitForSingleObject(hThread, INFINITE);

        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);

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


}


