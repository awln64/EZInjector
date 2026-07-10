#include "ProcessUtils.h"
#include <TlHelp32.h>
#include <algorithm>
#include <cstdio>
#include <Commdlg.h>

namespace Utils {

    HANDLE OpenKernelDriverHandle() {
        // Try both device paths — the driver must already be loaded
        const char* paths[] = { "\\\\.\\EZInjectorKernel", "\\\\.\\Global\\EZInjectorKernel" };

        for (const char* path : paths) {
            HANDLE h = CreateFileA(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (h != INVALID_HANDLE_VALUE) {
                return h;
            }
        }
        return INVALID_HANDLE_VALUE;
    }

    std::vector<ProcessInfo> GetProcessList() {
        std::vector<ProcessInfo> processList;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                do {
                    ProcessInfo info;
                    info.pid = pe32.th32ProcessID;

#ifdef UNICODE
                    char buffer[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, buffer, MAX_PATH, NULL, NULL);
                    info.name = buffer;
#else
                    info.name = pe32.szExeFile;
#endif
                    char displayBuf[512];
                    snprintf(displayBuf, sizeof(displayBuf), "%s (PID: %lu)", info.name.c_str(), info.pid);
                    info.displayName = displayBuf;

                    processList.push_back(info);
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        std::sort(processList.begin(), processList.end(),
            [](const ProcessInfo& a, const ProcessInfo& b) {
                return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
            });
        
        return processList;
    }

    DWORD GetTargetThreadId(DWORD pid) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE)
            return 0;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        DWORD tid = 0;

        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    tid = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(hSnap, &te));
        }

        CloseHandle(hSnap);
        return tid;
    }

    std::vector<DWORD> GetTargetThreadIds(DWORD pid) {
        std::vector<DWORD> threads;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE)
            return threads;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    threads.push_back(te.th32ThreadID);
                }
            } while (Thread32Next(hSnap, &te));
        }

        CloseHandle(hSnap);
        return threads;
    }

    std::string OpenFileDialog(const char* filter, HWND owner) {
        OPENFILENAMEA ofn;
        char szFile[MAX_PATH] = { 0 };
        ZeroMemory(&ofn, sizeof(ofn));

        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = owner;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = filter;
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

        if (GetOpenFileNameA(&ofn) == TRUE) {
            return std::string(ofn.lpstrFile);
        }
        return "";
    }

}
