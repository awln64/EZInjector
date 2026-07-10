#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace Utils {

    struct ProcessInfo {
        DWORD pid;
        std::string name;
        std::string displayName;
    };

    std::vector<ProcessInfo> GetProcessList();
    DWORD GetTargetThreadId(DWORD pid);
    std::vector<DWORD> GetTargetThreadIds(DWORD pid);
    HANDLE OpenKernelDriverHandle();
    std::string OpenFileDialog(const char* filter, HWND owner);

}
