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
    std::string OpenFileDialog(const char* filter, HWND owner);

}
