#include "KernelNativeInjector.h"
#include <windows.h>
#include <iostream>
#include "../../EZInjectorKernel/Communication.h"

namespace Injection {

    bool KernelNativeInjector::Inject(DWORD targetPid, const std::string& dllPath) {
        HANDLE hDevice = CreateFileA(
            "\\\\.\\EZInjectorKernel",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cerr << "[KernelNativeInjector] Could not open handle to EZInjectorKernel driver. Error: " << GetLastError() << std::endl;
            return false;
        }

        KERNEL_NATIVE_INJECT_REQUEST request = {};
        request.TargetPid = targetPid;
        strncpy_s(request.DllPath, sizeof(request.DllPath), dllPath.c_str(), _TRUNCATE);

        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_EZI_KERNEL_NATIVE_INJECT,
            &request,
            sizeof(request),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        CloseHandle(hDevice);

        if (!success) {
            std::cerr << "[KernelNativeInjector] DeviceIoControl failed. Error: " << GetLastError() << std::endl;
            return false;
        }

        return true;
    }

}
