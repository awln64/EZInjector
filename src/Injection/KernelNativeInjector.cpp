#include "KernelNativeInjector.h"
#include <windows.h>
#include <iostream>
#include "../../EZInjectorKernel/Communication.h"
#include "../Utils/ProcessUtils.h"

namespace Injection {

    InjectionResult KernelNativeInjector::Inject(DWORD targetPid, const std::string& dllPath) {
        HANDLE hDevice = Utils::OpenKernelDriverHandle();

        if (hDevice == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::cerr << "[KernelNativeInjector] Could not open handle to EZInjectorKernel driver. Error: " << err << std::endl;
            return InjectionResult::Failure("Could not open handle to EZInjectorKernel driver (\\\\.\\EZInjectorKernel). Ensure EZInjectorKernel.sys is built/loaded or run EZInjector as Administrator.", err);
        }

        KERNEL_NATIVE_INJECT_REQUEST request = {};
        request.TargetPid = targetPid;
        request.TargetThreadId = Utils::GetTargetThreadId(targetPid);
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
            DWORD err = GetLastError();
            std::cerr << "[KernelNativeInjector] DeviceIoControl failed. Error: " << err << std::endl;
            return InjectionResult::Failure("DeviceIoControl (IOCTL_EZI_KERNEL_NATIVE_INJECT) failed in kernel mode.", err);
        }

        return InjectionResult::Success("Kernel native injection completed successfully.");
    }

}
