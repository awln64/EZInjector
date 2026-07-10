#include "KernelManualMapInjector.h"
#include <windows.h>
#include "../../EZInjectorKernel/Communication.h"
#include "../Utils/ProcessUtils.h"

namespace Injection {

    KernelManualMapInjector::KernelManualMapInjector(const Options& options) : m_options(options) {}

    InjectionResult KernelManualMapInjector::Inject(DWORD targetPid, const std::string& dllPath) {
        HANDLE hDevice = Utils::OpenKernelDriverHandle();

        if (hDevice == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            return InjectionResult::Failure("Could not open handle to EZInjectorKernel driver (\\\\.\\EZInjectorKernel). Ensure EZInjectorKernel.sys is built/loaded or run EZInjector as Administrator.", err);
        }

        KERNEL_MANUAL_MAP_REQUEST request = {};
        request.TargetPid = targetPid;
        request.TargetThreadId = Utils::GetTargetThreadId(targetPid);
        strncpy_s(request.DllPath, sizeof(request.DllPath), dllPath.c_str(), _TRUNCATE);
        request.LinkPeb = m_options.linkPeb;
        request.ErasePe = m_options.erasePe;
        request.ResolveImports = m_options.resolveImports;
        request.IgnoreTls = m_options.ignoreTls;
        request.ConcealMem = m_options.concealMem;
        request.NoExceptions = m_options.noExceptions;

        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_EZI_KERNEL_MANUAL_MAP,
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
            return InjectionResult::Failure("DeviceIoControl (IOCTL_EZI_KERNEL_MANUAL_MAP) failed in kernel mode.", err);
        }

        return InjectionResult::Success("Kernel manual mapping completed successfully.");
    }
}
