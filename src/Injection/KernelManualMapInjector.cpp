#include "KernelManualMapInjector.h"
#include <windows.h>
#include <iostream>
#include "../../EZInjectorKernel/Communication.h"

namespace Injection {

    KernelManualMapInjector::KernelManualMapInjector(bool linkPeb, bool erasePe, bool resolveImports, bool ignoreTls, bool concealMem, bool noExceptions)
        : m_linkPeb(linkPeb), m_erasePe(erasePe), m_resolveImports(resolveImports), m_ignoreTls(ignoreTls), m_concealMem(concealMem), m_noExceptions(noExceptions) {
    }

    bool KernelManualMapInjector::Inject(DWORD targetPid, const std::string& dllPath) {
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
            std::cerr << "[KernelManualMapInjector] Could not open handle to EZInjectorKernel driver. Error: " << GetLastError() << std::endl;
            return false;
        }

        KERNEL_MANUAL_MAP_REQUEST request = {};
        request.TargetPid = targetPid;
        strncpy_s(request.DllPath, sizeof(request.DllPath), dllPath.c_str(), _TRUNCATE);
        request.LinkPeb = m_linkPeb;
        request.ErasePe = m_erasePe;
        request.ResolveImports = m_resolveImports;
        request.IgnoreTls = m_ignoreTls;
        request.ConcealMem = m_concealMem;
        request.NoExceptions = m_noExceptions;

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
            std::cerr << "[KernelManualMapInjector] DeviceIoControl failed. Error: " << GetLastError() << std::endl;
            return false;
        }

        return true;
    }

}
