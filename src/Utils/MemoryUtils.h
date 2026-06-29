#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace Utils {

    bool UnlinkModuleFromPEB(HANDLE hProcess, HMODULE hModule);
    void ErasePEHeaders(HANDLE hProcess, HMODULE hModule);
    bool LinkModuleToPEB(HANDLE hProcess, BYTE* pRemoteBase, const std::string& dllPath, DWORD sizeOfImage);
    void ConcealMemory(HANDLE hProcess, BYTE* pRemoteBase, IMAGE_NT_HEADERS* pNt, IMAGE_SECTION_HEADER* pSections);
    DWORD GetSectionProtection(DWORD characteristics);

}
