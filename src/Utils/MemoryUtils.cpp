#include "MemoryUtils.h"
#include "NtStructs.h"

namespace Utils {

    bool UnlinkModuleFromPEB(HANDLE hProcess, HMODULE hModule) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll)
            return false;

        auto NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInfo)
            return false;

        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        if (NtQueryInfo(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) != 0)
            return false;

        PEB peb;
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr))
            return false;

        FULL_PEB_LDR_DATA ldrData;
        if (!ReadProcessMemory(hProcess, peb.Ldr, &ldrData, sizeof(ldrData), nullptr))
            return false;

        BYTE* pLdrAddr = (BYTE*)peb.Ldr;
        LIST_ENTRY* pRemoteListHead = (LIST_ENTRY*)(pLdrAddr + offsetof(FULL_PEB_LDR_DATA, InLoadOrderModuleList));

        LIST_ENTRY currentListEntry;
        LIST_ENTRY* pCurrentNode = ldrData.InLoadOrderModuleList.Flink;
        if (!ReadProcessMemory(hProcess, pCurrentNode, &currentListEntry, sizeof(currentListEntry), nullptr)) {
            return false;
        }

        int maxIterations = 4096;
        while (pCurrentNode != pRemoteListHead && maxIterations-- > 0) {
            LDR_DATA_TABLE_ENTRY_COMPLETED entry;
            if (ReadProcessMemory(hProcess, pCurrentNode, &entry, sizeof(entry), nullptr)) {
                if (entry.DllBase == (PVOID)hModule) {

                    auto UnlinkList = [&](LIST_ENTRY& list) -> bool {
                        LIST_ENTRY prev, next;
                        if (!ReadProcessMemory(hProcess, list.Blink, &prev, sizeof(prev), nullptr))
                            return false;
                        if (!ReadProcessMemory(hProcess, list.Flink, &next, sizeof(next), nullptr))
                            return false;

                        prev.Flink = list.Flink;
                        next.Blink = list.Blink;

                        if (!WriteProcessMemory(hProcess, list.Blink, &prev, sizeof(prev), nullptr))
                            return false;
                        if (!WriteProcessMemory(hProcess, list.Flink, &next, sizeof(next), nullptr))
                            return false;
                        return true;
                    };

                    bool ok = true;
                    ok = UnlinkList(entry.InLoadOrderLinks) && ok;
                    ok = UnlinkList(entry.InMemoryOrderLinks) && ok;
                    ok = UnlinkList(entry.InInitializationOrderLinks) && ok;

                    return ok;
                }
            }

            pCurrentNode = currentListEntry.Flink;
            if (!ReadProcessMemory(hProcess, pCurrentNode, &currentListEntry, sizeof(currentListEntry), nullptr)) {
                break;
            }
        }

        return false;
    }

    void ErasePEHeaders(HANDLE hProcess, HMODULE hModule) {
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, (PVOID)hModule, &dosHeader, sizeof(dosHeader), nullptr)) {
            return;
        }

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            return;
        }

        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)hModule + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr)) {
            return;
        }

        DWORD sizeOfHeaders = ntHeaders.OptionalHeader.SizeOfHeaders;

        std::vector<BYTE> emptyBuffer(sizeOfHeaders, 0);

        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (PVOID)hModule, sizeOfHeaders, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteProcessMemory(hProcess, (PVOID)hModule, emptyBuffer.data(), sizeOfHeaders, nullptr);
            VirtualProtectEx(hProcess, (PVOID)hModule, sizeOfHeaders, oldProtect, &oldProtect);
        }
    }

    bool LinkModuleToPEB(HANDLE hProcess, BYTE* pRemoteBase, const std::string& dllPath, DWORD sizeOfImage) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

        if (!hNtdll) return false;

        auto NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInfo) return false;

        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        if (NtQueryInfo(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) != 0) return false;

        PEB peb;
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) return false;

        FULL_PEB_LDR_DATA ldrData;
        if (!ReadProcessMemory(hProcess, peb.Ldr, &ldrData, sizeof(ldrData), nullptr)) return false;

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, dllPath.c_str(), -1, nullptr, 0);
        std::vector<wchar_t> widePath(wideLen);

        MultiByteToWideChar(CP_UTF8, 0, dllPath.c_str(), -1, widePath.data(), wideLen);
        DWORD wideByteLen = (wideLen - 1) * sizeof(wchar_t);

        std::wstring fullPath(widePath.data());
        size_t slashPos = fullPath.find_last_of(L"\\/");
        std::wstring baseName = (slashPos != std::wstring::npos) ? fullPath.substr(slashPos + 1) : fullPath;

        SIZE_T allocSize = sizeof(LDR_DATA_TABLE_ENTRY_COMPLETED) + (wideByteLen + 2) + ((baseName.length() * sizeof(wchar_t)) + 2);
        BYTE* pRemoteMem = (BYTE*)VirtualAllocEx(hProcess, nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemoteMem) return false;

        BYTE* pRemoteFullDll = pRemoteMem + sizeof(LDR_DATA_TABLE_ENTRY_COMPLETED);
        BYTE* pRemoteBaseDll = pRemoteFullDll + wideByteLen + 2;

        if (!WriteProcessMemory(hProcess, pRemoteFullDll, fullPath.c_str(), wideByteLen + 2, nullptr) ||
            !WriteProcessMemory(hProcess, pRemoteBaseDll, baseName.c_str(), (baseName.length() * sizeof(wchar_t)) + 2, nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        LDR_DATA_TABLE_ENTRY_COMPLETED entry = {};
        entry.DllBase = pRemoteBase;
        entry.EntryPoint = nullptr;
        entry.SizeOfImage = sizeOfImage;
        entry.FullDllName.Length = (USHORT)wideByteLen;
        entry.FullDllName.MaximumLength = (USHORT)(wideByteLen + 2);
        entry.FullDllName.Buffer = (PWSTR)pRemoteFullDll;
        entry.BaseDllName.Length = (USHORT)(baseName.length() * sizeof(wchar_t));
        entry.BaseDllName.MaximumLength = (USHORT)(baseName.length() * sizeof(wchar_t) + 2);
        entry.BaseDllName.Buffer = (PWSTR)pRemoteBaseDll;

        LIST_ENTRY* pRemoteEntry = (LIST_ENTRY*)pRemoteMem;

        BYTE* pLdrAddr = (BYTE*)peb.Ldr;
        LIST_ENTRY* pListHead = (LIST_ENTRY*)(pLdrAddr + offsetof(FULL_PEB_LDR_DATA, InLoadOrderModuleList));

        LIST_ENTRY headEntry;
        if (!ReadProcessMemory(hProcess, pListHead, &headEntry, sizeof(headEntry), nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        entry.InLoadOrderLinks.Flink = pListHead;
        entry.InLoadOrderLinks.Blink = headEntry.Blink;

        LIST_ENTRY* pRemoteMemOrder = (LIST_ENTRY*)(pRemoteMem + offsetof(LDR_DATA_TABLE_ENTRY_COMPLETED, InMemoryOrderLinks));
        LIST_ENTRY* pMemOrderHead = (LIST_ENTRY*)(pLdrAddr + offsetof(FULL_PEB_LDR_DATA, InMemoryOrderModuleList));
        LIST_ENTRY memHead;

        if (!ReadProcessMemory(hProcess, pMemOrderHead, &memHead, sizeof(memHead), nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        entry.InMemoryOrderLinks.Flink = pMemOrderHead;
        entry.InMemoryOrderLinks.Blink = memHead.Blink;

        LIST_ENTRY* pRemoteInitOrder = (LIST_ENTRY*)(pRemoteMem + offsetof(LDR_DATA_TABLE_ENTRY_COMPLETED, InInitializationOrderLinks));
        LIST_ENTRY* pInitOrderHead = (LIST_ENTRY*)(pLdrAddr + offsetof(FULL_PEB_LDR_DATA, InInitializationOrderModuleList));
        LIST_ENTRY initHead;
        if (!ReadProcessMemory(hProcess, pInitOrderHead, &initHead, sizeof(initHead), nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        entry.InInitializationOrderLinks.Flink = pInitOrderHead;
        entry.InInitializationOrderLinks.Blink = initHead.Blink;

        if (!WriteProcessMemory(hProcess, pRemoteMem, &entry, sizeof(entry), nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        LIST_ENTRY oldTail;
        if (!ReadProcessMemory(hProcess, headEntry.Blink, &oldTail, sizeof(oldTail), nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }
        oldTail.Flink = pRemoteEntry;
        if (!WriteProcessMemory(hProcess, headEntry.Blink, &oldTail, sizeof(oldTail), nullptr)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            return false;
        }

        headEntry.Blink = pRemoteEntry;
        WriteProcessMemory(hProcess, pListHead, &headEntry, sizeof(headEntry), nullptr);

        LIST_ENTRY oldMemTail;
        ReadProcessMemory(hProcess, memHead.Blink, &oldMemTail, sizeof(oldMemTail), nullptr);

        oldMemTail.Flink = pRemoteMemOrder;
        WriteProcessMemory(hProcess, memHead.Blink, &oldMemTail, sizeof(oldMemTail), nullptr);

        memHead.Blink = pRemoteMemOrder;
        WriteProcessMemory(hProcess, pMemOrderHead, &memHead, sizeof(memHead), nullptr);

        LIST_ENTRY oldInitTail;
        ReadProcessMemory(hProcess, initHead.Blink, &oldInitTail, sizeof(oldInitTail), nullptr);

        oldInitTail.Flink = pRemoteInitOrder;
        WriteProcessMemory(hProcess, initHead.Blink, &oldInitTail, sizeof(oldInitTail), nullptr);

        initHead.Blink = pRemoteInitOrder;
        WriteProcessMemory(hProcess, pInitOrderHead, &initHead, sizeof(initHead), nullptr);
        return true;
    }

    DWORD GetSectionProtection(DWORD characteristics) {
        DWORD protect = PAGE_NOACCESS;
        bool exec = characteristics & IMAGE_SCN_MEM_EXECUTE;
        bool read = characteristics & IMAGE_SCN_MEM_READ;
        bool write = characteristics & IMAGE_SCN_MEM_WRITE;
        if (exec) {
            if (write) {
                protect = PAGE_EXECUTE_READWRITE;
            }
            else if (read) {
                protect = PAGE_EXECUTE_READ;
            }
            else {
                protect = PAGE_EXECUTE;
            }
        }
        else {
            if (write) {
                protect = PAGE_READWRITE;
            }
            else if (read) {
                protect = PAGE_READONLY;
            }
            else {
                protect = PAGE_NOACCESS;
            }
        }
        return protect;
    }

    void ConcealMemory(HANDLE hProcess, BYTE* pRemoteBase, IMAGE_NT_HEADERS* pNt, IMAGE_SECTION_HEADER* pSections) {
        if (!pRemoteBase || !pNt || !pSections) return;

        DWORD oldProtect;
        VirtualProtectEx(hProcess, pRemoteBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            DWORD size = pSections[i].Misc.VirtualSize;
            if (size == 0)
                continue;
            DWORD protect = GetSectionProtection(pSections[i].Characteristics);
            VirtualProtectEx(hProcess, pRemoteBase + pSections[i].VirtualAddress, size, protect, &oldProtect);
        }

        if (pNt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            auto& relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.VirtualAddress && relocDir.Size) {
                std::vector<BYTE> zeros(relocDir.Size, 0);

                VirtualProtectEx(hProcess, pRemoteBase + relocDir.VirtualAddress, relocDir.Size, PAGE_READWRITE, &oldProtect);
                WriteProcessMemory(hProcess, pRemoteBase + relocDir.VirtualAddress, zeros.data(), relocDir.Size, nullptr);
                DWORD sectionProt = PAGE_READONLY;

                for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                    if (pSections[i].VirtualAddress <= relocDir.VirtualAddress && relocDir.VirtualAddress < pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize) {
                        sectionProt = GetSectionProtection(pSections[i].Characteristics);
                        break;
                    }
                }

                VirtualProtectEx(hProcess, pRemoteBase + relocDir.VirtualAddress, relocDir.Size, sectionProt, &oldProtect);
            }
        }
    }

}
