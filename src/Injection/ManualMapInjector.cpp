#include "ManualMapInjector.h"
#include "../Utils/MemoryUtils.h"
#include <fstream>
#include <vector>

namespace Injection {

#pragma runtime_checks("", off)
#pragma optimize("ts", on)
    static DWORD WINAPI ManualMapShellcode(ManualMapData* pData) {
        if (!pData)
            return 0;
        BYTE* pBase = pData->ImageBase;
        pData->Success = FALSE;

        // 1. Process base relocations
        if (pData->RelocationDelta && pData->pBaseReloc) {
            IMAGE_BASE_RELOCATION* pReloc = pData->pBaseReloc;
            while (pReloc->VirtualAddress) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pEntries = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    int type = pEntries[i] >> 12;
                    int offset = pEntries[i] & 0xFFF;
                    BYTE* pPatch = pBase + pReloc->VirtualAddress + offset;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONGLONG*)pPatch += pData->RelocationDelta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD*)pPatch += (DWORD)pData->RelocationDelta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGH) {
                        *(WORD*)pPatch += HIWORD((DWORD)pData->RelocationDelta);
                    }
                    else if (type == IMAGE_REL_BASED_LOW) {
                        *(WORD*)pPatch += LOWORD((DWORD)pData->RelocationDelta);
                    }
                }
                pReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }

        // 2. Resolve imports
        if (pData->ResolveImports && pData->pImportDesc) {
            IMAGE_IMPORT_DESCRIPTOR* pImport = pData->pImportDesc;

            while (pImport->Name) {
                char* szModule = (char*)(pBase + pImport->Name);
                HMODULE hMod = pData->fnLoadLibraryA(szModule);

                if (!hMod) return 0;

                IMAGE_THUNK_DATA* pOrigThunk = pImport->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)(pBase + pImport->OriginalFirstThunk) : (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);
                IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(pBase + pImport->FirstThunk);

                while (pOrigThunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL64(pOrigThunk->u1.Ordinal)) {
                        pThunk->u1.Function = (ULONGLONG)pData->fnGetProcAddress(hMod, (char*)IMAGE_ORDINAL64(pOrigThunk->u1.Ordinal));
                    }
                    else {
                        IMAGE_IMPORT_BY_NAME* pName = (IMAGE_IMPORT_BY_NAME*)(pBase + pOrigThunk->u1.AddressOfData);
                        pThunk->u1.Function = (ULONGLONG)pData->fnGetProcAddress(hMod, pName->Name);
                    }
                    if (!pThunk->u1.Function) return 0;

                    pOrigThunk++;
                    pThunk++;
                }
                pImport++;
            }
        }

        // 3. Handle TLS callbacks
        if (!pData->IgnoreTls && pData->pTlsDir) {
            PIMAGE_TLS_CALLBACK* ppCallback = (PIMAGE_TLS_CALLBACK*)pData->pTlsDir->AddressOfCallBacks;
            if (ppCallback) {
                while (*ppCallback) {
                    (*ppCallback)((PVOID)pBase, DLL_PROCESS_ATTACH, nullptr);
                    ppCallback++;
                }
            }
        }

        // 4. Register exception handlers
        if (!pData->NoExceptions && pData->pExceptionDir && pData->ExceptionSize) {
            pData->fnRtlAddFunctionTable(
                pData->pExceptionDir,
                pData->ExceptionSize / sizeof(RUNTIME_FUNCTION), (DWORD64)pBase);
        }

        // 5. Call DllMain
        if (pData->EntryPoint) {
            typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);
            DllMain_t pDllMain = (DllMain_t)pData->EntryPoint;
            pDllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, nullptr);
        }

        pData->Success = TRUE;
        return 1;
    }

    static DWORD WINAPI ManualMapShellcodeEnd() { return 0; }

#pragma runtime_checks("", restore)
#pragma optimize("", on)

    ManualMapInjector::ManualMapInjector(const Options& options) : m_options(options) {}

    bool ManualMapInjector::Inject(DWORD pid, const std::string& dllPath) {
        // 1. Read DLL file
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;

        size_t fileSize = (size_t)file.tellg();
        if (fileSize < sizeof(IMAGE_DOS_HEADER)) return false;

        file.seekg(0, std::ios::beg);
        std::vector<BYTE> fileData(fileSize);

        file.read((char*)fileData.data(), fileSize);
        file.close();

        // 2. Parse and validate PE
        IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)fileData.data();
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(fileData.data() + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

        if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

        // 3. Open target process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;

        // 4. Allocate memory in target for the image
        BYTE* pRemoteBase = (BYTE*)VirtualAllocEx(hProcess, nullptr, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteBase) {
            CloseHandle(hProcess);
            return false;
        }

        // 5. Copy PE headers
        WriteProcessMemory(hProcess, pRemoteBase, fileData.data(), pNt->OptionalHeader.SizeOfHeaders, nullptr);

        // 6. Copy sections
        IMAGE_SECTION_HEADER* pSections = IMAGE_FIRST_SECTION(pNt);
        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (pSections[i].SizeOfRawData == 0)
                continue;
            WriteProcessMemory(hProcess, pRemoteBase + pSections[i].VirtualAddress, fileData.data() + pSections[i].PointerToRawData, pSections[i].SizeOfRawData, nullptr);
        }

        // 7. Prepare ManualMapData
        ManualMapData mapData = {};
        mapData.ImageBase = pRemoteBase;
        mapData.RelocationDelta = (ULONGLONG)pRemoteBase - pNt->OptionalHeader.ImageBase;
        auto& relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress && relocDir.Size) {
            mapData.pBaseReloc = (IMAGE_BASE_RELOCATION*)(pRemoteBase + relocDir.VirtualAddress);
        }

        auto& importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress && importDir.Size) {
            mapData.pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pRemoteBase + importDir.VirtualAddress);
        }

        auto& tlsDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            mapData.pTlsDir = (IMAGE_TLS_DIRECTORY*)(pRemoteBase + tlsDir.VirtualAddress);
        }

        auto& exceptDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exceptDir.VirtualAddress && exceptDir.Size) {
            mapData.pExceptionDir = (RUNTIME_FUNCTION*)(pRemoteBase + exceptDir.VirtualAddress);
            mapData.ExceptionSize = exceptDir.Size;
        }
        if (pNt->OptionalHeader.AddressOfEntryPoint) {
            mapData.EntryPoint = pRemoteBase + pNt->OptionalHeader.AddressOfEntryPoint;
        }

        mapData.fnLoadLibraryA = LoadLibraryA;
        mapData.fnGetProcAddress = GetProcAddress;
        mapData.fnRtlAddFunctionTable = RtlAddFunctionTable;
        mapData.ResolveImports = m_options.resolveImports ? TRUE : FALSE;
        mapData.IgnoreTls = m_options.ignoreTls ? TRUE : FALSE;
        mapData.NoExceptions = m_options.noExceptions ? TRUE : FALSE;
        mapData.Success = FALSE;

        // 8. Determine shellcode size and handle debug JMP stubs
        BYTE* pShellcodeFunc = (BYTE*)ManualMapShellcode;

#ifdef _DEBUG
        if (*pShellcodeFunc == 0xE9) {
            pShellcodeFunc = pShellcodeFunc + 5 + *(int*)(pShellcodeFunc + 1);
        }
#endif

        SIZE_T shellcodeSize = (SIZE_T)((BYTE*)ManualMapShellcodeEnd - (BYTE*)ManualMapShellcode);
        if (shellcodeSize == 0 || shellcodeSize > 0x2000) {
            shellcodeSize = 0x1000; // Fallback to 4KB
        }

        // 9. Allocate memory for shellcode + data in target
        SIZE_T totalAlloc = shellcodeSize + sizeof(ManualMapData) + 16;
        BYTE* pRemoteShellcode = (BYTE*)VirtualAllocEx(hProcess, nullptr, totalAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!pRemoteShellcode) {
            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Data goes right after shellcode (aligned to 16 bytes)
        BYTE* pRemoteData = pRemoteShellcode + ((shellcodeSize + 15) & ~(SIZE_T)15);

        // 10. Write shellcode and data
        WriteProcessMemory(hProcess, pRemoteShellcode, pShellcodeFunc, shellcodeSize, nullptr);
        WriteProcessMemory(hProcess, pRemoteData, &mapData, sizeof(mapData), nullptr);

        // 11. Execute shellcode
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteShellcode, pRemoteData, 0, nullptr);

        if (!hThread) {
            VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        // 12. Check result
        ManualMapData result = {};
        ReadProcessMemory(hProcess, pRemoteData, &result, sizeof(result), nullptr);

        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        if (!result.Success) {
            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // 13. Post-injection options
        if (m_options.erasePe) {
            Utils::ErasePEHeaders(hProcess, (HMODULE)pRemoteBase);
        }

        if (m_options.linkPeb) {
            Utils::LinkModuleToPEB(hProcess, pRemoteBase, dllPath, pNt->OptionalHeader.SizeOfImage);
        }

        if (m_options.concealMem) {
            Utils::ConcealMemory(hProcess, pRemoteBase, pNt, pSections);
        }

        CloseHandle(hProcess);
        return true;
    }
}
