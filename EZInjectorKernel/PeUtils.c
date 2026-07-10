#include "PeUtils.h"
#include "Logger.h"
#include "Communication.h"

// Maximum forwarder recursion depth to prevent infinite recursion on circular forwarder chains
#define MAX_FORWARDER_DEPTH 8

// Internal forwarder-aware export resolver with recursion depth tracking
static PVOID PeGetExportAddressInternal(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _In_ PCSTR ExportName,
    _In_ PEPROCESS ProcessForForwarder,
    _In_ BOOLEAN AlreadyAttached,
    _In_ ULONG Depth
);

PVOID PeGetModuleBaseAddress(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _In_ BOOLEAN AlreadyAttached) {
    if (!Process || !ModuleName) return NULL;

    KAPC_STATE apcState;
    if (!AlreadyAttached) {
        KeStackAttachProcess(Process, &apcState);
    }

    PVOID dllBase = NULL;
    __try {
        PPEB_KERNEL peb = PsGetProcessPeb(Process);
        if (peb && peb->Ldr) {
            PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
            PLIST_ENTRY listEntry = listHead->Flink;

            UNICODE_STRING targetName;
            RtlInitUnicodeString(&targetName, ModuleName);

            while (listEntry != listHead && listEntry != NULL) {
                PLDR_DATA_TABLE_ENTRY_KERNEL entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY_KERNEL, InLoadOrderLinks);
                if (entry->BaseDllName.Buffer != NULL) {
                    if (RtlCompareUnicodeString(&entry->BaseDllName, &targetName, TRUE) == 0) {
                        dllBase = entry->DllBase;
                        break;
                    }
                }
                listEntry = listEntry->Flink;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Exception while walking PEB module list.");
    }

    if (!AlreadyAttached) {
        KeUnstackDetachProcess(&apcState);
    }
    return dllBase;
}

PVOID PeGetExportAddress(_In_ PVOID ModuleBase, _In_ SIZE_T ModuleSize, _In_ PCSTR ExportName, _In_ PEPROCESS ProcessForForwarder, _In_ BOOLEAN AlreadyAttached) {
    return PeGetExportAddressInternal(ModuleBase, ModuleSize, ExportName, ProcessForForwarder, AlreadyAttached, 0);
}

static PVOID PeGetExportAddressInternal(
    _In_ PVOID ModuleBase,
    _In_ SIZE_T ModuleSize,
    _In_ PCSTR ExportName,
    _In_ PEPROCESS ProcessForForwarder,
    _In_ BOOLEAN AlreadyAttached,
    _In_ ULONG Depth
) {
    if (!ModuleBase || !ExportName) return NULL;
    if (Depth >= MAX_FORWARDER_DEPTH) {
        log("Export forwarder recursion depth exceeded for '%s'.", ExportName);
        return NULL;
    }

    PVOID exportAddress = NULL;
    __try {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        // Bounds-check e_lfanew: must point within the module
        if (ModuleSize > 0) {
            if ((ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > ModuleSize) {
                log("e_lfanew (0x%X) out of bounds (ModuleSize=0x%IX).", dosHeader->e_lfanew, ModuleSize);
                return NULL;
            }
        }

        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

        // Validate NumberOfRvaAndSizes before accessing DataDirectory
        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return NULL;

        ULONG exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exportSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRva == 0) return NULL;

        // Bounds-check export directory RVA
        if (ModuleSize > 0 && (SIZE_T)exportRva + exportSize > ModuleSize) {
            log("Export directory RVA out of bounds.");
            return NULL;
        }

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + exportRva);
        PULONG names = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
        PULONG funcs = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        PUSHORT ords = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);

        ULONG i;
        for (i = 0; i < exportDir->NumberOfNames; i++) {
            PCSTR funcName = (PCSTR)((PUCHAR)ModuleBase + names[i]);
            if (strcmp(funcName, ExportName) == 0) {
                ULONG funcRva = funcs[ords[i]];
                if (funcRva >= exportRva && funcRva < exportRva + exportSize) {
                    // Forwarded export — resolve recursively
                    char forwarder[256];
                    PCSTR fwdPtr = (PCSTR)((PUCHAR)ModuleBase + funcRva);
                    SIZE_T fwdLen = strlen(fwdPtr);
                    if (fwdLen >= sizeof(forwarder)) fwdLen = sizeof(forwarder) - 1;
                    RtlCopyMemory(forwarder, fwdPtr, fwdLen);
                    forwarder[fwdLen] = '\0';

                    char* dot = strchr(forwarder, '.');
                    if (dot) {
                        *dot = '\0';
                        char* modName = forwarder;
                        char* expName = dot + 1;

                        WCHAR wModName[256];
                        UNICODE_STRING uniMod;
                        uniMod.Buffer = wModName;
                        uniMod.MaximumLength = sizeof(wModName);

                        char fullDllName[256];
                        RtlStringCbPrintfA(fullDllName, sizeof(fullDllName), "%s.DLL", modName);
                        ANSI_STRING ansiMod;
                        RtlInitAnsiString(&ansiMod, fullDllName);
                        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniMod, &ansiMod, FALSE))) {
                            // Use AlreadyAttached=TRUE since caller may already be attached
                            PVOID fwdBase = PeGetModuleBaseAddress(
                                ProcessForForwarder ? ProcessForForwarder : PsGetCurrentProcess(),
                                uniMod.Buffer,
                                AlreadyAttached
                            );
                            if (!fwdBase) {
                                RtlInitAnsiString(&ansiMod, modName);
                                if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniMod, &ansiMod, FALSE))) {
                                    fwdBase = PeGetModuleBaseAddress(
                                        ProcessForForwarder ? ProcessForForwarder : PsGetCurrentProcess(),
                                        uniMod.Buffer,
                                        AlreadyAttached
                                    );
                                }
                            }
                            if (fwdBase) {
                                // Recurse with incremented depth; use 0 for ModuleSize since we don't know the forwarded module's size
                                return PeGetExportAddressInternal(fwdBase, 0, expName, ProcessForForwarder, AlreadyAttached, Depth + 1);
                            }
                        }
                    }
                    return NULL;
                }
                exportAddress = (PVOID)((PUCHAR)ModuleBase + funcRva);
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Exception while parsing PE export table.");
    }

    return exportAddress;
}

NTSTATUS PeReadDllFileFromDisk(_In_ PCSTR DosPath, _Out_ PVOID* OutBuffer, _Out_ PSIZE_T OutSize) {
    if (!DosPath || !OutBuffer || !OutSize) return STATUS_INVALID_PARAMETER;

    *OutBuffer = NULL;
    *OutSize = 0;

    char ntPathBuf[EZI_MAX_PATH + 16] = { 0 };
    if (_strnicmp(DosPath, "\\??\\", 4) != 0 && _strnicmp(DosPath, "\\DosDevices\\", 12) != 0) {
        RtlStringCbPrintfA(ntPathBuf, sizeof(ntPathBuf), "\\??\\%s", DosPath);
    } else {
        RtlStringCbCopyA(ntPathBuf, sizeof(ntPathBuf), DosPath);
    }

    ANSI_STRING ansiPath;
    RtlInitAnsiString(&ansiPath, ntPathBuf);

    UNICODE_STRING uniPath;
    NTSTATUS status = RtlAnsiStringToUnicodeString(&uniPath, &ansiPath, TRUE);
    if (!NT_SUCCESS(status)) {
        log("Failed to convert path to unicode: 0x%X", status);
        return status;
    }

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatus;
    status = ZwOpenFile(&hFile, FILE_GENERIC_READ, &objAttr, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    RtlFreeUnicodeString(&uniPath);

    if (!NT_SUCCESS(status)) {
        log("ZwOpenFile failed for %s: 0x%X", ntPathBuf, status);
        return status;
    }

    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    status = ZwQueryInformationFile(hFile, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status) || fileInfo.EndOfFile.QuadPart == 0) {
        log("ZwQueryInformationFile failed or empty file: 0x%X", status);
        ZwClose(hFile);
        return status ? status : STATUS_FILE_INVALID;
    }

    SIZE_T fileSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;

    // Validate file size: must be at least a DOS header and not exceed the maximum
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        log("File too small to be a valid PE: %Iu bytes", fileSize);
        ZwClose(hFile);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (fileSize > EZI_MAX_DLL_FILE_SIZE) {
        log("File exceeds maximum allowed size (%Iu > %u bytes)", fileSize, EZI_MAX_DLL_FILE_SIZE);
        ZwClose(hFile);
        return STATUS_FILE_TOO_LARGE;
    }

    // Use paged pool — all access happens at PASSIVE_LEVEL, no need to waste non-paged pool
    PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, fileSize, 'eDPe');
    if (!buffer) {
        log("Failed to allocate kernel pool for DLL file.");
        ZwClose(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    status = ZwReadFile(hFile, NULL, NULL, NULL, &ioStatus, buffer, (ULONG)fileSize, &byteOffset, NULL);
    ZwClose(hFile);

    if (!NT_SUCCESS(status)) {
        log("ZwReadFile failed: 0x%X", status);
        ExFreePool(buffer);
        return status;
    }

    // Validate PE signatures before returning the buffer
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        log("Invalid DOS signature in file.");
        ExFreePool(buffer);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if ((SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
        log("e_lfanew (0x%X) out of bounds for file of size %Iu.", dosHeader->e_lfanew, fileSize);
        ExFreePool(buffer);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        log("Invalid NT signature in file.");
        ExFreePool(buffer);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *OutBuffer = buffer;
    *OutSize = fileSize;
    return STATUS_SUCCESS;
}

VOID PeConcealMemory(_In_ PVOID RemoteBase, _In_ PIMAGE_NT_HEADERS64 NtHeaders, _In_ PIMAGE_SECTION_HEADER Sections) {
    if (!RemoteBase || !NtHeaders || !Sections) return;

    ULONG oldProtect = 0;
    SIZE_T headerSize = NtHeaders->OptionalHeader.SizeOfHeaders;
    PVOID headerAddr = RemoteBase;
    ZwProtectVirtualMemory(ZwCurrentProcess(), &headerAddr, &headerSize, PAGE_READONLY, &oldProtect);

    USHORT secIdx;
    for (secIdx = 0; secIdx < NtHeaders->FileHeader.NumberOfSections; secIdx++) {
        ULONG secSize = Sections[secIdx].Misc.VirtualSize;
        if (secSize == 0) continue;

        ULONG characteristics = Sections[secIdx].Characteristics;
        ULONG protect = PAGE_NOACCESS;
        BOOLEAN exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOLEAN read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOLEAN write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec) {
            if (write) protect = PAGE_EXECUTE_READWRITE;
            else if (read) protect = PAGE_EXECUTE_READ;
            else protect = PAGE_EXECUTE;
        } else {
            if (write) protect = PAGE_READWRITE;
            else if (read) protect = PAGE_READONLY;
            else protect = PAGE_NOACCESS;
        }

        // Avoid stripping EXECUTE permissions on shared 4KB pages if section alignment is < 0x1000
        if (NtHeaders->OptionalHeader.SectionAlignment < 0x1000 && !exec) {
            protect = write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }

        PVOID secAddr = (PUCHAR)RemoteBase + Sections[secIdx].VirtualAddress;
        SIZE_T secLen = secSize;
        ZwProtectVirtualMemory(ZwCurrentProcess(), &secAddr, &secLen, protect, &oldProtect);
    }
}

NTSTATUS PeLinkModuleToPeb(_In_ PEPROCESS Process, _In_ PVOID DllBase, _In_ ULONG SizeOfImage, _In_ PCSTR DllPath) {
    if (!Process || !DllBase || !DllPath) return STATUS_INVALID_PARAMETER;

    // Wrap all PEB access in SEH — PEB is user-mode memory and may be paged out or corrupted
    NTSTATUS status = STATUS_SUCCESS;

    PPEB_KERNEL peb = NULL;
    __try {
        peb = PsGetProcessPeb(Process);
        if (!peb || !peb->Ldr) {
            return STATUS_UNSUCCESSFUL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Exception accessing PEB in PeLinkModuleToPeb.");
        return GetExceptionCode();
    }

    ANSI_STRING ansiPath;
    UNICODE_STRING uniPath;
    RtlInitAnsiString(&ansiPath, DllPath);
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniPath, &ansiPath, TRUE))) {
        return STATUS_UNSUCCESSFUL;
    }

    PWSTR baseNamePtr = uniPath.Buffer;
    USHORT i;
    for (i = 0; i < uniPath.Length / sizeof(WCHAR); i++) {
        if (uniPath.Buffer[i] == L'\\' || uniPath.Buffer[i] == L'/') {
            baseNamePtr = &uniPath.Buffer[i + 1];
        }
    }
    USHORT baseNameLen = uniPath.Length - (USHORT)((PUCHAR)baseNamePtr - (PUCHAR)uniPath.Buffer);

    // Allocate 0x200 bytes for LDR_DATA_TABLE_ENTRY to accommodate internal Windows 10/11 fields (DdagNode, Flags, etc.)
    ULONG structHeaderSize = 0x200;
    SIZE_T totalAlloc = structHeaderSize + uniPath.Length + 2 + baseNameLen + 2;

    // Check for integer overflow
    if (totalAlloc < structHeaderSize) {
        RtlFreeUnicodeString(&uniPath);
        return STATUS_INTEGER_OVERFLOW;
    }

    PVOID remoteMem = NULL;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteMem, 0, &totalAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !remoteMem) {
        RtlFreeUnicodeString(&uniPath);
        return status;
    }

    PLDR_DATA_TABLE_ENTRY_KERNEL entry = (PLDR_DATA_TABLE_ENTRY_KERNEL)remoteMem;
    PWSTR fullPathBuf = (PWSTR)((PUCHAR)remoteMem + structHeaderSize);
    PWSTR basePathBuf = (PWSTR)((PUCHAR)fullPathBuf + uniPath.Length + 2);

    RtlZeroMemory(remoteMem, totalAlloc);
    RtlCopyMemory(fullPathBuf, uniPath.Buffer, uniPath.Length);
    RtlCopyMemory(basePathBuf, baseNamePtr, baseNameLen);

    entry->DllBase = DllBase;
    entry->SizeOfImage = SizeOfImage;
    entry->FullDllName.Length = uniPath.Length;
    entry->FullDllName.MaximumLength = uniPath.Length + 2;
    entry->FullDllName.Buffer = fullPathBuf;
    entry->BaseDllName.Length = baseNameLen;
    entry->BaseDllName.MaximumLength = baseNameLen + 2;
    entry->BaseDllName.Buffer = basePathBuf;

    // Wrap PEB linked list modifications in SEH to prevent BSOD
    __try {
        PLIST_ENTRY pLoadOrderHead = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY pMemOrderHead = &peb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY pInitOrderHead = &peb->Ldr->InInitializationOrderModuleList;

        InsertTailList(pLoadOrderHead, &entry->InLoadOrderLinks);
        InsertTailList(pMemOrderHead, &entry->InMemoryOrderLinks);
        InsertTailList(pInitOrderHead, &entry->InInitializationOrderLinks);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Exception while inserting module into PEB lists. Target process PEB may be corrupted.");
        status = GetExceptionCode();
        // Free the allocated memory since linking failed
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteMem, &freeSize, MEM_RELEASE);
        RtlFreeUnicodeString(&uniPath);
        return status;
    }

    RtlFreeUnicodeString(&uniPath);
    return STATUS_SUCCESS;
}
