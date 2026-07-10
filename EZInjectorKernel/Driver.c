#include "Driver.h"
#include "Logger.h"
#include "PeUtils.h"

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\EZInjectorKernel");
UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\EZInjectorKernel");
UNICODE_STRING g_GlobalSymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Global\\EZInjectorKernel");

NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    log("Unloading EZInjectorKernel...");

    IoDeleteSymbolicLink(&g_GlobalSymbolicLink);
    IoDeleteSymbolicLink(&g_SymbolicLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    log("EZInjectorKernel unloaded successfully.");
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesReturned = 0;

    switch (controlCode) {
    case IOCTL_EZI_KERNEL_NATIVE_INJECT:
        if (inputBufferLength >= sizeof(KERNEL_NATIVE_INJECT_REQUEST) && buffer != NULL) {
            PKERNEL_NATIVE_INJECT_REQUEST req = (PKERNEL_NATIVE_INJECT_REQUEST)buffer;
            req->DllPath[EZI_MAX_PATH - 1] = '\0';
            if (req->DllPath[0] == '\0') {
                status = STATUS_INVALID_PARAMETER;
            } else if (req->TargetPid == 0) {
                log("Invalid TargetPid: 0");
                status = STATUS_INVALID_PARAMETER;
            } else {
                log("Processing IOCTL_EZI_KERNEL_NATIVE_INJECT...");
                status = PerformKernelNativeInject(req);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_EZI_KERNEL_MANUAL_MAP:
        if (inputBufferLength >= sizeof(KERNEL_MANUAL_MAP_REQUEST) && buffer != NULL) {
            PKERNEL_MANUAL_MAP_REQUEST req = (PKERNEL_MANUAL_MAP_REQUEST)buffer;
            req->DllPath[EZI_MAX_PATH - 1] = '\0';
            if (req->DllPath[0] == '\0') {
                status = STATUS_INVALID_PARAMETER;
            } else if (req->TargetPid == 0) {
                log("Invalid TargetPid: 0");
                status = STATUS_INVALID_PARAMETER;
            } else {
                log("Processing IOCTL_EZI_KERNEL_MANUAL_MAP...");
                status = PerformKernelManualMap(req);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        log("Unknown IOCTL code: 0x%X", controlCode);
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID KernelNativeApcRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePool(Apc);
}

typedef PVOID (NTAPI *PFN_LOAD_LIBRARY_A_REMOTE)(PCSTR);
typedef PVOID (NTAPI *PFN_GET_PROC_ADDRESS_REMOTE)(PVOID, PCSTR);
typedef BOOLEAN (NTAPI *PFN_RTL_ADD_FUNCTION_TABLE_REMOTE)(PVOID, ULONG, ULONG64);
typedef BOOLEAN (NTAPI *PFN_DLL_MAIN_REMOTE)(PVOID, ULONG, PVOID);
typedef VOID (NTAPI *PFN_TLS_CALLBACK_REMOTE)(PVOID, ULONG, PVOID);

typedef struct _KERNEL_MANUAL_MAP_REMOTE_DATA {
    PUCHAR ImageBase;
    PFN_LOAD_LIBRARY_A_REMOTE fnLoadLibraryA;
    PFN_GET_PROC_ADDRESS_REMOTE fnGetProcAddress;
    PFN_RTL_ADD_FUNCTION_TABLE_REMOTE fnRtlAddFunctionTable;
    BOOLEAN ResolveImports;
    BOOLEAN IgnoreTls;
    BOOLEAN NoExceptions;
    ULONG ImportDirRva;
    ULONG TlsDirRva;
    ULONG ExceptionDirRva;
    ULONG ExceptionDirSize;
    ULONG EntryPointRva;
    volatile LONG Success;
} KERNEL_MANUAL_MAP_REMOTE_DATA, *PKERNEL_MANUAL_MAP_REMOTE_DATA;

static PUCHAR ResolveJmpThunk(PUCHAR pFunc) {
    if (pFunc && *pFunc == 0xE9) {
        LONG offset = *(PLONG)(pFunc + 1);
        return pFunc + 5 + offset;
    }
    return pFunc;
}

#pragma optimize("ts", on)
#pragma strict_gs_check(push, off)
__declspec(safebuffers) __declspec(guard(nocf))
static ULONG NTAPI KernelManualMapLoaderStub(PKERNEL_MANUAL_MAP_REMOTE_DATA pData) {
    if (!pData) return 0;
    if (_InterlockedCompareExchange((volatile LONG*)&pData->Success, 1, 0) != 0) return 1;
    PUCHAR pBase = pData->ImageBase;

    if (pData->ResolveImports && pData->ImportDirRva && pData->fnLoadLibraryA && pData->fnGetProcAddress) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pData->ImportDirRva);
        while (pImport->Name != 0) {
            char* szModule = (char*)(pBase + pImport->Name);
            PVOID hMod = pData->fnLoadLibraryA(szModule);
            if (hMod != NULL) {
                PIMAGE_THUNK_DATA64 pOrigThunk = pImport->OriginalFirstThunk ? (PIMAGE_THUNK_DATA64)(pBase + pImport->OriginalFirstThunk) : (PIMAGE_THUNK_DATA64)(pBase + pImport->FirstThunk);
                PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(pBase + pImport->FirstThunk);
                while (pOrigThunk->u1.AddressOfData != 0) {
                    if (IMAGE_SNAP_BY_ORDINAL64(pOrigThunk->u1.Ordinal)) {
                        ULONGLONG ord = IMAGE_ORDINAL64(pOrigThunk->u1.Ordinal);
                        pThunk->u1.Function = (ULONGLONG)pData->fnGetProcAddress(hMod, (char*)ord);
                    } else {
                        PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pBase + pOrigThunk->u1.AddressOfData);
                        pThunk->u1.Function = (ULONGLONG)pData->fnGetProcAddress(hMod, pName->Name);
                    }
                    if (pThunk->u1.Function == 0) {
                        pData->Success = 3;
                        return 0;
                    }
                    pOrigThunk++;
                    pThunk++;
                }
            } else {
                pData->Success = 3;
                return 0;
            }
            pImport++;
        }
    }

    if (!pData->IgnoreTls && pData->TlsDirRva) {
        PIMAGE_TLS_DIRECTORY64 pTlsDir = (PIMAGE_TLS_DIRECTORY64)(pBase + pData->TlsDirRva);
        PULONG64 ppCallback = (PULONG64)pTlsDir->AddressOfCallBacks;
        if (ppCallback != NULL) {
            while (*ppCallback != 0) {
                PFN_TLS_CALLBACK_REMOTE pCallback = (PFN_TLS_CALLBACK_REMOTE)(*ppCallback);
                pCallback(pBase, 1, NULL);
                ppCallback++;
            }
        }
    }

    if (!pData->NoExceptions && pData->ExceptionDirRva && pData->ExceptionDirSize && pData->fnRtlAddFunctionTable) {
        pData->fnRtlAddFunctionTable((PVOID)(pBase + pData->ExceptionDirRva), pData->ExceptionDirSize / 12, (ULONG64)pBase);
    }

    if (pData->EntryPointRva) {
        PFN_DLL_MAIN_REMOTE pDllMain = (PFN_DLL_MAIN_REMOTE)(pBase + pData->EntryPointRva);
        pDllMain(pBase, 1, NULL);
    }

    pData->Success = 2;
    return 1;
}
static ULONG NTAPI KernelManualMapLoaderStubEnd() { return 0; }
#pragma strict_gs_check(pop)
#pragma optimize("", on)

static NTSTATUS SpawnRemoteUserThread(HANDLE hProcess, PVOID startRoutine, PVOID argument, PHANDLE OutThreadHandle) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING rtlRoutineName;
    RtlInitUnicodeString(&rtlRoutineName, L"RtlCreateUserThread");
    typedef NTSTATUS (NTAPI *PFN_RtlCreateUserThread)(HANDLE, PVOID, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);
    PFN_RtlCreateUserThread pRtlCreateUserThread = (PFN_RtlCreateUserThread)MmGetSystemRoutineAddress(&rtlRoutineName);

    if (pRtlCreateUserThread) {
        HANDLE hThread = NULL;
        status = pRtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, startRoutine, argument, &hThread, NULL);
        if (NT_SUCCESS(status)) {
            log("RtlCreateUserThread spawned remote thread successfully (Handle: %p).", hThread);
            if (OutThreadHandle && hThread) {
                *OutThreadHandle = hThread;
            } else if (hThread) {
                ZwClose(hThread);
            }
            return STATUS_SUCCESS;
        } else {
            log("RtlCreateUserThread failed with status 0x%X", status);
        }
    } else {
        log("RtlCreateUserThread export not found.");
    }

    UNICODE_STRING zwRoutineName;
    RtlInitUnicodeString(&zwRoutineName, L"ZwCreateThreadEx");
    typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    PFN_ZwCreateThreadEx pZwCreateThreadEx = (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress(&zwRoutineName);

    if (pZwCreateThreadEx) {
        HANDLE hThread = NULL;
        status = pZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, startRoutine, argument, 0, 0, 0, 0, NULL);
        if (NT_SUCCESS(status)) {
            log("ZwCreateThreadEx spawned remote thread successfully (Handle: %p).", hThread);
            if (OutThreadHandle && hThread) {
                *OutThreadHandle = hThread;
            } else if (hThread) {
                ZwClose(hThread);
            }
            return STATUS_SUCCESS;
        } else {
            log("ZwCreateThreadEx failed with status 0x%X", status);
        }
    } else {
        log("ZwCreateThreadEx export not found.");
    }

    return status;
}

NTSTATUS PerformKernelNativeInject(_In_ PKERNEL_NATIVE_INJECT_REQUEST Request) {
    log("Target PID: %lu | DLL Path: %s", Request->TargetPid, Request->DllPath);

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(Request->TargetPid), &process);
    if (!NT_SUCCESS(status)) {
        log("Failed to lookup process by PID %lu: 0x%X", Request->TargetPid, status);
        return status;
    }

    // Resolve kernel32 module base BEFORE attaching to avoid nested attach in forwarder resolution
    PVOID kernel32Base = PeGetModuleBaseAddress(process, L"kernel32.dll", FALSE);
    if (!kernel32Base) {
        log("Could not find kernel32.dll in target process.");
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    // Now resolve LoadLibraryA while attached — pass AlreadyAttached=TRUE to prevent nested attach
    PVOID loadLibraryAddr = PeGetExportAddress(kernel32Base, 0, "LoadLibraryA", process, TRUE);
    if (!loadLibraryAddr) {
        log("Could not find LoadLibraryA export.");
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    PVOID remoteDllPath = NULL;
    SIZE_T allocSize = strlen(Request->DllPath) + 1;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteDllPath, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        log("ZwAllocateVirtualMemory failed: 0x%X", status);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return status;
    }

    __try {
        RtlCopyMemory(remoteDllPath, Request->DllPath, strlen(Request->DllPath) + 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Exception while copying DLL path to remote process.");
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteDllPath, &freeSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return GetExceptionCode();
    }

    HANDLE hTargetProcess = NULL;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hTargetProcess);
    if (!NT_SUCCESS(status)) {
        log("ObOpenObjectByPointer failed (0x%X), falling back to ZwCurrentProcess.", status);
        hTargetProcess = ZwCurrentProcess();
    }

    status = SpawnRemoteUserThread(hTargetProcess, loadLibraryAddr, remoteDllPath, NULL);
    BOOLEAN threadCreated = NT_SUCCESS(status);

    if (hTargetProcess != ZwCurrentProcess()) {
        ZwClose(hTargetProcess);
    }

    KeUnstackDetachProcess(&apcState);

    if (!threadCreated && Request->TargetThreadId != 0) {
        PETHREAD thread = NULL;
        NTSTATUS apcStatus = PsLookupThreadByThreadId(ULongToHandle(Request->TargetThreadId), &thread);
        if (NT_SUCCESS(apcStatus)) {
            PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'ApeI');
            if (apc) {
                KeInitializeApc(apc, thread, OriginalApcEnvironment, KernelNativeApcRoutine, NULL, (PKNORMAL_ROUTINE)loadLibraryAddr, UserMode, remoteDllPath);
                if (KeInsertQueueApc(apc, NULL, NULL, 0)) {
                    log("User APC queued to Thread ID %lu.", Request->TargetThreadId);
                    status = STATUS_SUCCESS;
                } else {
                    ExFreePool(apc);
                    status = STATUS_UNSUCCESSFUL;
                }
            } else {
                log("Failed to allocate APC object.");
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            ObDereferenceObject(thread);
        }
    }

    if (!NT_SUCCESS(status)) {
        log("PerformKernelNativeInject failed to execute remote load: 0x%X", status);
        // Re-attach to free the leaked remote memory
        KeStackAttachProcess(process, &apcState);
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteDllPath, &freeSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
    }

    ObDereferenceObject(process);
    return status;
}

NTSTATUS PerformKernelManualMap(_In_ PKERNEL_MANUAL_MAP_REQUEST Request) {
    log("Target PID: %lu | DLL Path: %s | Options: LinkPEB=%d, ErasePE=%d, Conceal=%d",
        Request->TargetPid, Request->DllPath, Request->LinkPeb, Request->ErasePe, Request->ConcealMem);

    PVOID rawBuffer = NULL;
    SIZE_T fileSize = 0;
    NTSTATUS status = PeReadDllFileFromDisk(Request->DllPath, &rawBuffer, &fileSize);
    if (!NT_SUCCESS(status)) {
        log("PeReadDllFileFromDisk failed for %s: 0x%X", Request->DllPath, status);
        return status;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)rawBuffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)rawBuffer + dosHeader->e_lfanew);

    if ((SIZE_T)ntHeaders->OptionalHeader.SizeOfHeaders > fileSize) {
        log("SizeOfHeaders (0x%X) exceeds file size (%Iu).", ntHeaders->OptionalHeader.SizeOfHeaders, fileSize);
        ExFreePool(rawBuffer);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    if (imageSize == 0 || imageSize > EZI_MAX_DLL_FILE_SIZE) {
        log("SizeOfImage (%Iu) is invalid or too large.", imageSize);
        ExFreePool(rawBuffer);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (ntHeaders->FileHeader.NumberOfSections == 0 || ntHeaders->FileHeader.NumberOfSections > 96) {
        log("Invalid NumberOfSections: %u", ntHeaders->FileHeader.NumberOfSections);
        ExFreePool(rawBuffer);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PEPROCESS process = NULL;
    status = PsLookupProcessByProcessId(ULongToHandle(Request->TargetPid), &process);
    if (!NT_SUCCESS(status)) {
        ExFreePool(rawBuffer);
        return status;
    }

    PVOID kernel32Base = PeGetModuleBaseAddress(process, L"kernel32.dll", FALSE);
    PVOID ntdllBase = PeGetModuleBaseAddress(process, L"ntdll.dll", FALSE);

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    PVOID pLoadLibraryA = kernel32Base ? PeGetExportAddress(kernel32Base, 0, "LoadLibraryA", process, TRUE) : NULL;
    PVOID pGetProcAddress = kernel32Base ? PeGetExportAddress(kernel32Base, 0, "GetProcAddress", process, TRUE) : NULL;
    PVOID pRtlAddFunctionTable = ntdllBase ? PeGetExportAddress(ntdllBase, 0, "RtlAddFunctionTable", process, TRUE) : NULL;
    if (!pRtlAddFunctionTable && kernel32Base) {
        pRtlAddFunctionTable = PeGetExportAddress(kernel32Base, 0, "RtlAddFunctionTable", process, TRUE);
    }

    if (!pLoadLibraryA || !pGetProcAddress) {
        log("Failed to resolve critical exports: LoadLibraryA=%p GetProcAddress=%p", pLoadLibraryA, pGetProcAddress);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        ExFreePool(rawBuffer);
        return STATUS_NOT_FOUND;
    }

    PVOID remoteBase = NULL;
    ULONG protect = PAGE_EXECUTE_READWRITE;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, protect);
    if (!NT_SUCCESS(status)) {
        log("ZwAllocateVirtualMemory failed: 0x%X", status);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        ExFreePool(rawBuffer);
        return status;
    }

    // Copy headers (SizeOfHeaders already validated above)
    __try {
        RtlCopyMemory(remoteBase, rawBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Exception while copying PE headers to remote process.");
        goto CleanupRemoteBase;
    }

    // Copy sections with bounds checking
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    USHORT secIdx;
    for (secIdx = 0; secIdx < ntHeaders->FileHeader.NumberOfSections; secIdx++, section++) {
        SIZE_T copySize = section->SizeOfRawData;
        if (copySize > 0) {
            if (section->PointerToRawData + copySize > fileSize) {
                if (fileSize > section->PointerToRawData) copySize = fileSize - section->PointerToRawData;
                else copySize = 0;
            }
            if (section->VirtualAddress + copySize > imageSize) {
                if (imageSize > section->VirtualAddress) copySize = imageSize - section->VirtualAddress;
                else copySize = 0;
            }
            if (copySize > 0) {
                __try {
                    RtlCopyMemory((PUCHAR)remoteBase + section->VirtualAddress, (PUCHAR)rawBuffer + section->PointerToRawData, copySize);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    log("Exception while copying section %u to remote process.", secIdx);
                    goto CleanupRemoteBase;
                }
            }
        }
    }

    // Apply relocations with bounds checking
    ULONG_PTR delta = (ULONG_PTR)remoteBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        // Validate NumberOfRvaAndSizes before accessing DataDirectory
        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            ULONG relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            ULONG relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (relocRva && relocSize) {
                if ((SIZE_T)relocRva + relocSize > imageSize) {
                    log("Relocation directory (RVA=0x%X, Size=0x%X) exceeds image size (%Iu).", relocRva, relocSize, imageSize);
                    goto CleanupRemoteBase;
                }

                PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)remoteBase + relocRva);
                PIMAGE_BASE_RELOCATION relocEnd = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + relocSize);
                while (reloc < relocEnd && reloc->VirtualAddress && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                    ULONG count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                    PUSHORT list = (PUSHORT)(reloc + 1);
                    ULONG relIdx;
                    for (relIdx = 0; relIdx < count; relIdx++) {
                        if (list[relIdx]) {
                            ULONG type = list[relIdx] >> 12;
                            ULONG offset = list[relIdx] & 0xFFF;
                            SIZE_T patchOffset = (SIZE_T)reloc->VirtualAddress + offset;

                            if (type == IMAGE_REL_BASED_DIR64) {
                                if (patchOffset + sizeof(ULONG64) > imageSize) continue;
                                *(PULONG64)((PUCHAR)remoteBase + patchOffset) += delta;
                            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                                if (patchOffset + sizeof(ULONG) > imageSize) continue;
                                *(PULONG)((PUCHAR)remoteBase + patchOffset) += (ULONG)delta;
                            } else if (type == IMAGE_REL_BASED_HIGH) {
                                if (patchOffset + sizeof(USHORT) > imageSize) continue;
                                *(PUSHORT)((PUCHAR)remoteBase + patchOffset) += (USHORT)(((ULONG)(delta) >> 16) & 0xFFFF);
                            } else if (type == IMAGE_REL_BASED_LOW) {
                                if (patchOffset + sizeof(USHORT) > imageSize) continue;
                                *(PUSHORT)((PUCHAR)remoteBase + patchOffset) += (USHORT)(((ULONG)(delta)) & 0xFFFF);
                            }
                        }
                    }
                    reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
                }
            }
        }
    }

    // Prepare loader data — validate DataDirectory indices
    NTSTATUS threadStatus = STATUS_UNSUCCESSFUL;
    PUCHAR pStubStart = ResolveJmpThunk((PUCHAR)KernelManualMapLoaderStub);
    PUCHAR pStubEnd = ResolveJmpThunk((PUCHAR)KernelManualMapLoaderStubEnd);
    SIZE_T loaderCodeSize = (SIZE_T)(pStubEnd - pStubStart);
    if (loaderCodeSize == 0 || loaderCodeSize > 0x2000) {
        log("Stub size calculation returned suspicious value (%Iu). Using 0x1000 fallback.", loaderCodeSize);
        loaderCodeSize = 0x1000;
    }
    SIZE_T totalLoaderSize = loaderCodeSize + sizeof(KERNEL_MANUAL_MAP_REMOTE_DATA) + 32;
    PVOID remoteLoaderMem = NULL;
    NTSTATUS allocStatus = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remoteLoaderMem, 0, &totalLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(allocStatus) && remoteLoaderMem) {
        KERNEL_MANUAL_MAP_REMOTE_DATA loaderData = { 0 };
        loaderData.ImageBase = (PUCHAR)remoteBase;
        loaderData.fnLoadLibraryA = (PFN_LOAD_LIBRARY_A_REMOTE)pLoadLibraryA;
        loaderData.fnGetProcAddress = (PFN_GET_PROC_ADDRESS_REMOTE)pGetProcAddress;
        loaderData.fnRtlAddFunctionTable = (PFN_RTL_ADD_FUNCTION_TABLE_REMOTE)pRtlAddFunctionTable;
        loaderData.ResolveImports = Request->ResolveImports;
        loaderData.IgnoreTls = Request->IgnoreTls;
        loaderData.NoExceptions = Request->NoExceptions;

        // Safe DataDirectory access with NumberOfRvaAndSizes check
        ULONG numDirs = ntHeaders->OptionalHeader.NumberOfRvaAndSizes;
        loaderData.ImportDirRva = (numDirs > IMAGE_DIRECTORY_ENTRY_IMPORT) ? ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress : 0;
        loaderData.TlsDirRva = (numDirs > IMAGE_DIRECTORY_ENTRY_TLS) ? ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress : 0;
        loaderData.ExceptionDirRva = (numDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION) ? ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress : 0;
        loaderData.ExceptionDirSize = (numDirs > IMAGE_DIRECTORY_ENTRY_EXCEPTION) ? ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size : 0;
        loaderData.EntryPointRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        loaderData.Success = 0;

        PUCHAR pRemoteCode = (PUCHAR)remoteLoaderMem;
        PUCHAR pRemoteData = pRemoteCode + ((loaderCodeSize + 15) & ~(SIZE_T)15);
        RtlCopyMemory(pRemoteCode, pStubStart, loaderCodeSize);
        RtlCopyMemory(pRemoteData, &loaderData, sizeof(loaderData));

        HANDLE hTargetProcess = NULL;
        threadStatus = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hTargetProcess);
        if (!NT_SUCCESS(threadStatus)) {
            log("ObOpenObjectByPointer failed (0x%X), falling back to ZwCurrentProcess.", threadStatus);
            hTargetProcess = ZwCurrentProcess();
        }

        HANDLE hThread = NULL;
        threadStatus = SpawnRemoteUserThread(hTargetProcess, pRemoteCode, pRemoteData, &hThread);
        BOOLEAN threadCreated = NT_SUCCESS(threadStatus);

        if (hTargetProcess != ZwCurrentProcess()) {
            ZwClose(hTargetProcess);
        }

        if (!threadCreated && Request->TargetThreadId != 0) {
            PETHREAD thread = NULL;
            NTSTATUS apcStatus = PsLookupThreadByThreadId(ULongToHandle(Request->TargetThreadId), &thread);
            if (NT_SUCCESS(apcStatus)) {
                PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'ApeI');
                if (apc) {
                    KeInitializeApc(apc, thread, OriginalApcEnvironment, KernelNativeApcRoutine, NULL, (PKNORMAL_ROUTINE)pRemoteCode, UserMode, pRemoteData);
                    if (KeInsertQueueApc(apc, NULL, NULL, 0)) {
                        log("User APC queued to Thread ID %lu for KernelManualMapLoader.", Request->TargetThreadId);
                        threadStatus = STATUS_SUCCESS;
                    } else {
                        ExFreePool(apc);
                        threadStatus = STATUS_UNSUCCESSFUL;
                    }
                } else {
                    log("Failed to allocate APC object.");
                    threadStatus = STATUS_INSUFFICIENT_RESOURCES;
                }
                ObDereferenceObject(thread);
            }
        }

        PKERNEL_MANUAL_MAP_REMOTE_DATA pRemoteDataTyped = (PKERNEL_MANUAL_MAP_REMOTE_DATA)pRemoteData;
        if (NT_SUCCESS(threadStatus)) {
            KeUnstackDetachProcess(&apcState);

            if (hThread != NULL) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -10000000LL * 5; // 5 seconds
                ZwWaitForSingleObject(hThread, FALSE, &timeout);
                ZwClose(hThread);
            }

            // Re-attach to check results and perform post-processing
            KeStackAttachProcess(process, &apcState);

            ULONG waitCount = 0;
            while (pRemoteDataTyped->Success <= 1 && waitCount < 100) {
                LARGE_INTEGER delay;
                delay.QuadPart = -500000LL; // 50ms
                KeDelayExecutionThread(UserMode, FALSE, &delay);
                waitCount++;
            }

            if (pRemoteDataTyped->Success != 2) {
                log("KernelManualMapLoader failed or timed out (Success=%ld).", pRemoteDataTyped->Success);
                threadStatus = STATUS_UNSUCCESSFUL;
            } else {
                log("KernelManualMapLoader executed successfully.");
                if (Request->ErasePe) {
                    __try {
                        RtlZeroMemory(remoteBase, ntHeaders->OptionalHeader.SizeOfHeaders);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        log("Exception while erasing PE headers.");
                    }
                }
                if (Request->ConcealMem) {
                    PeConcealMemory(remoteBase, ntHeaders, (PIMAGE_SECTION_HEADER)((PUCHAR)ntHeaders + sizeof(IMAGE_NT_HEADERS64)));
                }
                if (Request->LinkPeb) {
                    PeLinkModuleToPeb(process, remoteBase, (ULONG)imageSize, Request->DllPath);
                }
            }
        } else {
            log("Failed to spawn remote user thread or queue APC for KernelManualMapLoader: 0x%X", threadStatus);
        }

        if (!NT_SUCCESS(threadStatus) || pRemoteDataTyped->Success == 2 || (!threadCreated && Request->TargetThreadId == 0)) {
            SIZE_T freeLoaderSize = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteLoaderMem, &freeLoaderSize, MEM_RELEASE);
        }

        if (!NT_SUCCESS(threadStatus)) {
            SIZE_T freeImageSize = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, &freeImageSize, MEM_RELEASE);
            remoteBase = NULL;
        }
    } else {
        log("Failed to allocate remote memory for KernelManualMapLoader: 0x%X", allocStatus);
        threadStatus = allocStatus;
    }

    // Check if we still need to detach
    if (NT_SUCCESS(threadStatus)) {
        KeUnstackDetachProcess(&apcState);
    } else {
        // For the error paths that didn't go through the detach+reattach above
        if (remoteBase != NULL) {
            // We're still attached from the initial attach — free remote base before detaching
            SIZE_T freeImageSize = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, &freeImageSize, MEM_RELEASE);
        }
        KeUnstackDetachProcess(&apcState);
    }

    ObDereferenceObject(process);
    ExFreePool(rawBuffer);

    if (!NT_SUCCESS(threadStatus)) {
        log("Kernel Manual Map failed during thread execution phase for PID %lu: 0x%X", Request->TargetPid, threadStatus);
        return threadStatus;
    }

    log("Kernel Manual Map completed successfully for PID %lu.", Request->TargetPid);
    return STATUS_SUCCESS;

CleanupRemoteBase:
    {
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBase, &freeSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        ExFreePool(rawBuffer);
        return STATUS_UNSUCCESSFUL;
    }
}

// SDDL: Allow full access to SYSTEM (SY) and Built-in Administrators (BA) only
static UNICODE_STRING g_DeviceSddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
// Device class GUID for EZInjector
static const GUID g_DeviceClassGuid = { 0x45495A49, 0x4E4A, 0x4543, { 0x54, 0x4F, 0x52, 0x4B, 0x45, 0x52, 0x4E, 0x4C } };

NTSTATUS DriverMain(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    log("DriverEntry called. Initializing EZInjectorKernel...");

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceSddl,
        &g_DeviceClassGuid,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        log("Failed to create device: 0x%X", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        log("Failed to create symbolic link: 0x%X", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    IoCreateSymbolicLink(&g_GlobalSymbolicLink, &g_DeviceName);

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    log("EZInjectorKernel successfully initialized.");
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    log("DriverEntry called. Initializing EZInjectorKernel...");

    if (DriverObject != NULL) {
        log("Standard service load detected. Calling DriverMain directly.");
        return DriverMain(DriverObject, RegistryPath);
    }

    log("Manual map load detected (DriverObject is NULL). Creating driver object via IoCreateDriver.");
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\EZInjectorKernel");
    return IoCreateDriver(&driverName, &DriverMain);
}