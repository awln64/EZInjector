#pragma once
#include <ntifs.h>
#include <ntimage.h>

// Maximum DLL file size allowed (64MB) — prevents non-paged/paged pool exhaustion
#define EZI_MAX_DLL_FILE_SIZE (64 * 1024 * 1024)

#ifdef __cplusplus
extern "C" {
#endif

// PEB / LDR Definitions for kernel mode walking
typedef struct _PEB_LDR_DATA_KERNEL {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_KERNEL, *PPEB_LDR_DATA_KERNEL;

typedef struct _LDR_DATA_TABLE_ENTRY_KERNEL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_KERNEL, *PLDR_DATA_TABLE_ENTRY_KERNEL;

typedef struct _PEB_KERNEL {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_KERNEL Ldr;
} PEB_KERNEL, *PPEB_KERNEL;

NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

NTKERNELAPI PPEB_KERNEL PsGetProcessPeb(_In_ PEPROCESS Process);

PVOID PeGetModuleBaseAddress(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _In_ BOOLEAN AlreadyAttached);
PVOID PeGetExportAddress(_In_ PVOID ModuleBase, _In_ SIZE_T ModuleSize, _In_ PCSTR ExportName, _In_ PEPROCESS ProcessForForwarder, _In_ BOOLEAN AlreadyAttached);
NTSTATUS PeReadDllFileFromDisk(_In_ PCSTR DosPath, _Out_ PVOID* OutBuffer, _Out_ PSIZE_T OutSize);
VOID PeConcealMemory(_In_ PVOID RemoteBase, _In_ PIMAGE_NT_HEADERS64 NtHeaders, _In_ PIMAGE_SECTION_HEADER Sections);
NTSTATUS PeLinkModuleToPeb(_In_ PEPROCESS Process, _In_ PVOID DllBase, _In_ ULONG SizeOfImage, _In_ PCSTR DllPath);

#ifdef __cplusplus
}
#endif

