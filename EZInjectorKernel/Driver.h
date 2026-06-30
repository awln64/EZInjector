#pragma once
#include <ntifs.h>
#include "Communication.h"

// Driver logging macro
#define KDLOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EZIKernel] " fmt "\n", ##__VA_ARGS__)

// Undocumented kernel functions prototypes
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS *Process
);

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS PerformKernelNativeInject(
    _In_ PKERNEL_NATIVE_INJECT_REQUEST Request
);

NTSTATUS PerformKernelManualMap(
    _In_ PKERNEL_MANUAL_MAP_REQUEST Request
);
