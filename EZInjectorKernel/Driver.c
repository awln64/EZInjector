#include "Driver.h"

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\EZInjectorKernel");
UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\EZInjectorKernel");

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    KDLOG("DriverEntry called. Initializing EZInjectorKernel...");

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        KDLOG("Failed to create device: 0x%X", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        KDLOG("Failed to create symbolic link: 0x%X", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    KDLOG("EZInjectorKernel successfully initialized.");
    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    KDLOG("Unloading EZInjectorKernel...");

    IoDeleteSymbolicLink(&g_SymbolicLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    KDLOG("EZInjectorKernel unloaded successfully.");
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
            KDLOG("Processing IOCTL_EZI_KERNEL_NATIVE_INJECT...");
            status = PerformKernelNativeInject((PKERNEL_NATIVE_INJECT_REQUEST)buffer);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_EZI_KERNEL_MANUAL_MAP:
        if (inputBufferLength >= sizeof(KERNEL_MANUAL_MAP_REQUEST) && buffer != NULL) {
            KDLOG("Processing IOCTL_EZI_KERNEL_MANUAL_MAP...");
            status = PerformKernelManualMap((PKERNEL_MANUAL_MAP_REQUEST)buffer);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        KDLOG("Unknown IOCTL code: 0x%X", controlCode);
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS PerformKernelNativeInject(_In_ PKERNEL_NATIVE_INJECT_REQUEST Request) {
    KDLOG("Target PID: %lu | DLL Path: %s", Request->TargetPid, Request->DllPath);

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(Request->TargetPid), &process);
    if (!NT_SUCCESS(status)) {
        KDLOG("Failed to lookup process by PID %lu: 0x%X", Request->TargetPid, status);
        return status;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    // Skeleton implementation:
    // In a full native injection routine, we allocate virtual memory in user space using ZwAllocateVirtualMemory,
    // write the DLL path, and queue a kernel APC to an alertable user thread executing LoadLibraryA or shellcode.
    KDLOG("Successfully attached to process space of PID %lu for Native Injection.", Request->TargetPid);

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}

NTSTATUS PerformKernelManualMap(_In_ PKERNEL_MANUAL_MAP_REQUEST Request) {
    KDLOG("Target PID: %lu | DLL Path: %s | Options: LinkPEB=%d, ErasePE=%d, Conceal=%d",
        Request->TargetPid, Request->DllPath, Request->LinkPeb, Request->ErasePe, Request->ConcealMem);

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(Request->TargetPid), &process);
    if (!NT_SUCCESS(status)) {
        KDLOG("Failed to lookup process by PID %lu: 0x%X", Request->TargetPid, status);
        return status;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    // Skeleton implementation:
    // For manual mapping from kernel space, memory is allocated via ZwAllocateVirtualMemory,
    // headers and sections are mapped, relocations and imports are parsed, and execution is triggered.
    KDLOG("Successfully attached to process space of PID %lu for Manual Map.", Request->TargetPid);

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return STATUS_SUCCESS;
}
