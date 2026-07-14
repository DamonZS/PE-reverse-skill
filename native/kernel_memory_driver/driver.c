#include <ntifs.h>
#include <wdmsec.h>

#include "protocol.h"

#define KMD_POOL_TAG 'dMkR'
#define KMD_OPERATION_MASK 0x0Fu

typedef struct _KMD_CONFIGURATION {
    ULONG AllowedPid;
    ULONGLONG AllowedCreationTime;
    ULONGLONG AllowedBaseAddress;
    ULONGLONG AllowedRegionSize;
    ULONG AllowWrite;
} KMD_CONFIGURATION;

static KMD_CONFIGURATION g_Configuration;

static const GUID KmdDeviceClassGuid = {
    0xf31adbc5,
    0x798f,
    0x4f84,
    {0xa4, 0xc0, 0xa8, 0x0d, 0x3b, 0x79, 0x39, 0xd2}
};

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS
KmdCompleteIrp(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
KmdUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return KmdCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS
KmdCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return KmdCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static VOID
KmdLoadConfiguration(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    RTL_QUERY_REGISTRY_TABLE query[7];
    ULONG zero32;
    ULONGLONG zero64;
    NTSTATUS status;

    RtlZeroMemory(&g_Configuration, sizeof(g_Configuration));
    RtlZeroMemory(query, sizeof(query));
    zero32 = 0;
    zero64 = 0;

    query[0].Flags = RTL_QUERY_REGISTRY_SUBKEY;
    query[0].Name = L"Parameters";

    query[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[1].Name = L"AllowedPid";
    query[1].EntryContext = &g_Configuration.AllowedPid;
    query[1].DefaultType = REG_DWORD;
    query[1].DefaultData = &zero32;
    query[1].DefaultLength = sizeof(zero32);

    query[2].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[2].Name = L"AllowedCreationTime";
    query[2].EntryContext = &g_Configuration.AllowedCreationTime;
    query[2].DefaultType = REG_QWORD;
    query[2].DefaultData = &zero64;
    query[2].DefaultLength = sizeof(zero64);

    query[3].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[3].Name = L"AllowedBaseAddress";
    query[3].EntryContext = &g_Configuration.AllowedBaseAddress;
    query[3].DefaultType = REG_QWORD;
    query[3].DefaultData = &zero64;
    query[3].DefaultLength = sizeof(zero64);

    query[4].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[4].Name = L"AllowedRegionSize";
    query[4].EntryContext = &g_Configuration.AllowedRegionSize;
    query[4].DefaultType = REG_QWORD;
    query[4].DefaultData = &zero64;
    query[4].DefaultLength = sizeof(zero64);

    query[5].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[5].Name = L"AllowWrite";
    query[5].EntryContext = &g_Configuration.AllowWrite;
    query[5].DefaultType = REG_DWORD;
    query[5].DefaultData = &zero32;
    query[5].DefaultLength = sizeof(zero32);

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        RegistryPath->Buffer,
        query,
        NULL,
        NULL);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(&g_Configuration, sizeof(g_Configuration));
    }
}

static BOOLEAN
KmdIsUserRangeAllowed(
    _In_ ULONGLONG Address,
    _In_ ULONG Length,
    _In_ ULONG OperationLimit
    )
{
    ULONGLONG end;
    ULONGLONG allowedEnd;
    ULONGLONG highestUserAddress;

    if (Length == 0 || Length > OperationLimit ||
        Address < KMD_MIN_USER_ADDRESS ||
        g_Configuration.AllowedBaseAddress < KMD_MIN_USER_ADDRESS ||
        g_Configuration.AllowedRegionSize == 0) {
        return FALSE;
    }
    end = Address + (ULONGLONG)Length;
    allowedEnd = g_Configuration.AllowedBaseAddress +
                 g_Configuration.AllowedRegionSize;
    if (end <= Address ||
        allowedEnd <= g_Configuration.AllowedBaseAddress) {
        return FALSE;
    }
    highestUserAddress = (ULONGLONG)(ULONG_PTR)MmHighestUserAddress;
    if ((end - 1) > highestUserAddress) {
        return FALSE;
    }
    return Address >= g_Configuration.AllowedBaseAddress &&
           end <= allowedEnd;
}

static NTSTATUS
KmdValidateRequest(
    _In_ ULONG IoControlCode,
    _In_ const KMD_REQUEST* Request,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength
    )
{
    ULONG expectedOperation;
    ULONG requiredOutput;
    ULONG index;
    ULONGLONG requiredInput;
    BOOLEAN requestIdPresent;

    if (Request == NULL || InputLength < sizeof(KMD_REQUEST) ||
        Request->Magic != KMD_REQUEST_MAGIC ||
        Request->Version != KMD_PROTOCOL_VERSION ||
        Request->HeaderSize != sizeof(KMD_REQUEST) ||
        Request->TotalSize != InputLength ||
        Request->Flags != 0 || Request->Reserved != 0 ||
        Request->SessionNonce == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    requestIdPresent = FALSE;
    for (index = 0; index < sizeof(Request->RequestId); ++index) {
        if (Request->RequestId[index] != 0) {
            requestIdPresent = TRUE;
            break;
        }
    }
    if (!requestIdPresent) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (IoControlCode) {
    case IOCTL_KMD_VERSION:
        expectedOperation = KMD_OPERATION_VERSION;
        requiredOutput = sizeof(KMD_RESPONSE) + sizeof(KMD_VERSION_INFO);
        break;
    case IOCTL_KMD_QUERY_PROCESS:
        expectedOperation = KMD_OPERATION_QUERY_PROCESS;
        requiredOutput = sizeof(KMD_RESPONSE);
        break;
    case IOCTL_KMD_READ:
        expectedOperation = KMD_OPERATION_READ;
        if (Request->Length == 0 || Request->Length > KMD_MAX_READ_BYTES) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        requiredOutput = sizeof(KMD_RESPONSE) + Request->Length;
        break;
    case IOCTL_KMD_WRITE:
        expectedOperation = KMD_OPERATION_WRITE;
        if (Request->Length == 0 || Request->Length > KMD_MAX_WRITE_BYTES) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        requiredOutput = sizeof(KMD_RESPONSE) + Request->Length;
        break;
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (Request->Operation != expectedOperation) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (OutputLength < requiredOutput) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (expectedOperation == KMD_OPERATION_VERSION) {
        if (Request->Pid != 0 || Request->ProcessCreationTime != 0 ||
            Request->Address != 0 || Request->Length != 0 ||
            Request->ExpectedLength != 0 || Request->DataLength != 0 ||
            InputLength != sizeof(KMD_REQUEST)) {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_SUCCESS;
    }

    if (Request->Pid == 0 || Request->ProcessCreationTime == 0) {
        return STATUS_INVALID_CID;
    }
    if (expectedOperation == KMD_OPERATION_QUERY_PROCESS) {
        if (Request->Address != 0 || Request->Length != 0 ||
            Request->ExpectedLength != 0 || Request->DataLength != 0 ||
            InputLength != sizeof(KMD_REQUEST)) {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_SUCCESS;
    }
    if (expectedOperation == KMD_OPERATION_READ) {
        if (Request->ExpectedLength != 0 || Request->DataLength != 0 ||
            InputLength != sizeof(KMD_REQUEST)) {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_SUCCESS;
    }

    requiredInput = sizeof(KMD_REQUEST) +
                    ((ULONGLONG)Request->Length * 2ull);
    if (Request->ExpectedLength != Request->Length ||
        Request->DataLength != Request->Length ||
        requiredInput != InputLength) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KmdReferenceTargetProcess(
    _In_ const KMD_REQUEST* Request,
    _Outptr_ PEPROCESS* Process
    )
{
    NTSTATUS status;
    ULONGLONG actualCreationTime;

    *Process = NULL;
    if (g_Configuration.AllowedPid == 0 ||
        g_Configuration.AllowedCreationTime == 0 ||
        Request->Pid != g_Configuration.AllowedPid ||
        Request->ProcessCreationTime !=
            g_Configuration.AllowedCreationTime) {
        return STATUS_ACCESS_DENIED;
    }
    status = PsLookupProcessByProcessId(
        ULongToHandle(Request->Pid),
        Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    actualCreationTime = (ULONGLONG)
        PsGetProcessCreateTimeQuadPart(*Process);
    if (actualCreationTime != Request->ProcessCreationTime) {
        ObDereferenceObject(*Process);
        *Process = NULL;
        return STATUS_INVALID_CID;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KmdReadAttachedProcess(
    _In_ PEPROCESS Process,
    _In_ ULONGLONG Address,
    _In_ ULONG Length,
    _Out_writes_bytes_(Length) UCHAR* Destination
    )
{
    KAPC_STATE apcState;
    NTSTATUS status;
    PVOID source;

    status = STATUS_SUCCESS;
    source = (PVOID)(ULONG_PTR)Address;
    KeStackAttachProcess(Process, &apcState);
    __try {
        ProbeForRead(source, Length, 1);
        RtlCopyMemory(Destination, source, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    return status;
}

static NTSTATUS
KmdCompareWriteAttachedProcess(
    _In_ PEPROCESS Process,
    _In_ ULONGLONG Address,
    _In_ ULONG Length,
    _In_reads_bytes_(Length) const UCHAR* Expected,
    _In_reads_bytes_(Length) const UCHAR* Replacement,
    _Out_writes_bytes_(Length) UCHAR* Postimage
    )
{
    KAPC_STATE apcState;
    NTSTATUS status;
    PVOID target;

    status = STATUS_SUCCESS;
    target = (PVOID)(ULONG_PTR)Address;
    KeStackAttachProcess(Process, &apcState);
    __try {
        ProbeForRead(target, Length, 1);
        if (RtlCompareMemory(target, Expected, Length) != Length) {
            status = STATUS_REVISION_MISMATCH;
        } else {
            ProbeForWrite(target, Length, 1);
            RtlCopyMemory(target, Replacement, Length);
            KeMemoryBarrier();
            RtlCopyMemory(Postimage, target, Length);
            if (RtlCompareMemory(Postimage, Replacement, Length) != Length) {
                /*
                 * Do not overwrite a state that cannot be attributed to this
                 * request. The user-mode provider performs a fresh bounded
                 * read and only submits compare-before-restore when the full
                 * live postimage still equals Replacement.
                 */
                status = STATUS_DATA_ERROR;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    return status;
}

static VOID
KmdInitializeResponse(
    _Out_ KMD_RESPONSE* Response,
    _In_ const KMD_REQUEST* Request,
    _In_ NTSTATUS OperationStatus,
    _In_ ULONG BytesTransferred,
    _In_ ULONG DataLength
    )
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->Magic = KMD_RESPONSE_MAGIC;
    Response->Version = KMD_PROTOCOL_VERSION;
    Response->HeaderSize = sizeof(KMD_RESPONSE);
    Response->TotalSize = sizeof(KMD_RESPONSE) + DataLength;
    Response->Operation = Request->Operation;
    Response->Status = (LONG)OperationStatus;
    Response->Pid = Request->Pid;
    Response->ProcessCreationTime = Request->ProcessCreationTime;
    Response->Address = Request->Address;
    Response->SessionNonce = Request->SessionNonce;
    Response->RequestedLength = Request->Length;
    Response->BytesTransferred = BytesTransferred;
    Response->DataLength = DataLength;
    RtlCopyMemory(
        Response->RequestId,
        Request->RequestId,
        sizeof(Response->RequestId));
}

static NTSTATUS
KmdDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    ULONG inputLength;
    ULONG outputLength;
    ULONG ioControlCode;
    UCHAR* systemBuffer;
    KMD_REQUEST request;
    KMD_RESPONSE* response;
    PEPROCESS process;
    NTSTATUS status;
    ULONG dataLength;
    ULONG bytesTransferred;
    UCHAR* responseData;
    UCHAR* expectedCopy;
    UCHAR* replacementCopy;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    systemBuffer = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || systemBuffer == NULL ||
        inputLength < sizeof(KMD_REQUEST)) {
        return KmdCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    RtlCopyMemory(&request, systemBuffer, sizeof(request));
    status = KmdValidateRequest(
        ioControlCode,
        &request,
        inputLength,
        outputLength);
    if (!NT_SUCCESS(status)) {
        return KmdCompleteIrp(Irp, status, 0);
    }

    response = (KMD_RESPONSE*)systemBuffer;
    responseData = systemBuffer + sizeof(KMD_RESPONSE);
    process = NULL;
    dataLength = 0;
    bytesTransferred = 0;
    expectedCopy = NULL;
    replacementCopy = NULL;

    if (request.Operation == KMD_OPERATION_VERSION) {
        KMD_VERSION_INFO versionInfo;
        RtlZeroMemory(&versionInfo, sizeof(versionInfo));
        versionInfo.Magic = KMD_VERSION_MAGIC;
        versionInfo.StructVersion = 1;
        versionInfo.Size = sizeof(versionInfo);
        versionInfo.ProtocolMin = KMD_PROTOCOL_VERSION;
        versionInfo.ProtocolMax = KMD_PROTOCOL_VERSION;
        versionInfo.MaxReadBytes = KMD_MAX_READ_BYTES;
        versionInfo.MaxWriteBytes = KMD_MAX_WRITE_BYTES;
        versionInfo.OperationMask = KMD_OPERATION_MASK;
        RtlCopyMemory(responseData, &versionInfo, sizeof(versionInfo));
        status = STATUS_SUCCESS;
        dataLength = sizeof(versionInfo);
        bytesTransferred = sizeof(versionInfo);
    } else {
        status = KmdReferenceTargetProcess(&request, &process);
        if (NT_SUCCESS(status) &&
            request.Operation == KMD_OPERATION_QUERY_PROCESS) {
            status = STATUS_SUCCESS;
        } else if (NT_SUCCESS(status) &&
                   request.Operation == KMD_OPERATION_READ) {
            if (!KmdIsUserRangeAllowed(
                    request.Address,
                    request.Length,
                    KMD_MAX_READ_BYTES)) {
                status = STATUS_ACCESS_DENIED;
            } else {
                status = KmdReadAttachedProcess(
                    process,
                    request.Address,
                    request.Length,
                    responseData);
                if (NT_SUCCESS(status)) {
                    dataLength = request.Length;
                    bytesTransferred = request.Length;
                }
            }
        } else if (NT_SUCCESS(status) &&
                   request.Operation == KMD_OPERATION_WRITE) {
            if (g_Configuration.AllowWrite != 1 ||
                !KmdIsUserRangeAllowed(
                    request.Address,
                    request.Length,
                    KMD_MAX_WRITE_BYTES)) {
                status = STATUS_ACCESS_DENIED;
            } else {
                expectedCopy = (UCHAR*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    request.Length,
                    KMD_POOL_TAG);
                replacementCopy = (UCHAR*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    request.Length,
                    KMD_POOL_TAG);
                if (expectedCopy == NULL || replacementCopy == NULL) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                } else {
                    RtlCopyMemory(
                        expectedCopy,
                        systemBuffer + sizeof(KMD_REQUEST),
                        request.Length);
                    RtlCopyMemory(
                        replacementCopy,
                        systemBuffer + sizeof(KMD_REQUEST) + request.Length,
                        request.Length);
                    status = KmdCompareWriteAttachedProcess(
                        process,
                        request.Address,
                        request.Length,
                        expectedCopy,
                        replacementCopy,
                        responseData);
                    if (NT_SUCCESS(status)) {
                        dataLength = request.Length;
                        bytesTransferred = request.Length;
                    }
                }
            }
        }
    }

    if (expectedCopy != NULL) {
        RtlSecureZeroMemory(expectedCopy, request.Length);
        ExFreePoolWithTag(expectedCopy, KMD_POOL_TAG);
    }
    if (replacementCopy != NULL) {
        RtlSecureZeroMemory(replacementCopy, request.Length);
        ExFreePoolWithTag(replacementCopy, KMD_POOL_TAG);
    }
    if (process != NULL) {
        ObDereferenceObject(process);
    }

    KmdInitializeResponse(
        response,
        &request,
        status,
        bytesTransferred,
        dataLength);
    return KmdCompleteIrp(
        Irp,
        STATUS_SUCCESS,
        sizeof(KMD_RESPONSE) + dataLength);
}

static VOID
KmdUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symbolicLink;

    RtlInitUnicodeString(
        &symbolicLink,
        L"\\DosDevices\\ReverseAnalyzerKernelMemory");
    IoDeleteSymbolicLink(&symbolicLink);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    RtlSecureZeroMemory(&g_Configuration, sizeof(g_Configuration));
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    UNICODE_STRING sddl;
    PDEVICE_OBJECT deviceObject;
    NTSTATUS status;
    ULONG index;

    KmdLoadConfiguration(RegistryPath);
    RtlInitUnicodeString(
        &deviceName,
        L"\\Device\\ReverseAnalyzerKernelMemory");
    RtlInitUnicodeString(
        &symbolicLink,
        L"\\DosDevices\\ReverseAnalyzerKernelMemory");
    RtlInitUnicodeString(
        &sddl,
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    deviceObject = NULL;
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &sddl,
        &KmdDeviceClassGuid,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(&g_Configuration, sizeof(g_Configuration));
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        RtlSecureZeroMemory(&g_Configuration, sizeof(g_Configuration));
        return status;
    }

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        DriverObject->MajorFunction[index] = KmdUnsupported;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = KmdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KmdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KmdDeviceControl;
    DriverObject->DriverUnload = KmdUnload;
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
