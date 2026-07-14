#pragma once

#include <ntddk.h>

#define KMD_PROTOCOL_VERSION 1u

#define KMD_REQUEST_MAGIC 0x51524D4Bu /* KMRQ */
#define KMD_RESPONSE_MAGIC 0x53524D4Bu /* KMRS */
#define KMD_VERSION_MAGIC 0x56444D4Bu /* KMDV */

#define KMD_OPERATION_VERSION 1u
#define KMD_OPERATION_QUERY_PROCESS 2u
#define KMD_OPERATION_READ 3u
#define KMD_OPERATION_WRITE 4u

#define KMD_MAX_READ_BYTES (64u * 1024u)
#define KMD_MAX_WRITE_BYTES (4u * 1024u)
#define KMD_MIN_USER_ADDRESS 0x10000ull

#define IOCTL_KMD_VERSION                                                     \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED,                    \
             FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_KMD_QUERY_PROCESS                                               \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED,                    \
             FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_KMD_READ                                                        \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED,                    \
             FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_KMD_WRITE                                                       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED,                    \
             FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(push, 1)

typedef struct _KMD_REQUEST {
    ULONG Magic;
    USHORT Version;
    USHORT HeaderSize;
    ULONG TotalSize;
    ULONG Operation;
    ULONG Flags;
    ULONG Pid;
    ULONGLONG ProcessCreationTime;
    ULONGLONG Address;
    ULONGLONG SessionNonce;
    ULONG Length;
    ULONG ExpectedLength;
    ULONG DataLength;
    ULONG Reserved;
    UCHAR RequestId[16];
} KMD_REQUEST, *PKMD_REQUEST;

typedef struct _KMD_RESPONSE {
    ULONG Magic;
    USHORT Version;
    USHORT HeaderSize;
    ULONG TotalSize;
    ULONG Operation;
    LONG Status;
    ULONG Pid;
    ULONGLONG ProcessCreationTime;
    ULONGLONG Address;
    ULONGLONG SessionNonce;
    ULONG RequestedLength;
    ULONG BytesTransferred;
    ULONG DataLength;
    ULONG Flags;
    UCHAR RequestId[16];
} KMD_RESPONSE, *PKMD_RESPONSE;

typedef struct _KMD_VERSION_INFO {
    ULONG Magic;
    USHORT StructVersion;
    USHORT Size;
    USHORT ProtocolMin;
    USHORT ProtocolMax;
    ULONG MaxReadBytes;
    ULONG MaxWriteBytes;
    ULONG OperationMask;
} KMD_VERSION_INFO, *PKMD_VERSION_INFO;

#pragma pack(pop)

C_ASSERT(sizeof(KMD_REQUEST) == 80);
C_ASSERT(sizeof(KMD_RESPONSE) == 80);
C_ASSERT(sizeof(KMD_VERSION_INFO) == 24);

