#pragma once
// Shared header between kernel driver and user-mode (DriverManager)
// Keep this in sync with DriverManager.h definitions.

#include <ntdef.h>

#define XDRDRV_SYMLINK_NAME       L"\\??\\XDR"   // symbolic link (CreateFile("\\\\.\\XDR"))
#define XDRDRV_DEVICE_NAME        L"\\Device\\XDR" // device object name

// Event types (mirrors user-mode enum XdrDriverEventType)
#define XDR_EVT_PROC_CREATE       1
#define XDR_EVT_PROC_EXIT         2
#define XDR_EVT_IMAGE_LOAD        3
#define XDR_EVT_SUSPICIOUS_HANDLE 4

// IOCTLs (must match user-mode)
#ifndef CTL_CODE
#include <winioctl.h>
#endif
#define IOCTL_XDR_GET_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push,1)
typedef struct _XDR_DRIVER_EVENT {
    ULONG   Type;       // XDR_EVT_*
    ULONG   Pid;
    ULONG   ParentPid;  // valid for create
    ULONG   Reserved;   // alignment / future
    ULONGLONG Time100ns; // KeQuerySystemTimePrecise value
    ULONGLONG Arg1;     // base / target pid / access
    ULONGLONG Arg2;     // size / access mask / misc
    WCHAR   Path[260];  // image path (NT style) or empty
} XDR_DRIVER_EVENT, *PXDR_DRIVER_EVENT;
#pragma pack(pop)

#define XDR_MAX_EVENTS 1024
