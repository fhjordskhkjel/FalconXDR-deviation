#include <ntddk.h>
#include "XdrDriverShared.h"

// Simple ring buffer for events (no locking, single producer in callbacks, single consumer in IOCTL with IRQL PASSIVE)
// For safety we raise IRQL to DISPATCH when copying indices.
static XDR_DRIVER_EVENT g_EventBuffer[XDR_MAX_EVENTS];
static volatile LONG g_WriteIndex = 0; // next write slot
static volatile LONG g_ReadIndex = 0;  // next read slot (advanced in IOCTL)
static PDEVICE_OBJECT g_DeviceObject = NULL;

// LSASS pid tracking and suspicious handle callback registration
static ULONG g_LsassPid = 0; // discovered via process create path match
static PVOID g_ObCallbackHandle = NULL;

// Lightweight duplicate suppression for IMAGE_LOAD (pid+base)
#define MAX_IMAGE_SEEN 256
typedef struct _IMG_SEEN { ULONG Pid; ULONGLONG Base; } IMG_SEEN;
static IMG_SEEN g_ImageSeen[MAX_IMAGE_SEEN];
static volatile LONG g_ImageSeenCount = 0;

// Duplicate suppression for handle events (src,target) every N seconds
#define HANDLE_SUPPRESS_SLOTS 64
typedef struct _HANDLE_SEEN { ULONG SrcPid; ULONG TargetPid; ULONGLONG LastTime; } HANDLE_SEEN;
static HANDLE_SEEN g_HandleSeen[HANDLE_SUPPRESS_SLOTS];
static volatile LONG g_HandleSeenInit = 0;
static const ULONGLONG HANDLE_SUPPRESS_INTERVAL_100NS = 5ULL * 1000 * 1000 * 10; // 5s

static BOOLEAN EndsWithInsensitive(const WCHAR* buf, USHORT cch, const WCHAR* suffix){
    if(!buf||!suffix) return FALSE; size_t sl=0; while(suffix[sl]) ++sl; if(sl>cch) return FALSE; const WCHAR* start = buf + (cch - sl); for(size_t i=0;i<sl;i++){ WCHAR a=start[i]; WCHAR b=suffix[i]; if(a>='A'&&a<='Z') a=(WCHAR)(a-'A'+'a'); if(b>='A'&&b<='Z') b=(WCHAR)(b-'A'+'a'); if(a!=b) return FALSE; } return TRUE; }

// Utility: push event (best effort, drop on overflow)
static VOID XdrPushEvent(_In_ const XDR_DRIVER_EVENT* Evt){
    LONG w = InterlockedIncrement(&g_WriteIndex) - 1;
    LONG r = g_ReadIndex; // snapshot
    if (w - r >= XDR_MAX_EVENTS){
        // overflow, drop (do not advance read pointer here)
        return;
    }
    g_EventBuffer[w % XDR_MAX_EVENTS] = *Evt;
}

static ULONGLONG XdrQueryTime(){ LARGE_INTEGER t; KeQuerySystemTimePrecise(&t); return (ULONGLONG)t.QuadPart; }

static BOOLEAN ImageAlreadyReported(ULONG pid, ULONGLONG base){
    LONG count = g_ImageSeenCount; for(LONG i=0;i<count;i++){ if(g_ImageSeen[i].Pid==pid && g_ImageSeen[i].Base==base) return TRUE; }
    // Add
    if(count < MAX_IMAGE_SEEN){ LONG idx = InterlockedIncrement(&g_ImageSeenCount) - 1; if(idx < MAX_IMAGE_SEEN){ g_ImageSeen[idx].Pid=pid; g_ImageSeen[idx].Base=base; } }
    return FALSE;
}

static BOOLEAN ShouldReportHandle(ULONG src, ULONG target, ULONGLONG now){
    // one-time init
    if(InterlockedCompareExchange(&g_HandleSeenInit,1,0)==0){ RtlZeroMemory(g_HandleSeen,sizeof(g_HandleSeen)); }
    for(int i=0;i<HANDLE_SUPPRESS_SLOTS;i++){
        if(g_HandleSeen[i].SrcPid==src && g_HandleSeen[i].TargetPid==target){
            if(now - g_HandleSeen[i].LastTime < HANDLE_SUPPRESS_INTERVAL_100NS) return FALSE;
            g_HandleSeen[i].LastTime = now; return TRUE;
        }
    }
    // insert (simple linear placement)
    for(int i=0;i<HANDLE_SUPPRESS_SLOTS;i++){
        if(g_HandleSeen[i].SrcPid==0){ g_HandleSeen[i].SrcPid=src; g_HandleSeen[i].TargetPid=target; g_HandleSeen[i].LastTime=now; return TRUE; }
    }
    // overwrite oldest if full
    int oldest=0; ULONGLONG oldestTime = g_HandleSeen[0].LastTime; for(int i=1;i<HANDLE_SUPPRESS_SLOTS;i++){ if(g_HandleSeen[i].LastTime < oldestTime){ oldest=i; oldestTime=g_HandleSeen[i].LastTime; } }
    g_HandleSeen[oldest].SrcPid=src; g_HandleSeen[oldest].TargetPid=target; g_HandleSeen[oldest].LastTime=now; return TRUE;
}

// Process create/exit notify
static VOID XdrProcessNotify(_Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo){
    if(CreateInfo){
        XDR_DRIVER_EVENT ev = {0};
        ev.Type = XDR_EVT_PROC_CREATE; ev.Pid = (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess; ev.ParentPid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId; ev.Time100ns = XdrQueryTime();
        if(CreateInfo->ImageFileName && CreateInfo->ImageFileName->Length > 0){ USHORT cch = min((USHORT)259, CreateInfo->ImageFileName->Length/sizeof(WCHAR)); RtlCopyMemory(ev.Path, CreateInfo->ImageFileName->Buffer, cch*sizeof(WCHAR)); ev.Path[cch]=0; if(EndsWithInsensitive(ev.Path, cch, L"\\lsass.exe")) g_LsassPid = ev.Pid; }
        XdrPushEvent(&ev);
    } else {
        // Exit not delivered here (use legacy notify)
    }
}

static VOID XdrProcessNotifyLegacy(_In_ HANDLE ParentId,_In_ HANDLE ProcessId,_In_ BOOLEAN Create){
    if(!Create){ XDR_DRIVER_EVENT ev={0}; ev.Type=XDR_EVT_PROC_EXIT; ev.Pid=(ULONG)(ULONG_PTR)ProcessId; ev.Time100ns=XdrQueryTime(); if(ev.Pid==g_LsassPid) g_LsassPid=0; XdrPushEvent(&ev);} }

// Image load notify
static VOID XdrImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName,_In_ HANDLE ProcessId,_In_ PIMAGE_INFO ImageInfo){
    if(ProcessId==0) return; // system image (ignore for now)
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId; ULONGLONG base=(ULONGLONG)ImageInfo->ImageBase; if(ImageAlreadyReported(pid, base)) return; // duplicate suppression
    XDR_DRIVER_EVENT ev={0}; ev.Type=XDR_EVT_IMAGE_LOAD; ev.Pid=pid; ev.Time100ns=XdrQueryTime(); ev.Arg1=base; ev.Arg2=ImageInfo->ImageSize; if(FullImageName){ USHORT cch=min((USHORT)259,FullImageName->Length/sizeof(WCHAR)); RtlCopyMemory(ev.Path,FullImageName->Buffer,cch*sizeof(WCHAR)); ev.Path[cch]=0;} XdrPushEvent(&ev);
}

// Ob callback for suspicious handle access to LSASS
static OB_PREOP_CALLBACK_STATUS XdrPreOpCallback(_In_ PVOID RegistrationContext,_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation){ UNREFERENCED_PARAMETER(RegistrationContext); if(g_LsassPid==0) return OB_PREOP_SUCCESS; if(OperationInformation->ObjectType==*PsProcessType){ PEPROCESS target = (PEPROCESS)OperationInformation->Object; ULONG targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(target); if(targetPid==g_LsassPid){ ACCESS_MASK desired=0; if(OperationInformation->Operation==OB_OPERATION_HANDLE_CREATE) desired = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess; else desired = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess; // suspicious if requesting VM or write/thread rights
            if(desired & (PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD|PROCESS_DUP_HANDLE)){
                ULONG srcPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId(); ULONGLONG now=XdrQueryTime(); if(ShouldReportHandle(srcPid,targetPid,now)){ XDR_DRIVER_EVENT ev={0}; ev.Type=XDR_EVT_SUSPICIOUS_HANDLE; ev.Pid=srcPid; ev.Arg1=targetPid; ev.Arg2=desired; ev.Time100ns=now; XdrPushEvent(&ev);} }
        } }
    return OB_PREOP_SUCCESS; }
static VOID XdrPostOpCallback(_In_ PVOID RegistrationContext,_In_ POB_POST_OPERATION_INFORMATION OperationInformation){ UNREFERENCED_PARAMETER(RegistrationContext); UNREFERENCED_PARAMETER(OperationInformation); }

// Device control handler
static NTSTATUS XdrDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,_Inout_ PIRP Irp){ UNREFERENCED_PARAMETER(DeviceObject); auto stack=IoGetCurrentIrpStackLocation(Irp); NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST; ULONG outLen=0; if(stack->Parameters.DeviceIoControl.IoControlCode==IOCTL_XDR_GET_EVENTS){ ULONG maxOut=stack->Parameters.DeviceIoControl.OutputBufferLength; if(maxOut >= sizeof(XDR_DRIVER_EVENT)){ LONG r = g_ReadIndex; LONG w = g_WriteIndex; LONG available = w - r; if(available<0) available=0; LONG maxEvents = (LONG)(maxOut / sizeof(XDR_DRIVER_EVENT)); if(available > maxEvents) available = maxEvents; for(LONG i=0;i<available;i++){ ((PXDR_DRIVER_EVENT)Irp->AssociatedIrp.SystemBuffer)[i]= g_EventBuffer[(r+i)%XDR_MAX_EVENTS]; } g_ReadIndex += available; outLen = (ULONG)(available * sizeof(XDR_DRIVER_EVENT)); status=STATUS_SUCCESS; } else { status=STATUS_BUFFER_TOO_SMALL; } }
    Irp->IoStatus.Status=status; Irp->IoStatus.Information=outLen; IoCompleteRequest(Irp, IO_NO_INCREMENT); return status; }

static NTSTATUS XdrCreateClose(_In_ PDEVICE_OBJECT DeviceObject,_Inout_ PIRP Irp){ UNREFERENCED_PARAMETER(DeviceObject); Irp->IoStatus.Status=STATUS_SUCCESS; Irp->IoStatus.Information=0; IoCompleteRequest(Irp,IO_NO_INCREMENT); return STATUS_SUCCESS; }

// Driver unload
static VOID XdrUnload(_In_ PDRIVER_OBJECT DriverObject){ UNREFERENCED_PARAMETER(DriverObject); PsSetCreateProcessNotifyRoutineEx(XdrProcessNotify, TRUE); PsRemoveCreateProcessNotifyRoutine(XdrProcessNotifyLegacy); PsRemoveLoadImageNotifyRoutine(XdrImageLoadNotify); if(g_ObCallbackHandle) ObUnRegisterCallbacks(g_ObCallbackHandle); UNICODE_STRING sym; RtlInitUnicodeString(&sym, XDRDRV_SYMLINK_NAME); IoDeleteSymbolicLink(&sym); if(g_DeviceObject) IoDeleteDevice(g_DeviceObject); }

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){ UNREFERENCED_PARAMETER(RegistryPath); DriverObject->DriverUnload = XdrUnload; for(UINT i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++) DriverObject->MajorFunction[i]=XdrCreateClose; DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=XdrDeviceControl; UNICODE_STRING devName; RtlInitUnicodeString(&devName, XDRDRV_DEVICE_NAME); NTSTATUS status=IoCreateDevice(DriverObject,0,&devName,FILE_DEVICE_UNKNOWN,0,FALSE,&g_DeviceObject); if(!NT_SUCCESS(status)) return status; UNICODE_STRING sym; RtlInitUnicodeString(&sym, XDRDRV_SYMLINK_NAME); status=IoCreateSymbolicLink(&sym,&devName); if(!NT_SUCCESS(status)){ IoDeleteDevice(g_DeviceObject); return status; }
    // Register callbacks
    status=PsSetCreateProcessNotifyRoutineEx(XdrProcessNotify,FALSE); if(!NT_SUCCESS(status)) return status; status=PsSetCreateProcessNotifyRoutine(XdrProcessNotifyLegacy,FALSE); if(!NT_SUCCESS(status)) return status; status=PsSetLoadImageNotifyRoutine(XdrImageLoadNotify); if(!NT_SUCCESS(status)) return status; // Ob callbacks
    OB_OPERATION_REGISTRATION opReg = {0}; opReg.ObjectType = PsProcessType; opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; opReg.PreOperation = XdrPreOpCallback; opReg.PostOperation = XdrPostOpCallback; OB_CALLBACK_REGISTRATION reg = {0}; reg.Version = OB_FLT_REGISTRATION_VERSION; reg.OperationRegistrationCount = 1; reg.OperationRegistration = &opReg; reg.RegistrationContext = nullptr; UNICODE_STRING altitude; RtlInitUnicodeString(&altitude, L"320000" ); reg.Altitude = altitude; status=ObRegisterCallbacks(&reg,&g_ObCallbackHandle); if(!NT_SUCCESS(status)){ g_ObCallbackHandle=NULL; }
    return STATUS_SUCCESS; }
