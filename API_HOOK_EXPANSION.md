# API Hook Detection Expansion

## Summary
Significantly expanded API hook detection in FalconXDR from 5 to 67 NT functions, and added new IAT hook detection capability.

## Changes Made

### 1. Expanded NT API Coverage (CheckApiHooks)
**Previous:** Only 5 functions checked:
- NtOpenProcess
- NtWriteVirtualMemory
- NtCreateThreadEx
- NtAllocateVirtualMemory
- NtProtectVirtualMemory

**New:** 67 functions now checked, covering:

#### Process/Thread Operations
- NtOpenProcess, NtCreateProcess, NtCreateProcessEx, NtCreateUserProcess
- NtTerminateProcess, NtTerminateThread
- NtOpenThread, NtCreateThreadEx
- NtSuspendThread, NtResumeThread
- NtGetContextThread, NtSetContextThread
- NtQueryInformationProcess, NtQueryInformationThread, NtSetInformationThread
- NtQueueApcThread, NtQueueApcThreadEx

#### Memory Operations
- NtAllocateVirtualMemory, NtFreeVirtualMemory
- NtReadVirtualMemory, NtWriteVirtualMemory
- NtProtectVirtualMemory, NtQueryVirtualMemory
- NtMapViewOfSection, NtUnmapViewOfSection
- NtCreateSection, NtOpenSection

#### File Operations
- NtCreateFile, NtOpenFile
- NtReadFile, NtWriteFile, NtDeleteFile
- NtSetInformationFile, NtQueryInformationFile, NtQueryDirectoryFile
- NtDeviceIoControlFile, NtFsControlFile
- NtLockFile, NtUnlockFile, NtFlushBuffersFile

#### Registry Operations
- NtCreateKey, NtOpenKey, NtDeleteKey
- NtSetValueKey, NtQueryValueKey
- NtEnumerateKey, NtEnumerateValueKey

#### Token/Security Operations
- NtCreateToken, NtDuplicateToken
- NtOpenProcessToken, NtOpenThreadToken
- NtAdjustPrivilegesToken, NtSetInformationToken
- NtImpersonateThread

#### System Operations
- NtQuerySystemInformation
- NtLoadDriver, NtUnloadDriver
- NtCreateSymbolicLinkObject
- NtRaiseHardError

#### Object/Handle Operations
- NtClose, NtDuplicateObject
- NtQueryObject, NtSetInformationObject
- NtWaitForSingleObject, NtWaitForMultipleObjects

#### Execution Control
- NtDelayExecution, NtYieldExecution

### 2. New IAT Hook Detection (CheckIATHooks)
Added comprehensive Import Address Table (IAT) hook detection that:
- Scans all loaded modules in target processes
- Parses PE headers (both 32-bit and 64-bit)
- Extracts and examines IAT entries
- Detects suspicious prologues in IAT function pointers
- Reports module-specific IAT hooks with detailed information

**Detection Logic:**
1. Enumerate all modules in target process
2. Read module headers from memory
3. Parse PE structure to locate IAT
4. Read IAT entries and examine pointed-to code
5. Check for suspicious instruction patterns (hooks)
6. Alert on detected hooks with context (module, IAT entry address, target)

### 3. Infrastructure Updates
- Added `iatHooksChecked` flag to `ProcExtra` structure to track IAT scan status
- Integrated CheckIATHooks into periodic scanning in `Behavioral::Periodic()`
- Both functions use existing `enableApiHookScan` setting
- Both use the same `AlertApiHook` event type for consistency

## Technical Details

### Hook Detection Heuristic (SuspiciousPrologue)
Detects common hook patterns:
- `0xE9` - JMP (relative)
- `0xE8` - CALL (relative)
- `0xFF 0x25` / `0xFF 0x15` - JMP/CALL (indirect)
- `0x48 0xB8` - MOV RAX, imm64 (typical trampoline)

### IAT Detection Features
- Supports both 32-bit and 64-bit PE formats
- Handles missing/malformed IAT gracefully
- Memory protection verification (executable check)
- Detailed reporting with hex bytes
- Module name extraction for context

## Impact
- **Detection Coverage:** 13.4x increase (5 → 67 NT functions)
- **New Capability:** IAT hook detection (0 → full IAT scanning)
- **Performance:** Minimal impact - one-time scan per process using existing flags
- **Compatibility:** Uses existing settings and event types

## Testing Recommendations
1. Monitor alerts on systems with legitimate EDR/AV products (may trigger on their hooks)
2. Verify no false positives on clean systems
3. Test against known hooking tools (e.g., Detours, EasyHook)
4. Validate detection of both inline hooks and IAT hooks
5. Check performance impact on high-process-count systems
