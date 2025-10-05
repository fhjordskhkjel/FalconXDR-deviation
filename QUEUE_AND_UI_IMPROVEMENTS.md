# Queue Scanning and UI Improvements

## Overview
This update implements comprehensive improvements to FalconXDR's scanning queue visualization and user interface, making it easier to monitor system activity and identify security threats.

## Key Features

### 1. APCQueues Scanning Visualization

The behavioral analyzer uses priority queues for efficient threat detection:

#### Scan Scheduler Queue
- **Priority-based scheduling** - Processes are scanned based on risk level
- **Adaptive intervals** - High-risk processes scanned more frequently:
  - Critical: Every 5 seconds
  - High: Every 12 seconds
  - Medium: Every 30 seconds
  - Low: Every 60 seconds

#### YARA Queue
- **Memory region scanning** - Suspicious memory regions queued for YARA analysis
- **Rate limiting** - Prevents system overload
- **Per-process budgets** - Max 8 queued tasks per process
- **Global throttling** - 8MB/minute global scan budget

#### Queue Status Display
The status bar now shows real-time queue metrics:
```
Q: Scan:45 Y:12 H:3 C:1
```
- **Scan** - Total processes being monitored
- **Y** - YARA tasks queued for scanning
- **H** - High priority processes
- **C** - Critical priority processes

### 2. Color-Coded Memory Regions

The Memory Regions window now uses visual color coding:

| Color | Meaning | Criteria |
|-------|---------|----------|
| 🔴 Red | **SUSPICIOUS** | PE headers in private memory, or executable+writable+unmapped |
| 🟡 Yellow | **RWX Warning** | Readable, Writable, and Executable (dangerous combination) |
| 🟢 Green | **Normal** | Standard memory regions with safe properties |

**Benefits:**
- Instant visual identification of threats
- No need to read status text for every row
- Easier to spot patterns in memory layout
- Reduces analyst fatigue during investigations

### 3. Enhanced Alert Severity System

Alerts now have 4 distinct severity levels with unique colors:

#### Critical (Bright Red RGB(255,60,60))
- ProcessHollowing - Process memory replacement
- ReflectiveMemory - In-memory PE loading
- ApiHookSuspicious - API hooks to RWX memory
- KerberosExtraction - Credential theft attempts

#### High (Orange-Red RGB(255,120,80))
- ProcessInjection - Code injection detected
- DllInjection - Suspicious DLL loading
- PrivilegedExec - Privilege escalation
- LsassAccess - LSASS process access

#### Medium (Orange RGB(255,180,80))
- SuspiciousProcess - Anomalous process behavior
- ApiHook - Generic API hooking
- UnsignedModule - Unsigned code execution
- SuspiciousExecRegion - High entropy executable regions

#### Low (Yellow RGB(255,230,100))
- YaraMatch - YARA signature hits
- ScreenshotCaptured - Monitoring events

## Technical Implementation

### Code Changes

1. **BehavioralAnalyzer.h** - Added `QueueStats` structure and `GetQueueStats()` function
2. **BehavioralAnalyzer.cpp** - Implemented queue statistics gathering
3. **XDR.cpp** - Updated UI rendering:
   - Status bar expanded to show queue metrics
   - Memory Regions window custom draw implementation
   - Enhanced severity color system

### Performance Considerations

- Queue statistics gathered efficiently (O(n) where n = process count)
- Custom draw only processes visible rows
- No impact on scanning performance
- Minimal memory overhead

## Usage Guide

### Monitoring Queue Activity

Watch the status bar to understand system load:
- High `Scan` count = Many processes monitored
- High `Y` count = YARA backlog (may need tuning)
- High `H`/`C` count = Multiple high-risk processes detected

### Investigating Memory Regions

1. Right-click any alert with a PID
2. Select "Browse Memory Regions"
3. Look for:
   - 🔴 Red rows = Immediate investigation needed
   - 🟡 Yellow rows = Review RWX usage
   - Multiple suspicious regions = Likely compromise

### Alert Prioritization

Use color coding to triage alerts:
1. **Critical (Red)** - Immediate response required
2. **High (Orange-Red)** - Investigate within minutes
3. **Medium (Orange)** - Review within the hour
4. **Low (Yellow)** - Background monitoring

## Configuration

Queue behavior can be tuned via `Settings`:

```cpp
Behavioral::Settings settings;
settings.yaraMaxRegionSize = 512 * 1024;  // Max bytes per scan
settings.yaraGlobalBytesPerMin = 8*1024*1024;  // Global rate limit
settings.yaraPerPidMaxQueued = 8;  // Per-process queue depth
```

## Benefits

### For Security Analysts
- **Faster threat identification** - Visual cues reduce cognitive load
- **Better context** - Queue stats show system-wide activity
- **Improved workflow** - Color coding enables faster triage

### For System Administrators
- **Capacity planning** - Monitor queue depths to understand load
- **Performance tuning** - Adjust priorities based on queue metrics
- **Resource optimization** - See YARA backlog to tune budgets

### For Incident Response
- **Quick memory analysis** - Color-coded regions highlight IOCs
- **Evidence collection** - Easy identification of suspicious regions
- **Pattern recognition** - Visual layout reveals injection techniques

## Future Enhancements

Planned improvements:
- Queue depth history/graphs
- Configurable color schemes
- Queue alerts (high watermark warnings)
- Per-queue statistics (wait times, throughput)
- Export colored reports to HTML
