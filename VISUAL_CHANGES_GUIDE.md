# Visual Changes Guide

## Status Bar Updates

### Before
```
Events: 1234 | Alerts: 56 | ⏸ DISPLAY PAUSED | AutoScroll:ON | Theme: Dark
```

### After
```
Events: 1234 | Alerts: 56 | ⏸ DISPLAY PAUSED | Q: Scan:45 Y:12 H:3 C:1 | Theme: Dark
```

**New Queue Section Breakdown:**
- `Scan:45` - 45 processes being actively monitored
- `Y:12` - 12 memory regions queued for YARA scanning
- `H:3` - 3 processes classified as High priority
- `C:1` - 1 process classified as Critical priority

## Memory Regions Window

### Window Title
```
Memory Regions - PID 1234
```

### Color-Coded Rows

The ListView now displays with background colors:

```
+-------------+--------+------------+--------+----+---------------+
| Address     | Size   | Protection | Type   | PE | Status        | Color
+-------------+--------+------------+--------+----+---------------+
| 0x10000000  | 64 KB  | RWX        | Private| Yes| ⚠ SUSPICIOUS | 🔴 RED
| 0x20000000  | 128 KB | RWX        | Mapped | No | ⚠ SUSPICIOUS | 🟡 YELLOW
| 0x30000000  | 256 KB | RX         | Private| Yes| ⚠ SUSPICIOUS | 🔴 RED
| 0x40000000  | 512 KB | RW         | Private| No | Normal       | 🟢 GREEN
| 0x50000000  | 1024KB | R          | Mapped | No | Normal       | 🟢 GREEN
+-------------+--------+------------+--------+----+---------------+
```

#### Color Legend
- **🔴 Red (RGB 255,200,200)** - Highly suspicious
  - PE headers in private memory (reflective loading)
  - Executable+Writable+Unmapped combination
  
- **🟡 Yellow (RGB 255,255,200)** - Warning
  - RWX permissions (Read-Write-Execute)
  - Potential shellcode or injected code
  
- **🟢 Light Green (RGB 240,255,240)** - Normal
  - Standard memory regions
  - Safe permission combinations

### Button Layout
```
[Refresh]  [Dump Selected]
```
Positioned at bottom with 10px margins

## Alert List Colors

### Alert Severity Visualization

The Alerts list now uses 4 distinct color levels:

```
# | Alert
--+--------------------------------------------------------------------
1 | [12:34:56] ALERT ProcessHollowing pid=1234 ...        🔴 CRITICAL
2 | [12:35:12] ALERT ProcessInjection pid=5678 ...        🟠 HIGH
3 | [12:35:45] ALERT SuspiciousProcess pid=9012 ...       🟡 MEDIUM
4 | [12:36:00] ALERT YaraMatch pid=3456 ...               🟢 LOW
```

#### Color Specifications

**Critical - RGB(255,60,60) - Brightest Red**
Threats requiring immediate action:
- ProcessHollowing
- ReflectiveMemory
- ApiHookSuspicious
- KerberosExtraction

**High - RGB(255,120,80) - Orange-Red**
Serious security events:
- ProcessInjection
- DllInjection
- ReflectiveModule
- PrivilegedExec
- LsassAccess

**Medium - RGB(255,180,80) - Orange**
Suspicious activity:
- SuspiciousProcess
- SuspiciousRemotePort
- ApiHook
- UnsignedModule
- SuspiciousExecRegion

**Low - RGB(255,230,100) - Yellow**
Informational events:
- YaraMatch
- ScreenshotCaptured

### Visual Comparison

#### Old Color Scheme (3 levels)
```
High:   RGB(255,90,90)   - Red
Medium: RGB(255,170,60)  - Orange  
Low:    RGB(255,220,60)  - Yellow
```

#### New Color Scheme (4 levels)
```
Critical: RGB(255,60,60)   - Bright Red   ███
High:     RGB(255,120,80)  - Orange-Red   ███
Medium:   RGB(255,180,80)  - Orange       ███
Low:      RGB(255,230,100) - Yellow       ███
```

**Improvements:**
- More distinct color separation
- Critical level for most severe threats
- Better gradient from red → orange → yellow
- Easier to distinguish at a glance

## Queue Statistics in Action

### Monitoring Example

**Normal Operation:**
```
Q: Scan:20 Y:3 H:0 C:0
```
- 20 processes monitored
- 3 YARA scans pending
- No high-risk processes

**Under Attack:**
```
Q: Scan:35 Y:24 H:8 C:3
```
- 35 processes (elevated activity)
- 24 YARA scans (high backlog)
- 8 high priority processes
- 3 critical priority processes
→ Indicates active threat or compromise

**Heavy Load:**
```
Q: Scan:150 Y:89 H:12 C:1
```
- System under heavy monitoring
- Large YARA backlog
- May need to tune rate limits

## Dark Theme Compatibility

All colors work in both dark and light themes:

### Dark Theme (Default)
- Background: RGB(17,17,17)
- Text: RGB(235,235,235)
- Alert colors pop against dark background
- Memory region colors remain visible

### Light Theme
- Background: RGB(255,255,255)
- Text: RGB(40,40,40)
- Alert colors maintain contrast
- Memory region colors adjusted for readability

## Interaction Examples

### 1. Investigating Suspicious Memory
```
1. See Critical alert in red
2. Right-click → "Browse Memory Regions"
3. Window opens showing colored rows
4. Red rows immediately visible
5. Select red row → "Dump Selected"
6. Analyze dumped memory offline
```

### 2. Monitoring System Load
```
1. Watch status bar: Q: Scan:45 Y:12 H:3 C:1
2. Y count increasing → YARA backlog building
3. H/C counts elevated → Active threats
4. Scan count stable → Normal process churn
```

### 3. Alert Triage
```
1. Alerts list shows mixed colors
2. Focus on red (Critical) first
3. Review orange (High) next
4. Queue medium/low for later
5. Faster incident response
```

## Accessibility Notes

### Color Blindness Considerations
- Text labels still present (⚠ SUSPICIOUS)
- Different brightness levels aid distinction
- Status column provides textual info
- Not solely dependent on color

### Performance
- Custom draw only on visible rows
- Minimal CPU overhead
- No impact on scan performance
- Smooth scrolling maintained

## Keyboard Shortcuts

Existing shortcuts still work:
- `Ctrl+F` - Focus search box
- `Space` - Toggle display pause
- `F5` - Refresh view
- `Ctrl+A` - Toggle auto-scroll
- `Double-click` - Open Memory Regions

## Tips for Best Results

1. **Monitor queue stats regularly**
   - Normal: Scan ≈ processes, Y < 20
   - Alert: Y > 50 or C > 0

2. **Use colors for quick scanning**
   - Glance at alerts for red
   - Check memory regions for red rows
   - Yellow = review when time permits

3. **Combine with search**
   - Filter + colors = powerful triage
   - Search "ProcessInjection" → all red
   - Search "pid=1234" → one process

4. **Export colored findings**
   - Select red alerts
   - Right-click → Export
   - Document for reporting
