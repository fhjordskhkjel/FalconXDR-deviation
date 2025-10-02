# UI and Memory Analysis Feature Improvements

## Summary
This update restores and enhances the memory analysis features in FalconXDR, including memory region browsing and dumping capabilities. The UI has also been improved with better spacing, cleaner layouts, and enhanced usability.

## Changes Made

### 1. Context Menu Restoration
- **Restored missing right-click menu options** in Events and Alerts lists:
  - "Copy" - Copy selected event to clipboard
  - "Export..." - Export selected events to a file
  - "Browse Memory Regions" - Open memory region viewer for the process
  - "Dump Memory..." - Opens memory region viewer with focus on dumping

### 2. Memory Region Browser Window
- **Implemented fully functional memory region window** (`ShowRegionWindow` and `RegionWndProc`):
  - Displays all memory regions for a selected process
  - Shows detailed information for each region:
    - Base address (hexadecimal format)
    - Region size (in KB)
    - Protection flags (RWX, RX, RW, R)
    - Type (Mapped, Private, Unknown)
    - PE Header presence (Yes/No)
    - Status (Normal or ⚠ SUSPICIOUS)
  
- **Suspicious Region Detection**:
  - Automatically flags suspicious memory regions
  - Based on MemoryAnalysis::MemoryRegionInfo.isSuspicious flag
  - Helps identify potential malware indicators like:
    - Executable private memory with PE headers (reflective DLL loading)
    - Executable memory not backed by files
    - Process hollowing artifacts

### 3. Memory Dumping Functionality
- **"Dump Selected" button** in Memory Region window:
  - Select any memory region and dump it to a binary file
  - Automatically suggests filename: `memdump_pid[PID]_0x[ADDRESS].bin`
  - Provides user feedback on success/failure
  - Handles read errors gracefully

- **"Refresh" button** to reload memory regions on demand

### 4. UI Layout Improvements
- **Better spacing and margins**:
  - Increased margins around search controls (6px)
  - Improved vertical spacing between toolbar and content (4px total)
  - Added 2px margins on list views for cleaner look
  
- **Enhanced search bar**:
  - Wider search edit box (220px, was 200px)
  - Larger buttons (70px, were 60px)
  - Better button spacing (4px, 8px gaps)

- **Status bar improvements**:
  - Cleaner formatting with pipe separators
  - Status icons: ▶ COLLECTING, ⏸ STOPPED, ⏸ DISPLAY PAUSED
  - More readable state information

- **Better column widths**:
  - Events column: 1200px (was 800px) for more visible content
  - Line number column: 50px (was 60px) for compact display

### 5. Memory Region Window Enhancements
- **Larger default window size**: 900x650 (was 800x600)
- **Responsive layout**:
  - Buttons positioned at bottom with proper margins
  - ListView auto-resizes with window
  - Better button spacing (28px height, 6px gap)
- **Better column widths**: Proportioned for typical address/size/status display

### 6. Export Selected Functionality
- **New ExportSelected function**: Export only selected events/alerts to a file
- Supports multiple selections
- Separate from "Export All" functionality

### 7. Header File Updates
- Added `ScanProcessMemoryRegions` declaration to `MemoryAnalysis.h`
- Added `std::vector` include for return type
- Maintains consistency with implementation

## Technical Details

### Files Modified
- `XDR/XDR.cpp` - Main application file (316 lines added/modified)
- `XDR/MemoryAnalysis.h` - Header file (4 lines added)

### New Control IDs
- `IDC_LIST_CTX_EXPORT` (5002) - Export selected context menu item
- `IDC_LIST_CTX_DUMPREGION` (5004) - Dump memory context menu item
- `IDC_LIST_CTX_REGIONS` (5005) - Browse regions context menu item
- `IDC_REGION_LIST` (6001) - Region window listview
- `IDC_BTN_REFRESH` (6002) - Refresh regions button
- `IDC_BTN_DUMP` (6003) - Dump memory button

### Dependencies
- Uses `MemoryAnalysis::ScanProcessMemoryRegions()` for region scanning
- Integrates with existing event/alert system
- Compatible with current storage and logging systems

## Usage

### Browsing Memory Regions
1. Right-click on any event or alert that contains a PID
2. Select "Browse Memory Regions"
3. A new window opens showing all memory regions for that process
4. Suspicious regions are marked with ⚠ SUSPICIOUS

### Dumping Memory
1. Open Memory Regions window (as above)
2. Select a region from the list
3. Click "Dump Selected" button
4. Choose save location and filename
5. Binary dump is saved to disk

### Exporting Events
1. Select one or more events in the Events or Alerts list
2. Right-click and select "Export..."
3. Choose save location and filename
4. Selected events are exported as text

## Security Implications

The memory analysis features help detect:
- **Reflective DLL Loading**: Executable memory with PE headers not from normal modules
- **Process Hollowing**: Modified memory regions in legitimate processes
- **Code Injection**: Unexpected executable memory regions
- **Malware Artifacts**: Suspicious memory patterns

## Testing Recommendations

When testing on Windows:
1. Open FalconXDR
2. Generate some test events (start processes, network activity)
3. Right-click on events to verify context menu appears
4. Test "Browse Memory Regions" on a running process (e.g., notepad.exe)
5. Verify suspicious regions are flagged correctly
6. Test memory dumping functionality
7. Verify UI layout looks clean and responsive
8. Test window resizing in both main window and region window

## Known Limitations

- Memory dumping requires PROCESS_VM_READ permission
- Very large memory regions may take time to dump
- Region window is modal per-process (one window per PID)
- No color highlighting for suspicious rows (text marker only)

## Future Enhancements

Possible improvements:
- Custom draw for colored rows in region list
- Hex viewer for dumped memory
- String search within memory regions
- Comparison between multiple dumps
- Auto-YARA scan on dumped regions
- Process tree view with memory info
