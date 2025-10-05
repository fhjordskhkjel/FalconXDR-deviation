# Testing Checklist for API Hook Detection Expansion

## Prerequisites
- Windows environment (Windows 10/11 or Windows Server)
- Visual Studio or MSBuild for compilation
- Administrator privileges for testing

## Build Verification
- [ ] Project compiles without errors
- [ ] No new compiler warnings introduced
- [ ] All dependencies resolved

## Functional Testing

### Basic Hook Detection
- [ ] Start FalconXDR application
- [ ] Verify it runs without crashes
- [ ] Check that API hook scanning is enabled in settings
- [ ] Monitor log files for normal operation

### NT API Hook Detection (67 functions)
- [ ] Test against clean system - should see minimal/no alerts
- [ ] Test against system with legitimate EDR/AV (e.g., Windows Defender)
  - May see alerts for hooked functions (expected)
  - Verify alerts are informative and not crashes
- [ ] Test with known hooking tools if available:
  - Microsoft Detours
  - EasyHook
  - MinHook
  - Any custom test hooking code

### IAT Hook Detection
- [ ] Verify IAT hooks are detected on clean applications
- [ ] Test with applications that have hooked IATs
- [ ] Verify both 32-bit and 64-bit module handling
- [ ] Check that module names are correctly extracted

### Alert Quality
- [ ] Verify alerts contain:
  - Process ID and name
  - API function name (for NT hooks)
  - Module name (for IAT hooks)
  - Memory addresses
  - Hex bytes of hook code
  - Disassembly information
- [ ] Check alert de-duplication works (same hook not reported multiple times)

## Performance Testing
- [ ] Monitor CPU usage during scanning
- [ ] Check memory consumption
- [ ] Verify scanning completes in reasonable time
- [ ] Test on systems with many processes (>100)
- [ ] Ensure no memory leaks over extended runtime

## Integration Testing
- [ ] Verify hooks are logged correctly
- [ ] Check database storage of hook events
- [ ] Verify UI displays hook alerts (if applicable)
- [ ] Test correlation with other detection mechanisms

## Edge Cases
- [ ] Process exits during hook scanning
- [ ] Insufficient permissions to read process memory
- [ ] Malformed PE headers in target processes
- [ ] Very large IAT tables
- [ ] Modules without IAT
- [ ] Protected processes (System, csrss, etc.)

## Security Testing
- [ ] Verify XDR itself doesn't crash when encountering anti-analysis
- [ ] Test against known EDR evasion techniques:
  - Heaven's Gate
  - Direct syscalls
  - Manual syscall invocation
  - Hardware breakpoint evasion

## Regression Testing
- [ ] All previous functionality still works
- [ ] Existing alerts still trigger correctly
- [ ] No impact on other detection mechanisms
- [ ] Settings are preserved correctly

## Documentation
- [ ] API_HOOK_EXPANSION.md is accurate
- [ ] Code comments are clear
- [ ] No sensitive information in logs
- [ ] User documentation updated if needed

## Expected Outcomes
1. **Clean System:** Minimal false positives, system APIs should appear clean
2. **With EDR/AV:** Some alerts expected for legitimate security software hooks
3. **With Malware:** Should detect hooking behavior used for evasion
4. **Performance:** No significant impact on system performance

## Known Limitations
- May alert on legitimate security software (EDR, AV, debugging tools)
- Requires PROCESS_VM_READ permission
- Cannot detect some advanced hooking techniques (kernel hooks, hypervisor-based)
- One-time scan per process (not continuous monitoring)

## Notes for Testers
- Keep detailed logs of any issues
- Note specific processes that trigger alerts
- Record system configuration (OS version, security software)
- Capture screenshots of alerts for documentation
- Report any crashes or unexpected behavior immediately
