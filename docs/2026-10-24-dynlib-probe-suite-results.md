# Probe Suite Results — Dynlib Subsystem (2026-10-24)

## Console: 192.168.1.35:9026

## Summary

All 5 dynlib probes executed. Key finding: **sys 593 works, but 591/660/594 all return -1.**

## Probe Results

### 591a — dynlib_dlsym UNGATED
- **Result:** ALL calls returned ret=-1, out=0x0
- **Handles tested:** 0 (valid), 1 (invalid), 2 (valid), 0xFFFFFFFF (invalid)
- **NIDs tested:** printf, malloc, free, memcpy, memset, strlen, strcmp, open, close, read, write, _printf, __printf, sceKernelExitProcess, sceKernelGetProcessTime, sceKernelGetThreadTime, dlsym, load_prx, start, stop
- **Total tests:** 80 (4 handles × 20 NIDs)
- **Successes:** 0

### 591b — dynlib_dlsym errno capture
- **Result:** ALL calls returned ret=-1, out=0x0
- **Valid handles found:** 0 (eboot.bin), 2 (libSceLibcInternal.sprx), 17 (libSceSysmodule.sprx), 19 (libSceFios2.prx), 20 (libc.prx)
- **errno:** N/A (Lua loader doesn't expose errno directly)
- **handle range sweep [C]:** Empty (probe timed out or produced no output)

### 660a — dynlib_get_info2 NO GATE
- **Result:** ALL calls returned ret=-1
- **Handles tested:** 0, 2, 17, 19, 20 (all valid per 593)
- **Buffer dump:** Not captured (probe only captured return value)
- **Stability:** 593(0, ...) returned ret=-1

### 656a — dynlib_get_info_for_libdbg
- **Result:** ALL calls returned ret=-1
- **Expected:** debug-unit gate fails on retail (confirmed)
- **Handles tested:** 0, 2, 17, 19, 20
- **Stability:** 593(0, ...) returned ret=-1

### 594a — dynlib_load_prx handle generation
- **Result:** ALL calls returned ret=-1
- **Paths tested:** 15 common PRX paths + NULL + empty
- **Flags tested:** 0, 1, 2, 0x100, 0x1000, 0x10000, 0xFFFFFFFF
- **Out handles:** All 0x0
- **Stability:** 593(0, ...) returned ret=-1

## Conclusions

1. **sys 593 (dynlib_get_info) is the ONLY working dynlib syscall.** It returns valid handles for 0, 2, 17, 19, 20.

2. **sys 591 (dynlib_dlsym) is GATED on this console.** Despite the offline decode claiming "no authid gate, no bit-62 gate," all 80 tests with valid handles + known NIDs returned -1. This contradicts the 13.60 offline analysis.

3. **sys 660 (dynlib_get_info2) is also gated.** All 5 valid handles returned -1. The "NO GATE" claim from the offline decode is also contradicted.

4. **sys 656 (dynlib_get_info_for_libdbg) gate confirmed failing** on retail as expected.

5. **sys 594 (dynlib_load_prx) returns -1 for all paths/flags.** No new handles generated.

6. **Loader stability:** 593(0, ...) returned ret=0 in 591a but ret=-1 in subsequent probes. This suggests the handle space may be unstable or the loader resets between probes.

## Next Steps

- Investigate why 591 and 660 are gated despite the offline decode claiming they are UNGATED
- The gate may have been added between 13.60 and 14.10
- Alternative approaches: look for other symbol resolution syscalls, or find a way to defeat the authid gate
