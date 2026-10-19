# Deep Result File Forensic Scan
# Date: 2026-10-18
# Scanner: deep_result_scanner.py

Total result files: 255

## Summary Statistics
- Kernel pointer candidates: 80
- Deobfuscated kernel pointer candidates: 0
- Userland code pointer candidates: 232
- Heap metadata candidates: 213
- Unusual return values: 2998
- Non-zero buffer data: 13

## Detailed Findings by File

### 01_identity_20261018_083215.txt
**USERLAND CODE POINTERS:**
  Line 17: 0x0000000819B40000
    Context: libkernel_base: 0x819b40000

### 42h2_rop_exploit2_20261016_070945.txt
**USERLAND CODE POINTERS:**
  Line 9: 0x000000080CC80000
    Context: libkernel: 0x80CC80000

### 42h_rop_exploit_20261016_070824.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x0000000834E44000
    Context: h=2 base=0x834E44000 size=0x128000
  Line 86: 0x0000000834E44B57
    Context: looking for stub at 0x834E44B57 (libkernel+0xB57)

**HEAP METADATA CANDIDATES:**
  Line 47: 0x00000000000001E1 (size=0x1E, flags=0x1)
    Context: +0x0D8: 0x0000001E1

### 42i_chain_analysis_20261016_071113.txt
**USERLAND CODE POINTERS:**
  Line 80: 0x000000088033BE40
    Context: +0x228: 0x310722500 H:near_chain *=0x88033BE40
  Line 123: 0x0000000814EA4B57
    Context: address @ 0x814ea4b57

**HEAP METADATA CANDIDATES:**
  Line 95: 0x0000000000000301 (size=0x30, flags=0x1)
    Context: +0x2A0: 0x31071E3E0 H:near_chain *=0x000000301
  Line 105: 0x0000000000000301 (size=0x30, flags=0x1)
    Context: +0x2F0: 0x000000301
  Line 109: 0x0000000000000301 (size=0x30, flags=0x1)
    Context: fn-32: 0x000000301
  Line 116: 0x0000000000000301 (size=0x30, flags=0x1)
    Context: fn+24: 0x000000301

### 43g_sony_syscall_sweep_20261016_180802.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 6: ret=16901 (0x00004205)
    Context: 557: ret=16901  buf=00000000_00000000

### 43n_hid_ioctl_20261016_180856.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 21: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGRDESCSIZE (0x80044801): ret=-2143617020
  Line 22: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGRDESC (0x81004802): ret=-2143617020
  Line 23: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGRAWINFO (0x80044803): ret=-2143617020
  Line 24: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGRAWNAME (0x81004804): ret=-2143617020
  Line 25: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGRAWPHYS (0x81004805): ret=-2143617020
  Line 26: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGFEATURE (0x80404806): ret=-2143617020
  Line 27: ret=-2143617020 (0x803B0004)
    Context: HIDIOCSFEATURE (0x40404807): ret=-2143617020
  Line 28: ret=-2143617020 (0x803B0004)
    Context: HIDIOCGRAWUNIQ (0x81004808): ret=-2143617020
  Line 29: ret=-2143617020 (0x803B0004)
    Context: USB_GET_REPORT_DESC (0x80205515): ret=-2143617020
  Line 30: ret=-2143617020 (0x803B0004)
    Context: USB_GET_REPORT_ID (0x80045517): ret=-2143617020
  ... and 3 more

### 43o_afroute_kaslr_20261016_180647.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 13: ret=108 (0x0000006C)
    Context: read ret=108 bytes

### 44a_mtypeprotect_exec_20261016_182522.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 26: ret=121 (0x00000079)
    Context: nop_sled result: ok=true ret=121 (0x79)
  Line 30: ret=121 (0x00000079)
    Context: mov_eax result: ok=true ret=121 (0x79)
  Line 34: ret=121 (0x00000079)
    Context: syscall result: ok=true ret=121
  Line 40: ret=121 (0x00000079)
    Context: getpid after restore: ok=true ret=121

### 44b_sony557_deep_20261016_182531.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 11: ret=16901 (0x00004205)
    Context: 557(buf, 4096): ret=16901 (0x4205)

### 45a_native_exec_kaslr_20261016_185642.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 19: ret=128 (0x00000080)
    Context: call returned: ok=true ret=128
  Line 32: ret=128 (0x00000080)
    Context: call returned: ok=true ret=128
  Line 38: ret=128 (0x00000080)
    Context: call returned: ok=true ret=128
  Line 46: ret=128 (0x00000080)
    Context: call returned: ok=true ret=128

### 45b_shellcode_write_diag_20261016_191357.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 19: ret=128 (0x00000080)
    Context: NOP+ret: ok=true ret=128 — EXECUTION WORKS
  Line 24: ret=128 (0x00000080)
    Context: exec: ok=true ret=128
  Line 30: ret=128 (0x00000080)
    Context: exec: ok=true ret=128
  Line 36: ret=128 (0x00000080)
    Context: exec: ok=true ret=128
  Line 47: ret=128 (0x00000080)
    Context: bare ret: ok=true ret=128 (0x80)
  Line 48: ret=128 (0x00000080)
    Context: xor eax,eax; ret: ok=true ret=128
  Line 49: ret=128 (0x00000080)
    Context: mov eax,0xBEEF; ret: ok=true ret=128 (0x80)
  Line 50: ret=128 (0x00000080)
    Context: mov eax,0x41414141; ret: ok=true ret=128 (0x80)

### 45c_execution_reality_check_20261016_192713.txt
**USERLAND CODE POINTERS:**
  Line 138: 0x000000083742CB57
    Context: address @ 0x83742cb57

**HEAP METADATA CANDIDATES:**
  Line 19: 0x0000000000000448 (size=0x44, flags=0x8)
    Context: output[0]=0x00000448, len=1096
  Line 23: 0x0000000000000448 (size=0x44, flags=0x8)
    Context: output[0]=0x00000448, len=1096

**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 26: ret=135 (0x00000087)
    Context: fn_addr+00: ok=true ret=135
  Line 27: ret=135 (0x00000087)
    Context: fn_addr+01: ok=true ret=135
  Line 28: ret=135 (0x00000087)
    Context: fn_addr+02: ok=true ret=135
  Line 29: ret=135 (0x00000087)
    Context: fn_addr+03: ok=true ret=135
  Line 30: ret=135 (0x00000087)
    Context: fn_addr+04: ok=true ret=135
  Line 31: ret=135 (0x00000087)
    Context: fn_addr+05: ok=true ret=135
  Line 32: ret=135 (0x00000087)
    Context: fn_addr+06: ok=true ret=135
  Line 33: ret=135 (0x00000087)
    Context: fn_addr+07: ok=true ret=135
  Line 34: ret=135 (0x00000087)
    Context: fn_addr+08: ok=true ret=135
  Line 35: ret=135 (0x00000087)
    Context: fn_addr+09: ok=true ret=135
  ... and 8 more

### 46a_sony_syscall_deep_20261016_194741.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 35: ret=16901 (0x00004205)
    Context: 557({size=0x200}): ret=16901
  Line 36: ret=518 (0x00000206)
    Context: 557({ver=1,size=0x200}): ret=518

### 46a_sony_syscall_deep_20261016_195704.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 35: ret=1038 (0x0000040E)
    Context: 557({size=0x200}): ret=1038
  Line 36: ret=1039 (0x0000040F)
    Context: 557({ver=1,size=0x200}): ret=1039

### 46b_loader_dispatch_20261016_194751.txt
**USERLAND CODE POINTERS:**
  Line 161: 0x000000083742CB57
    Context: pipe tostring: 0x83742cb57

### 46d_socket_bypass_20261016_194839.txt
**HEAP METADATA CANDIDATES:**
  Line 59: 0x0000000000000200 (size=0x20, flags=0x0)
    Context: +004: 0x00000200 (512)
  Line 60: 0x00000000000F4240 (size=0xF424, flags=0x0)
    Context: +008: 0x000F4240 (1000000)
  Line 62: 0x0000000000000218 (size=0x21, flags=0x8)
    Context: +016: 0x00000218 (536)
  Line 63: 0x0000000000000218 (size=0x21, flags=0x8)
    Context: +020: 0x00000218 (536)
  Line 71: 0x0000000000000BB8 (size=0xBB, flags=0x8)
    Context: +052: 0x00000BB8 (3000)

### 47a_dispatch_deep_20261016_195632.txt
**USERLAND CODE POINTERS:**
  Line 53: 0x0000000830764B57
    Context: pipe.fn_addr = 0x830764b57 [table]

**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 64: ret=16901 (0x00004205)
    Context: ver=0 → ret=16901 (0x4205)
  Line 65: ret=518 (0x00000206)
    Context: ver=1 → ret=518 (0x206)
  Line 66: ret=519 (0x00000207)
    Context: ver=2 → ret=519 (0x207)
  Line 67: ret=520 (0x00000208)
    Context: ver=3 → ret=520 (0x208)
  Line 68: ret=521 (0x00000209)
    Context: ver=4 → ret=521 (0x209)
  Line 69: ret=522 (0x0000020A)
    Context: ver=5 → ret=522 (0x20A)
  Line 70: ret=523 (0x0000020B)
    Context: ver=6 → ret=523 (0x20B)
  Line 71: ret=524 (0x0000020C)
    Context: ver=7 → ret=524 (0x20C)
  Line 72: ret=525 (0x0000020D)
    Context: ver=8 → ret=525 (0x20D)
  Line 73: ret=526 (0x0000020E)
    Context: ver=9 → ret=526 (0x20E)
  ... and 255 more

**NON-ZERO BUFFER DATA:**
  Line 25: 0x00000003109B8130
    Context: jmpbuf = 0x3109b8130

### 47b_cclosure_hijack_20261016_200459.txt
**USERLAND CODE POINTERS:**
  Line 47: 0x000000082151CB57
    Context: pipe: address @ 0x82151cb57

### 48b_sctp_loopback_fuzz_20261016_202732.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 33: ret=160 (0x000000A0)
    Context: B17: HEARTBEAT huge                 len=160 ret=160
  Line 34: ret=132 (0x00000084)
    Context: B18: COOKIE_ECHO garbage            len=132 ret=132
  Line 47: ret=232 (0x000000E8)
    Context: B27: 50 ABORT chunks                len=232 ret=232
  Line 48: ret=160 (0x000000A0)
    Context: B28: types 0-15 chain               len=160 ret=160
  Line 63: ret=232 (0x000000E8)
    Context: B39: FWD_TSN 48 streams             len=232 ret=232
  Line 68: ret=132 (0x00000084)
    Context: C3: COOKIE garbage → LAN          len=132 ret=132
  Line 70: ret=232 (0x000000E8)
    Context: C5: 50 ABORTs → LAN               len=232 ret=232

### 49a_tcp_inject_loopback_20261016_205919.txt
**HEAP METADATA CANDIDATES:**
  Line 18: 0x0000000000770700 (size=0x77070, flags=0x0)
    Context: +004: 0x00770700 (7800576)
  Line 19: 0x0000000000038270 (size=0x3827, flags=0x0)
    Context: +008: 0x00038270 (230000)
  Line 21: 0x0000000000003FD8 (size=0x3FD, flags=0x8)
    Context: +016: 0x00003FD8 (16344)
  Line 22: 0x0000000000003FD8 (size=0x3FD, flags=0x8)
    Context: +020: 0x00003FD8 (16344)
  Line 30: 0x0000000000001388 (size=0x138, flags=0x8)
    Context: +052: 0x00001388 (5000)
  Line 34: 0x00000000000003E8 (size=0x3E, flags=0x8)
    Context: +068: 0x000003E8 (1000)
  Line 35: 0x00000000000001F4 (size=0x1F, flags=0x4)
    Context: +072: 0x000001F4 (500)
  Line 50: 0x0000000000770700 (size=0x77070, flags=0x0)
    Context: +004: 0x00770700 (7800576)
  Line 51: 0x00000000000F4240 (size=0xF424, flags=0x0)
    Context: +008: 0x000F4240 (1000000)
  Line 53: 0x0000000000003FD8 (size=0x3FD, flags=0x8)
    Context: +016: 0x00003FD8 (16344)
  ... and 16 more

**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 180: ret=140 (0x0000008C)
    Context: D10: URG+data 100B ptr=0xFFFF              ret=140

### 51a_sony_syscall_survey_20261016_214814.txt
**HEAP METADATA CANDIDATES:**
  Line 30: 0x0000000000000D31 (size=0xD3, flags=0x1)
    Context: [vm] 624: ret=3377 (0x00000000_00000D31)

**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 30: ret=3377 (0x00000D31)
    Context: [vm] 624: ret=3377 (0x00000000_00000D31)

### 51b_accessible_syscall_deep_20261016_214832.txt
**HEAP METADATA CANDIDATES:**
  Line 17: 0x0000000000000D30 (size=0xD3, flags=0x0)
    Context: 624(): ret=0x00000000_00000D30

### 53b_afroute_retest_20261018_091237.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 13: ret=168 (0x000000A8)
    Context: variant hdr=152: write result=RETURNED ret=168
  Line 15: ret=136 (0x00000088)
    Context: variant hdr=152 read attempt 1: RETURNED ret=136

### 53b_afroute_retest_20261018_091257.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 13: ret=168 (0x000000A8)
    Context: variant hdr=152: write result=RETURNED ret=168
  Line 15: ret=136 (0x00000088)
    Context: variant hdr=152 read attempt 1: RETURNED ret=136

### 54d_dmem_page_flip_20261018_091257.txt
**USERLAND CODE POINTERS:**
  Line 48: 0x0000000E00000000
    Context: 588(0xE00000000 (max zone), 0x4000, &struct) = 0

### 54f_kaslr_deep_20261018_090603.txt
**USERLAND CODE POINTERS:**
  Line 19: 0x000000080AA14010
    Context: 649(h=2,m=1) ret=0 buf[0]=0x00000008_0AA14010
  Line 20: 0x000000080AB39060
    Context: 649(h=2,m=2) ret=0 buf[0]=0x00000008_0AB39060
  Line 21: 0x000000080AB3C000
    Context: 649(h=2,m=3) ret=0 buf[0]=0x00000008_0AB3C000
  Line 22: 0x000000080AB4FC50
    Context: 649(h=2,m=4) ret=0 buf[0]=0x00000008_0AB4FC50
  Line 23: 0x00000008243D8010
    Context: 649(h=8193,m=1) ret=0 buf[0]=0x00000008_243D8010
  Line 24: 0x000000082441CF90
    Context: 649(h=8193,m=2) ret=0 buf[0]=0x00000008_2441CF90
  Line 25: 0x0000000824420000
    Context: 649(h=8193,m=3) ret=0 buf[0]=0x00000008_24420000
  Line 26: 0x00000008244242D0
    Context: 649(h=8193,m=4) ret=0 buf[0]=0x00000008_244242D0
  Line 47: 0x0000000A00000210
    Context: iflistl+0x1A8: 0x0000000A_00000210 (high bits set)

**NON-ZERO BUFFER DATA:**
  Line 15: 0x000000004F3A8020
    Context: 649(h=0,m=1) ret=0 buf[0]=0x00000000_4F3A8020
  Line 16: 0x000000004F6B4AC0
    Context: 649(h=0,m=2) ret=0 buf[0]=0x00000000_4F6B4AC0
  Line 17: 0x000000004F821EA8
    Context: 649(h=0,m=3) ret=0 buf[0]=0x00000000_4F821EA8
  Line 18: 0x000000004F7B8CF4
    Context: 649(h=0,m=4) ret=0 buf[0]=0x00000000_4F7B8CF4
  Line 19: 0x000000080AA14010
    Context: 649(h=2,m=1) ret=0 buf[0]=0x00000008_0AA14010
  Line 20: 0x000000080AB39060
    Context: 649(h=2,m=2) ret=0 buf[0]=0x00000008_0AB39060
  Line 21: 0x000000080AB3C000
    Context: 649(h=2,m=3) ret=0 buf[0]=0x00000008_0AB3C000
  Line 22: 0x000000080AB4FC50
    Context: 649(h=2,m=4) ret=0 buf[0]=0x00000008_0AB4FC50
  Line 23: 0x00000008243D8010
    Context: 649(h=8193,m=1) ret=0 buf[0]=0x00000008_243D8010
  Line 24: 0x000000082441CF90
    Context: 649(h=8193,m=2) ret=0 buf[0]=0x00000008_2441CF90
  ... and 2 more

### 54j_sys624_oracle_20261018_083648.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 5: ret=3381 (0x00000D35)
    Context: call  1: ret=3381 (0xD35)
  Line 6: ret=3381 (0x00000D35)
    Context: call  2: ret=3381 (0xD35)
  Line 7: ret=3381 (0x00000D35)
    Context: call  3: ret=3381 (0xD35)
  Line 8: ret=3381 (0x00000D35)
    Context: call  4: ret=3381 (0xD35)
  Line 9: ret=3381 (0x00000D35)
    Context: call  5: ret=3381 (0xD35)
  Line 10: ret=3381 (0x00000D35)
    Context: call  6: ret=3381 (0xD35)
  Line 11: ret=3381 (0x00000D35)
    Context: call  7: ret=3381 (0xD35)
  Line 12: ret=3381 (0x00000D35)
    Context: call  8: ret=3381 (0xD35)
  Line 13: ret=3381 (0x00000D35)
    Context: call  9: ret=3381 (0xD35)
  Line 14: ret=3381 (0x00000D35)
    Context: call 10: ret=3381 (0xD35)
  ... and 10 more

### 54k_sys649_deep_and_rdmsr_20261018_090952.txt
**USERLAND CODE POINTERS:**
  Line 13: 0x00000008375B0010
    Context: h=2 m=  1 ret=0 [0]=0x00000008_375B0010 [8]=0x00000000_00000000
  Line 14: 0x00000008376D5060
    Context: h=2 m=  2 ret=0 [0]=0x00000008_376D5060 [8]=0x00000000_00000000
  Line 15: 0x00000008376D8000
    Context: h=2 m=  3 ret=0 [0]=0x00000008_376D8000 [8]=0x00000000_00000000
  Line 16: 0x00000008376EBC50
    Context: h=2 m=  4 ret=0 [0]=0x00000008_376EBC50 [8]=0x00000000_00000000
  Line 17: 0x000000083775C000
    Context: h=2 m=  7 ret=0 [0]=0x00000008_3775C000 [8]=0x00000000_00000000
  Line 18: 0x0000000837763238
    Context: h=2 m=  8 ret=0 [0]=0x00000008_37763238 [8]=0x00000000_00000000

**HEAP METADATA CANDIDATES:**
  Line 31: 0x0000000000000176 (size=0x17, flags=0x6)
    Context: 0x00000176 SYSENTER_EIP     ret=-1 buf=0x00000000_00000000
  Line 44: 0x0000000000000176 (size=0x17, flags=0x6)
    Context: 0x00000176 SYSENTER_EIP     ret=-1 (0xFFFFFFFFFFFFFFFF_FFFFFFFF)

### 54l_rwx_verify_20261018_091853.txt
**HEAP METADATA CANDIDATES:**
  Line 40: 0x00000000000014B8 (size=0x14B, flags=0x8)
    Context: shellcode[0] = 0x000014B8 (expect 0x000014B8)

### 54n_cclosure_real_cfunc_20261018_092406.txt
**HEAP METADATA CANDIDATES:**
  Line 7: 0x0000000000000206 (size=0x20, flags=0x6)
    Context: +0x08: 0x00000000_00000206
  Line 20: 0x0000000000010406 (size=0x1040, flags=0x6)
    Context: +0x08: 0x00000000_00010406
  Line 48: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: +0x08: 0x00000000_00010106
  Line 87: 0x0000000000000106 (size=0x10, flags=0x6)
    Context: print (C) +0x08: 0x00000000_00000106 (low byte: 0x06)
  Line 88: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: type (C) +0x08: 0x00000000_00010106 (low byte: 0x06)
  Line 90: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: pcall (C) +0x08: 0x00000000_00010106 (low byte: 0x06)

### phase13_53batch\53b_afroute_retest_20261018_091257.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 13: ret=168 (0x000000A8)
    Context: variant hdr=152: write result=RETURNED ret=168
  Line 15: ret=136 (0x00000088)
    Context: variant hdr=152 read attempt 1: RETURNED ret=136

### phase14_final_push\54l_rwx_verify_20261018_091853.txt
**HEAP METADATA CANDIDATES:**
  Line 40: 0x00000000000014B8 (size=0x14B, flags=0x8)
    Context: shellcode[0] = 0x000014B8 (expect 0x000014B8)

### phase14_final_push\54n_cclosure_real_cfunc_20261018_092406.txt
**HEAP METADATA CANDIDATES:**
  Line 7: 0x0000000000000206 (size=0x20, flags=0x6)
    Context: +0x08: 0x00000000_00000206
  Line 20: 0x0000000000010406 (size=0x1040, flags=0x6)
    Context: +0x08: 0x00000000_00010406
  Line 48: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: +0x08: 0x00000000_00010106
  Line 87: 0x0000000000000106 (size=0x10, flags=0x6)
    Context: print (C) +0x08: 0x00000000_00000106 (low byte: 0x06)
  Line 88: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: type (C) +0x08: 0x00000000_00010106 (low byte: 0x06)
  Line 90: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: pcall (C) +0x08: 0x00000000_00010106 (low byte: 0x06)

### phase14_final_push\54r_cfunc_code_bytes_20261018_103421.txt
**HEAP METADATA CANDIDATES:**
  Line 6: 0x0000000000010206 (size=0x1020, flags=0x6)
    Context: +0x08 tag=0x00000000_00010206
  Line 30: 0x0000000000010206 (size=0x1020, flags=0x6)
    Context: +0x08 tag=0x00000000_00010206
  Line 78: 0x0000000000010206 (size=0x1020, flags=0x6)
    Context: +0x08 tag=0x00000000_00010206
  Line 126: 0x0000000000010206 (size=0x1020, flags=0x6)
    Context: +0x08 tag=0x00000000_00010206

### phase14_final_push\55a_chicken_switches_20261018_094008.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 9: ret=4294967295 (0xFFFFFFFF)
    Context: mprotect(RWX) before chicken: ret=4294967295
  Line 18: ret=4294967295 (0xFFFFFFFF)
    Context: mprotect(RWX) after chicken: ret=4294967295
  Line 21: ret=4294967295 (0xFFFFFFFF)
    Context: fork: ret=4294967295

### phase14_final_push\55d_sys601_process_control_20261018_100435.txt
**HEAP METADATA CANDIDATES:**
  Line 7: 0x0000000000000100 (size=0x10, flags=0x0)
    Context: +0x00: 0x00000100

### phase14_final_push\55g_cclosure_write_diagnostic_20261018_103406.txt
**HEAP METADATA CANDIDATES:**
  Line 12: 0x0000000000010206 (size=0x1020, flags=0x6)
    Context: +0x08: 0x00000000_00010206
  Line 29: 0x0000000000010206 (size=0x1020, flags=0x6)
    Context: +0x08: no-op ok=true time=0.0000s val=0x00000000_00010206

### phase14_final_push\56f_controlled_return_20261018_112849.txt
**HEAP METADATA CANDIDATES:**
  Line 22: 0x0000000000010106 (size=0x1010, flags=0x6)
    Context: +0x08: 0x00000000_00010106

### phase14_final_push\56g_syscall_gadget_20261018_113423.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x000000080507C000
    Context: libkernel text: 0x00000008_0507C000
  Line 17: 0x000000080507CB57
    Context: tostring: address @ 0x80507cb57
  Line 118: 0x000000080507CB57
    Context: .fn_addr = 0x80507cb57

### phase14_final_push\56g_syscall_gadget_20261018_113437.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x000000081E764000
    Context: libkernel text: 0x00000008_1E764000
  Line 17: 0x000000081E764B57
    Context: tostring: address @ 0x81e764b57
  Line 118: 0x000000081E764B57
    Context: .fn_addr = 0x81e764b57

### phase14_final_push\56h_kldstat_kaslr_20261018_114516.txt
**USERLAND CODE POINTERS:**
  Line 5: 0x0000000807274000
    Context: libkernel text: 0x00000008_07274000

### phase14_final_push\56i4_vm_region_dump_20261018_120109.txt
**KERNEL POINTERS:**
  Line 472: 0xFFFFFFFE082E0057
    Context: +0x07F8: 0xFFFFFFFE_082E0057 KPTR!

**HEAP METADATA CANDIDATES:**
  Line 449: 0x0000000000000100 (size=0x10, flags=0x0)
    Context: +0x010: 0x00000000_00000100
  Line 455: 0x0000000000002018 (size=0x201, flags=0x8)
    Context: +0x000: 0x00000000_00002018

### phase14_final_push\56i5_kptr_investigate_20261018_120505.txt
**KERNEL POINTERS:**
  Line 25: 0xFFFFFBCE00000034
    Context: rgn[12 '']+0x1E20: 0xFFFFFBCE_00000034
  Line 26: 0xFFFFFBCE00000035
    Context: rgn[12 '']+0x1E48: 0xFFFFFBCE_00000035
  Line 27: 0xFFFFFF6B00000018
    Context: rgn[12 '']+0x1E70: 0xFFFFFF6B_00000018
  Line 28: 0xFFFFFFFE082E0057
    Context: rgn[51 '']+0x07F8: 0xFFFFFFFE_082E0057

### phase14_final_push\56i6_kaslr_pivot_20261018_121034.txt
**KERNEL POINTERS:**
  Line 51: 0xFFFF827000014E08
    Context: data+0x03E38: 0xFFFF8270_00014E08 KPTR!
  Line 52: 0xFFFF830000014E34
    Context: data+0x03E40: 0xFFFF8300_00014E34 KPTR!
  Line 53: 0xFFFF83B000014E60
    Context: data+0x03E48: 0xFFFF83B0_00014E60 KPTR!
  Line 54: 0xFFFF850000014E80
    Context: data+0x03E50: 0xFFFF8500_00014E80 KPTR!
  Line 55: 0xFFFF870000014EB0
    Context: data+0x03E58: 0xFFFF8700_00014EB0 KPTR!
  Line 56: 0xFFFF8AA000014ED8
    Context: data+0x03E60: 0xFFFF8AA0_00014ED8 KPTR!
  Line 57: 0xFFFF8B6000014F04
    Context: data+0x03E68: 0xFFFF8B60_00014F04 KPTR!
  Line 58: 0xFFFF8BA000014F28
    Context: data+0x03E70: 0xFFFF8BA0_00014F28 KPTR!
  Line 59: 0xFFFF8C3000014F3C
    Context: data+0x03E78: 0xFFFF8C30_00014F3C KPTR!
  Line 60: 0xFFFF8C5000014F60
    Context: data+0x03E80: 0xFFFF8C50_00014F60 KPTR!
  Line 61: 0xFFFF8C9000014F74
    Context: data+0x03E88: 0xFFFF8C90_00014F74 KPTR!
  Line 62: 0xFFFF8D0000014F88
    Context: data+0x03E90: 0xFFFF8D00_00014F88 KPTR!
  Line 63: 0xFFFF8E3000014FB0
    Context: data+0x03E98: 0xFFFF8E30_00014FB0 KPTR!
  Line 64: 0xFFFF8EA000014FE0
    Context: data+0x03EA0: 0xFFFF8EA0_00014FE0 KPTR!
  Line 65: 0xFFFF90C000015004
    Context: data+0x03EA8: 0xFFFF90C0_00015004 KPTR!
  Line 66: 0xFFFF921000015030
    Context: data+0x03EB0: 0xFFFF9210_00015030 KPTR!
  Line 67: 0xFFFF935000015060
    Context: data+0x03EB8: 0xFFFF9350_00015060 KPTR!
  Line 68: 0xFFFF94400001508C
    Context: data+0x03EC0: 0xFFFF9440_0001508C KPTR!
  Line 69: 0xFFFF96E0000150B4
    Context: data+0x03EC8: 0xFFFF96E0_000150B4 KPTR!
  Line 70: 0xFFFF9740000150E4
    Context: data+0x03ED0: 0xFFFF9740_000150E4 KPTR!
  Line 73: 0xFFFF806000040740
    Context: data+0x0A428: 0xFFFF8060_00040740 KPTR!
  Line 74: 0xFFFF809000040774
    Context: data+0x0A430: 0xFFFF8090_00040774 KPTR!
  Line 75: 0xFFFF80C000035CC4
    Context: data+0x0A438: 0xFFFF80C0_00035CC4 KPTR!
  Line 76: 0xFFFF80F000035CD8
    Context: data+0x0A440: 0xFFFF80F0_00035CD8 KPTR!
  Line 77: 0xFFFF825000035CEC
    Context: data+0x0A448: 0xFFFF8250_00035CEC KPTR!
  Line 78: 0xFFFF82B000035D1C
    Context: data+0x0A450: 0xFFFF82B0_00035D1C KPTR!
  Line 79: 0xFFFF831000035D30
    Context: data+0x0A458: 0xFFFF8310_00035D30 KPTR!
  Line 80: 0xFFFF834000035D54
    Context: data+0x0A460: 0xFFFF8340_00035D54 KPTR!
  Line 81: 0xFFFF835000035D74
    Context: data+0x0A468: 0xFFFF8350_00035D74 KPTR!
  Line 82: 0xFFFF836000035D88
    Context: data+0x0A470: 0xFFFF8360_00035D88 KPTR!
  Line 83: 0xFFFF84F000035D9C
    Context: data+0x0A478: 0xFFFF84F0_00035D9C KPTR!
  Line 84: 0xFFFF85D000035DCC
    Context: data+0x0A480: 0xFFFF85D0_00035DCC KPTR!
  Line 85: 0xFFFF85E000035DF4
    Context: data+0x0A488: 0xFFFF85E0_00035DF4 KPTR!
  Line 86: 0xFFFF863000035E08
    Context: data+0x0A490: 0xFFFF8630_00035E08 KPTR!
  Line 87: 0xFFFF89000004079C
    Context: data+0x0A498: 0xFFFF8900_0004079C KPTR!
  Line 88: 0xFFFF8AA000035E2C
    Context: data+0x0A4A0: 0xFFFF8AA0_00035E2C KPTR!
  Line 89: 0xFFFF8BD000035E58
    Context: data+0x0A4A8: 0xFFFF8BD0_00035E58 KPTR!
  Line 90: 0xFFFF8DE000035E84
    Context: data+0x0A4B0: 0xFFFF8DE0_00035E84 KPTR!
  Line 91: 0xFFFF8FC000035EB4
    Context: data+0x0A4B8: 0xFFFF8FC0_00035EB4 KPTR!
  Line 92: 0xFFFF90D000035EE4
    Context: data+0x0A4C0: 0xFFFF90D0_00035EE4 KPTR!
  Line 96: 0xFFFF80F00000146C
    Context: mod[17] data+0x002E8: 0xFFFF80F0_0000146C
  Line 97: 0xFFFF81900000149C
    Context: mod[17] data+0x002F0: 0xFFFF8190_0000149C
  Line 98: 0xFFFF81F0000014C4
    Context: mod[17] data+0x002F8: 0xFFFF81F0_000014C4
  Line 99: 0xFFFF8650000014EC
    Context: mod[17] data+0x00300: 0xFFFF8650_000014EC
  Line 100: 0xFFFF86600000151C
    Context: mod[17] data+0x00308: 0xFFFF8660_0000151C
  Line 101: 0xFFFF867000001530
    Context: mod[17] data+0x00310: 0xFFFF8670_00001530
  Line 102: 0xFFFF871000001544
    Context: mod[17] data+0x00318: 0xFFFF8710_00001544
  Line 103: 0xFFFF87C000001568
    Context: mod[17] data+0x00320: 0xFFFF87C0_00001568
  Line 104: 0xFFFF8BF000001594
    Context: mod[17] data+0x00328: 0xFFFF8BF0_00001594
  Line 105: 0xFFFF8C20000015CC
    Context: mod[17] data+0x00330: 0xFFFF8C20_000015CC
  Line 106: 0xFFFF8C50000015E0
    Context: mod[17] data+0x00338: 0xFFFF8C50_000015E0
  Line 107: 0xFFFF8D40000015F4
    Context: mod[17] data+0x00340: 0xFFFF8D40_000015F4
  Line 108: 0xFFFF8D9000001624
    Context: mod[17] data+0x00348: 0xFFFF8D90_00001624
  Line 109: 0xFFFF8E2000001648
    Context: mod[17] data+0x00350: 0xFFFF8E20_00001648
  Line 110: 0xFFFF8E7000001670
    Context: mod[17] data+0x00358: 0xFFFF8E70_00001670
  Line 111: 0xFFFF90E000001698
    Context: mod[17] data+0x00360: 0xFFFF90E0_00001698
  Line 112: 0xFFFF90F0000016C0
    Context: mod[17] data+0x00368: 0xFFFF90F0_000016C0
  Line 113: 0xFFFF9100000016D4
    Context: mod[17] data+0x00370: 0xFFFF9100_000016D4
  Line 114: 0xFFFF94A0000016E8
    Context: mod[17] data+0x00378: 0xFFFF94A0_000016E8
  Line 115: 0xFFFF94B000001718
    Context: mod[17] data+0x00380: 0xFFFF94B0_00001718
  Line 116: 0xFFFF94C00000172C
    Context: mod[17] data+0x00388: 0xFFFF94C0_0000172C
  Line 117: 0xFFFF95C000001740
    Context: mod[17] data+0x00390: 0xFFFF95C0_00001740
  Line 118: 0xFFFF95D00000176C
    Context: mod[17] data+0x00398: 0xFFFF95D0_0000176C
  Line 119: 0xFFFF95E000001780
    Context: mod[17] data+0x003A0: 0xFFFF95E0_00001780
  Line 120: 0xFFFF95F000001794
    Context: mod[17] data+0x003A8: 0xFFFF95F0_00001794
  Line 121: 0xFFFF9600000017A8
    Context: mod[17] data+0x003B0: 0xFFFF9600_000017A8
  Line 122: 0xFFFF9610000017BC
    Context: mod[17] data+0x003B8: 0xFFFF9610_000017BC
  Line 123: 0xFFFF9620000017D0
    Context: mod[17] data+0x003C0: 0xFFFF9620_000017D0
  Line 124: 0xFFFF9630000017E4
    Context: mod[17] data+0x003C8: 0xFFFF9630_000017E4
  Line 125: 0xFFFF9640000017F8
    Context: mod[17] data+0x003D0: 0xFFFF9640_000017F8

**HEAP METADATA CANDIDATES:**
  Line 17: 0x00000000000021B6 (size=0x21B, flags=0x6)
    Context: fd=0: dev=0x0000002A_7113FF71 ino=0x00000000_000021B6 mode=0x6AD4BA26
  Line 18: 0x00000000000021B6 (size=0x21B, flags=0x6)
    Context: fd=1: dev=0x00000012_7113FF71 ino=0x00000000_000021B6 mode=0x6AD4BA26
  Line 19: 0x00000000000021B6 (size=0x21B, flags=0x6)
    Context: fd=2: dev=0x00000013_7113FF71 ino=0x00000000_000021B6 mode=0x6AD4BA26
  Line 20: 0x00000000000021B6 (size=0x21B, flags=0x6)
    Context: fd=3: dev=0x00000018_7113FF71 ino=0x00000000_000021B6 mode=0x6AD4BA26
  Line 24: 0x000000000000B000 (size=0xB00, flags=0x0)
    Context: fd=7: dev=0x00000000_00000000 ino=0x00000000_0000B000 mode=0x0
  Line 25: 0x00000000000021B6 (size=0x21B, flags=0x6)
    Context: fd=8: dev=0x0000006C_7113FF71 ino=0x00000000_000021B6 mode=0x6AD4BA26
  Line 26: 0x00000000000091B6 (size=0x91B, flags=0x6)
    Context: fd=9: dev=0x00000000_00000000 ino=0x00000000_000091B6 mode=0x0
  Line 27: 0x00000000000021B6 (size=0x21B, flags=0x6)
    Context: fd=10: dev=0x000000A1_7113FF71 ino=0x00000000_000021B6 mode=0x6AD4BA26

**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 32: ret=1376 (0x00000560)
    Context: getdirentries ret=1376

### phase14_final_push\56i7_kptr_validate_20261018_121302.txt
**HEAP METADATA CANDIDATES:**
  Line 45: 0x0000000000014E08 (size=0x14E0, flags=0x8)
    Context: +0x3E38: hi=0xFFFF8270 lo=0x00014E08  delta_hi=0
  Line 46: 0x0000000000014E34 (size=0x14E3, flags=0x4)
    Context: +0x3E40: hi=0xFFFF8300 lo=0x00014E34  delta_hi=144
  Line 47: 0x0000000000014E60 (size=0x14E6, flags=0x0)
    Context: +0x3E48: hi=0xFFFF83B0 lo=0x00014E60  delta_hi=176
  Line 48: 0x0000000000014E80 (size=0x14E8, flags=0x0)
    Context: +0x3E50: hi=0xFFFF8500 lo=0x00014E80  delta_hi=336
  Line 49: 0x0000000000014EB0 (size=0x14EB, flags=0x0)
    Context: +0x3E58: hi=0xFFFF8700 lo=0x00014EB0  delta_hi=512
  Line 50: 0x0000000000014ED8 (size=0x14ED, flags=0x8)
    Context: +0x3E60: hi=0xFFFF8AA0 lo=0x00014ED8  delta_hi=928
  Line 51: 0x0000000000014F04 (size=0x14F0, flags=0x4)
    Context: +0x3E68: hi=0xFFFF8B60 lo=0x00014F04  delta_hi=192
  Line 52: 0x0000000000014F28 (size=0x14F2, flags=0x8)
    Context: +0x3E70: hi=0xFFFF8BA0 lo=0x00014F28  delta_hi=64
  Line 54: 0x0000000000014F60 (size=0x14F6, flags=0x0)
    Context: +0x3E80: hi=0xFFFF8C50 lo=0x00014F60  delta_hi=32
  Line 55: 0x0000000000014F74 (size=0x14F7, flags=0x4)
    Context: +0x3E88: hi=0xFFFF8C90 lo=0x00014F74  delta_hi=64
  ... and 48 more

### phase14_final_push\56i8_eboot_data_kptr_20261018_121608.txt
**KERNEL POINTERS:**
  Line 12: 0xFFFF827000014E08
    Context: [0] 0xFFFF8270_00014E08
  Line 13: 0xFFFF830000014E34
    Context: [1] 0xFFFF8300_00014E34
  Line 14: 0xFFFF83B000014E60
    Context: [2] 0xFFFF83B0_00014E60
  Line 15: 0xFFFF850000014E80
    Context: [3] 0xFFFF8500_00014E80
  Line 16: 0xFFFF870000014EB0
    Context: [4] 0xFFFF8700_00014EB0

**USERLAND CODE POINTERS:**
  Line 24: 0x000000080B264B57
    Context: pipe_str: address @ 0x80b264b57

### phase14_final_push\56j_timing_kaslr_20261018_122158.txt
**USERLAND CODE POINTERS:**
  Line 46: 0x0000000881DF0080
    Context: sysarch(128) ret=0 fsbase=0x00000008_81DF0080

**HEAP METADATA CANDIDATES:**
  Line 30: 0x00000000000030F7 (size=0x30F, flags=0x7)
    Context: +0x08: 0x00000000_000030F7
  Line 33: 0x0000000000460320 (size=0x46032, flags=0x0)
    Context: +0x20: 0x00000000_00460320
  Line 34: 0x00000000007CDD10 (size=0x7CDD1, flags=0x0)
    Context: +0x28: 0x00000000_007CDD10
  Line 35: 0x0000000000886080 (size=0x88608, flags=0x0)
    Context: +0x30: 0x00000000_00886080
  Line 36: 0x0000000000050E80 (size=0x50E8, flags=0x0)
    Context: +0x38: 0x00000000_00050E80
  Line 43: 0x00000000000006A0 (size=0x6A, flags=0x0)
    Context: +0x88: 0x00000000_000006A0

### phase1_identity_layout\01_identity_20261015_184244.txt
**USERLAND CODE POINTERS:**
  Line 17: 0x000000080B8E4000
    Context: libkernel_base: 0x80b8e4000

### phase1_identity_layout\01_identity_20261018_094017.txt
**USERLAND CODE POINTERS:**
  Line 17: 0x000000082E420000
    Context: libkernel_base: 0x82e420000

### phase1_identity_layout\01_identity_20261018_094147.txt
**USERLAND CODE POINTERS:**
  Line 17: 0x000000083B6F0000
    Context: libkernel_base: 0x83b6f0000

### phase1_identity_layout\01_identity_20261018_094249.txt
**USERLAND CODE POINTERS:**
  Line 17: 0x0000000835CDC000
    Context: libkernel_base: 0x835cdc000

### phase1_identity_layout\08_read_offsets_20261015_185427.txt
**HEAP METADATA CANDIDATES:**
  Line 992: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: DATA_BASE_DYNAMIC = 0x00010000,
  Line 1011: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: DATA_BASE_DYNAMIC = 0x00010000,
  Line 1030: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: DATA_BASE_DYNAMIC = 0x00010000,
  Line 1049: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: DATA_BASE_DYNAMIC = 0x00010000,
  Line 1068: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: DATA_BASE_DYNAMIC = 0x00010000,
  Line 1087: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: DATA_BASE_DYNAMIC = 0x00010000,
  Line 1090: 0x0000000000AC8064 (size=0xAC806, flags=0x4)
    Context: DATA_BASE_SECURITY_FLAGS = 0x00AC8064,

### phase2_kernel_objects\12_nwake_robust_20261015_190720.txt
**HEAP METADATA CANDIDATES:**
  Line 14: 0x0000000000000100 (size=0x10, flags=0x0)
    Context: count=0x00000100 (       256): -1
  Line 15: 0x0000000000000400 (size=0x40, flags=0x0)
    Context: count=0x00000400 (      1024): -1
  Line 16: 0x0000000000001000 (size=0x100, flags=0x0)
    Context: count=0x00001000 (      4096): -1
  Line 17: 0x0000000000004000 (size=0x400, flags=0x0)
    Context: count=0x00004000 (     16384): -1
  Line 18: 0x0000000000010000 (size=0x1000, flags=0x0)
    Context: count=0x00010000 (     65536): -1
  Line 19: 0x0000000000040000 (size=0x4000, flags=0x0)
    Context: count=0x00040000 (    262144): -1
  Line 20: 0x0000000000100000 (size=0x10000, flags=0x0)
    Context: count=0x00100000 (   1048576): -1
  Line 36: 0x0000000001000000 (size=0x100000, flags=0x0)
    Context: count=0x01000000 (16M): 0.0000 sec
  Line 65: 0x0000000000001000 (size=0x100, flags=0x0)
    Context: +0: 0x0000000000001000

### phase2_kernel_objects\14_device_ioctl_20261015_191602.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 21224: ret=-2143617020 (0x803B0004)
    Context: cmd=0x20006400 grp=d num=0 sz=0 rv=-2143617020 LEAK:32qw
  Line 21226: ret=-2143617020 (0x803B0004)
    Context: cmd=0x40046400 grp=d num=0 sz=4 rv=-2143617020 LEAK:32qw
  Line 21228: ret=-2143617020 (0x803B0004)
    Context: cmd=0x40086400 grp=d num=0 sz=8 rv=-2143617020 LEAK:32qw
  Line 21230: ret=-2143617020 (0x803B0004)
    Context: cmd=0x40106400 grp=d num=0 sz=16 rv=-2143617020 LEAK:32qw
  Line 21232: ret=-2143617020 (0x803B0004)
    Context: cmd=0x40206400 grp=d num=0 sz=32 rv=-2143617020 LEAK:32qw
  Line 21234: ret=-2143617020 (0x803B0004)
    Context: cmd=0x40406400 grp=d num=0 sz=64 rv=-2143617020 LEAK:32qw
  Line 21236: ret=-2143617020 (0x803B0004)
    Context: cmd=0x40806400 grp=d num=0 sz=128 rv=-2143617020 LEAK:32qw
  Line 21238: ret=-2143617020 (0x803B0004)
    Context: cmd=0x41006400 grp=d num=0 sz=256 rv=-2143617020 LEAK:32qw
  Line 21240: ret=-2143617020 (0x803B0004)
    Context: cmd=0x44006400 grp=d num=0 sz=1024 rv=-2143617020 LEAK:32qw
  Line 21242: ret=-2143617020 (0x803B0004)
    Context: cmd=0x20006401 grp=d num=1 sz=0 rv=-2143617020 LEAK:32qw
  ... and 2627 more

### phase2_kernel_objects\18_dmem_phys_20261015_192222.txt
**HEAP METADATA CANDIDATES:**
  Line 11: 0x00000000002C0000 (size=0x2C000, flags=0x0)
    Context: 0x00000000002c0000 from +0x10950 ALIGNED
  Line 12: 0x0000000000400027 (size=0x40002, flags=0x7)
    Context: 0x0000000000400027 from +0x16a58
  Line 75: 0x00000000002C0000 (size=0x2C000, flags=0x0)
    Context: phys=0x00000000002c0000: MAPPED nz=0

### phase4_ipc_network\30b_fcntl_scm_20261015_201028.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 10: ret=1024 (0x00000400)
    Context: writev 16x64: rv=1024
  Line 11: ret=1024 (0x00000400)
    Context: readv 16x64: rv=1024
  Line 12: ret=1024 (0x00000400)
    Context: writev 1024x1: rv=1024

### phase4_ipc_network\31_sockopt_fuzz_20261015_202000.txt
**HEAP METADATA CANDIDATES:**
  Line 11: 0x0000000000000218 (size=0x21, flags=0x8)
    Context: get TCP_MAXSEG           rv=0 len=4 val=0x00000218,deaddead

### phase4_ipc_network\31b_tcpinfo_dump_20261015_202500.txt
**HEAP METADATA CANDIDATES:**
  Line 35: 0x00000000000F4240 (size=0xF424, flags=0x0)
    Context: @008: 0x00000000000f4240
  Line 72: 0x0000000000038270 (size=0x3827, flags=0x0)
    Context: @008: 0x0000000000038270
  Line 77: 0x0000000000007F98 (size=0x7F9, flags=0x8)
    Context: @050: 0x0000000000007f98
  Line 100: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: SOL 0x01001: len=4 val=0x00002000 00000000
  Line 101: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: SOL 0x01002: len=4 val=0x00002000 00000000
  Line 102: 0x0000000000000800 (size=0x80, flags=0x0)
    Context: SOL 0x01003: len=4 val=0x00000800 00000000

### phase4_ipc_network\31c_ps5opts_fuzz_20261015_203000.txt
**HEAP METADATA CANDIDATES:**
  Line 22: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: 0x1001: len=4 val=0x00002000
  Line 23: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: 0x1002: len=4 val=0x00002000
  Line 24: 0x0000000000000800 (size=0x80, flags=0x0)
    Context: 0x1003: len=4 val=0x00000800
  Line 44: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0x1): rv=0 readback=0x00002000
  Line 45: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0x2): rv=0 readback=0x00002000
  Line 46: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0xff): rv=0 readback=0x00002000
  Line 47: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0xffff): rv=0 readback=0x00002000
  Line 48: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0x7fffffff): rv=0 readback=0x00002000
  Line 49: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0x80000000): rv=0 readback=0x00002000
  Line 50: 0x0000000000002000 (size=0x200, flags=0x0)
    Context: set(0xffffffff): rv=0 readback=0x00002000
  ... and 38 more

### phase7_heap_exploitation\41p_libkernel_gadgets_20261015_232718.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x00000008149E8000
    Context: text base: 0x00000008149E8000
  Line 8: 0x0000000814A30000
    Context: data base: 0x0000000814A30000

### phase7_heap_exploitation\41p_libkernel_gadgets_20261015_232807.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x0000000832AEC000
    Context: text base: 0x832AEC000
  Line 8: 0x0000000832B34000
    Context: data base: 0x832B34000

### phase7_heap_exploitation\41q_segment_readability_20261015_232935.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x000000081FC38000
    Context: [ 1] h=0x2001 libkernel.sprx                   0x81FC38000+0x48000 | 0x81FC80000+0x20000 | 0x81FCA0000+0x4000 | 0x81FCA4
  Line 6: 0x000000081FC80000
    Context: [ 1] h=0x2001 libkernel.sprx                   0x81FC38000+0x48000 | 0x81FC80000+0x20000 | 0x81FCA0000+0x4000 | 0x81FCA4
  Line 6: 0x000000081FCA0000
    Context: [ 1] h=0x2001 libkernel.sprx                   0x81FC38000+0x48000 | 0x81FC80000+0x20000 | 0x81FCA0000+0x4000 | 0x81FCA4
  Line 6: 0x000000081FCA4000
    Context: [ 1] h=0x2001 libkernel.sprx                   0x81FC38000+0x48000 | 0x81FC80000+0x20000 | 0x81FCA0000+0x4000 | 0x81FCA4
  Line 7: 0x00000008350A0000
    Context: [ 2] h=0x0002 libSceLibcInternal.sprx          0x8350A0000+0x128000 | 0x8351C8000+0x84000 | 0x83524C000+0x8000 | 0x83525
  Line 7: 0x00000008351C8000
    Context: [ 2] h=0x0002 libSceLibcInternal.sprx          0x8350A0000+0x128000 | 0x8351C8000+0x84000 | 0x83524C000+0x8000 | 0x83525
  Line 7: 0x000000083524C000
    Context: [ 2] h=0x0002 libSceLibcInternal.sprx          0x8350A0000+0x128000 | 0x8351C8000+0x84000 | 0x83524C000+0x8000 | 0x83525
  Line 7: 0x0000000835254000
    Context: [ 2] h=0x0002 libSceLibcInternal.sprx          0x8350A0000+0x128000 | 0x8351C8000+0x84000 | 0x83524C000+0x8000 | 0x83525
  Line 8: 0x00000008334F4000
    Context: [ 3] h=0x0011 libSceSysmodule.sprx             0x8334F4000+0xC000 | 0x833500000+0x8000 | 0x833508000+0x4000 | 0x83350C00
  Line 8: 0x0000000833500000
    Context: [ 3] h=0x0011 libSceSysmodule.sprx             0x8334F4000+0xC000 | 0x833500000+0x8000 | 0x833508000+0x4000 | 0x83350C00
  ... and 135 more

### phase7_heap_exploitation\41r_eboot_gadgets_20261015_233051.txt
**USERLAND CODE POINTERS:**
  Line 59: 0x000000081737C000
    Context: libkernel data at 0x81737C000 sz=0x20000

### phase7_heap_exploitation\41v_got_dump_20261015_233933.txt
**USERLAND CODE POINTERS:**
  Line 7: 0x00000008283C0000
    Context: libkernel: 0x8283C0000 sz=0x48000
  Line 31: 0x00000008283C0000
    Context: libkernel base: 0x8283C0000
  Line 36: 0x00000008283C0000
    Context: libkernel+0x0000: 0x8283C0000
  Line 37: 0x00000008283C0004
    Context: libkernel+0x0004: 0x8283C0004
  Line 38: 0x00000008283C0008
    Context: libkernel+0x0008: 0x8283C0008
  Line 39: 0x00000008283C000C
    Context: libkernel+0x000C: 0x8283C000C
  Line 40: 0x00000008283C0010
    Context: libkernel+0x0010: 0x8283C0010
  Line 41: 0x00000008283C0014
    Context: libkernel+0x0014: 0x8283C0014
  Line 42: 0x00000008283C0018
    Context: libkernel+0x0018: 0x8283C0018
  Line 43: 0x00000008283C001C
    Context: libkernel+0x001C: 0x8283C001C
  ... and 4 more

### phase7_heap_exploitation\41w_kernel_rw_20261015_234305.txt
**USERLAND CODE POINTERS:**
  Line 5: 0x00000008281F0000
    Context: libkernel base: 0x8281F0000
  Line 6: 0x00000008281F0000
    Context: syscall stub: 0x8281F0000+0xB57

### phase7_heap_exploitation\41z_chain_hijack_20261015_235238.txt
**HEAP METADATA CANDIDATES:**
  Line 44: 0x0000000000000301 (size=0x30, flags=0x1)
    Context: chain+0x298 -> slot 0x31080E3E0 = 0x000000301

### phase9_kaslr_defeat\42b_kaslr_defeat_20261016_065521.txt
**USERLAND CODE POINTERS:**
  Line 25: 0x000000082D4B0000
    Context: [1] h=8193 libkernel.sprx text=0x82D4B0000 data=0x82D4F8000
  Line 25: 0x000000082D4F8000
    Context: [1] h=8193 libkernel.sprx text=0x82D4B0000 data=0x82D4F8000
  Line 26: 0x000000082D554000
    Context: [2] h=2 libSceLibcInternal.sprx text=0x82D554000 data=0x82D67C000
  Line 26: 0x000000082D67C000
    Context: [2] h=2 libSceLibcInternal.sprx text=0x82D554000 data=0x82D67C000
  Line 27: 0x0000000832240000
    Context: [3] h=17 libSceSysmodule.sprx text=0x832240000 data=0x83224C000
  Line 27: 0x000000083224C000
    Context: [3] h=17 libSceSysmodule.sprx text=0x832240000 data=0x83224C000
  Line 30: 0x000000080B328000
    Context: [6] h=34 libSceNet.sprx text=0x80B328000 data=0x80B35C000
  Line 30: 0x000000080B35C000
    Context: [6] h=34 libSceNet.sprx text=0x80B328000 data=0x80B35C000
  Line 31: 0x0000000817B14000
    Context: [7] h=49 libSceIpmi.sprx text=0x817B14000 data=0x817B1C000
  Line 31: 0x0000000817B1C000
    Context: [7] h=49 libSceIpmi.sprx text=0x817B14000 data=0x817B1C000
  ... and 17 more

## Cross-Run Value Comparison

### Probe: 45c_execution_reality_check
  Files: 45c_execution_reality_check_20261016_192602.txt vs 45c_execution_reality_check_20261016_192713.txt
  Values only in file 2: 1
    0x4141414141414141

### Probe: 51a_sony_syscall_survey
  Files: 51a_sony_syscall_survey_20261016_214814.txt vs 51a_sony_syscall_survey_20261016_220811.txt
  Values only in file 1: 2
    0x0000000000000000
    0x0000000000000D31

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_093008.txt vs 54p_redirect_minimal_20261018_093839.txt
  Values only in file 1: 4
    0x00000000478C8000
    0x00000000478C8471
    0x0000000047A6ECD0
    0x0000000310E13EC0

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_093008.txt vs 54p_redirect_minimal_20261018_094036.txt
  Values only in file 1: 4
    0x00000000478C8000
    0x00000000478C8471
    0x0000000047A6ECD0
    0x0000000310E13EC0

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_093008.txt vs 54p_redirect_minimal_20261018_094206.txt
  Values only in file 1: 4
    0x00000000478C8000
    0x00000000478C8471
    0x0000000047A6ECD0
    0x0000000310E13EC0

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_093008.txt vs 54p_redirect_minimal_20261018_094326.txt
  Values only in file 1: 4
    0x00000000478C8000
    0x00000000478C8471
    0x0000000047A6ECD0
    0x0000000310E13EC0
  Values only in file 2: 4
    0x0000000023C98000
    0x0000000023C98471
    0x0000000023E3ECD0
    0x0000000310967EC0

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_093839.txt vs 54p_redirect_minimal_20261018_094326.txt
  Values only in file 2: 4
    0x0000000023C98000
    0x0000000023C98471
    0x0000000023E3ECD0
    0x0000000310967EC0

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_094036.txt vs 54p_redirect_minimal_20261018_094326.txt
  Values only in file 2: 4
    0x0000000023C98000
    0x0000000023C98471
    0x0000000023E3ECD0
    0x0000000310967EC0

### Probe: 54p_redirect_minimal
  Files: 54p_redirect_minimal_20261018_094206.txt vs 54p_redirect_minimal_20261018_094326.txt
  Values only in file 2: 4
    0x0000000023C98000
    0x0000000023C98471
    0x0000000023E3ECD0
    0x0000000310967EC0

### Probe: 56a_controlled_redirect
  Files: 56a_controlled_redirect_20261018_104052.txt vs 56a_controlled_redirect_20261018_104142.txt
  Values only in file 1: 12
    0x000000003500E5F0
    0x000000003500E770
    0x000000003500E7C0
    0x000000003500E870
    0x000000003500EBC0
  Values only in file 2: 12
    0x000000001451E5F0
    0x000000001451E770
    0x000000001451E7C0
    0x000000001451E870
    0x000000001451EBC0

### Probe: 56a_controlled_redirect
  Files: 56a_controlled_redirect_20261018_104052.txt vs 56a_controlled_redirect_20261018_104741.txt
  Values only in file 1: 12
    0x000000003500E5F0
    0x000000003500E770
    0x000000003500E7C0
    0x000000003500E870
    0x000000003500EBC0
  Values only in file 2: 12
    0x000000001A7665F0
    0x000000001A766770
    0x000000001A7667C0
    0x000000001A766870
    0x000000001A766BC0

### Probe: 56a_controlled_redirect
  Files: 56a_controlled_redirect_20261018_104142.txt vs 56a_controlled_redirect_20261018_104741.txt
  Values only in file 1: 12
    0x000000001451E5F0
    0x000000001451E770
    0x000000001451E7C0
    0x000000001451E870
    0x000000001451EBC0
  Values only in file 2: 12
    0x000000001A7665F0
    0x000000001A766770
    0x000000001A7667C0
    0x000000001A766870
    0x000000001A766BC0

### Probe: 56b_redirect_minimal
  Files: 56b_redirect_minimal_20261018_110114.txt vs 56b_redirect_minimal_20261018_111030.txt
  Values only in file 1: 6
    0x00000003105E3440
    0x00000003105E3640
    0x00000003105E3820
    0x00000003105E38A0
    0x00000003105E3EC0
  Values only in file 2: 6
    0x000000031123F440
    0x000000031123F640
    0x000000031123F820
    0x000000031123F8A0
    0x000000031123FEC0

### Probe: 56d_gadget_redirect
  Files: 56d_gadget_redirect_20261018_112132.txt vs 56d_gadget_redirect_20261018_112241.txt
  Values only in file 2: 6
    0x000000003EF0C000
    0x000000003EF0C042
    0x000000003EF0C992
    0x000000003EFD5DFE
    0x00000003107F3820

### Probe: 56d_gadget_redirect
  Files: 56d_gadget_redirect_20261018_112134.txt vs 56d_gadget_redirect_20261018_112241.txt
  Values only in file 2: 6
    0x000000003EF0C000
    0x000000003EF0C042
    0x000000003EF0C992
    0x000000003EFD5DFE
    0x00000003107F3820

### Probe: 56g_syscall_gadget
  Files: 56g_syscall_gadget_20261018_113423.txt vs 56g_syscall_gadget_20261018_113437.txt
  Values only in file 1: 6
    0x00000000418E0000
    0x0000000310FCB820
    0x0000000311035AA0
    0x0000000311053160
    0x000000080507C000 [code ptr]
  Values only in file 2: 6
    0x000000005350C000
    0x0000000310A67820
    0x0000000310AE1160
    0x0000000310B47AA0
    0x000000081E764000 [code ptr]

### Probe: 56k2_signal_oracle
  Files: 56k2_signal_oracle_20261018_130912.txt vs 56k2_signal_oracle_20261018_132218.txt
  Values only in file 2: 4
    0x0000000022D16770
    0x0000000022EE98F4
    0x000000031107F820
    0x00007FFFDEAD0000

### Probe: 56k2_signal_oracle
  Files: 56k2_signal_oracle_20261018_131048.txt vs 56k2_signal_oracle_20261018_132218.txt
  Values only in file 2: 4
    0x0000000022D16770
    0x0000000022EE98F4
    0x000000031107F820
    0x00007FFFDEAD0000

### Probe: 56k2_signal_oracle
  Files: 56k2_signal_oracle_20261018_131756.txt vs 56k2_signal_oracle_20261018_132218.txt
  Values only in file 2: 4
    0x0000000022D16770
    0x0000000022EE98F4
    0x000000031107F820
    0x00007FFFDEAD0000

## Targeted Analysis

### sys 624 Values (from 51b)
  51b_accessible_syscall_deep_20261016_214832.txt:17: 624(): ret=0x00000000_00000D30

### sys 572 Values
  47a_dispatch_deep_20261016_195632.txt:119: ver=55 → ret=572 (0x23C)
  51a_sony_syscall_survey_20261016_214814.txt:24: [vm] 572: ret=0 (0x00000000_00000000) [SUCCESS]
  54f_kaslr_deep_20261018_090603.txt:201: --- E: sys 572 (VM syscall — returned 0 before) ---
  54f_kaslr_deep_20261018_090603.txt:202: 572(outbuf,0x200,0,0,0,0) ret=0 buf[0]=0x00000000_00000000 buf[8]=0x00000000_00000000
  54f_kaslr_deep_20261018_090603.txt:203: 572(0,outbuf,0x200,0,0,0) ret=-1 buf[0]=0x00000000_00000000 buf[8]=0x00000000_00000000
  54f_kaslr_deep_20261018_090603.txt:204: 572(0,0,outbuf,0x200,0,0) ret=-1 buf[0]=0x00000000_00000000 buf[8]=0x00000000_00000000
  54f_kaslr_deep_20261018_090603.txt:205: 572(1,outbuf,0x200,0,0,0) ret=-1 buf[0]=0x00000000_00000000 buf[8]=0x00000000_00000000
  54f_kaslr_deep_20261018_090603.txt:206: 572(2,outbuf,0x200,0,0,0) ret=-1 buf[0]=0x00000000_00000000 buf[8]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:1: === PROBE 54i: SYS 572 BUFFER EXAMINATION ===
  54i_sys572_buffer_exam_20261018_091303.txt:5: 572(0, outbuf, 64) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:6: 572(0, outbuf, 256) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:7: 572(0, outbuf, 1024) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:8: 572(0, outbuf, 4096) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:34: [*] Phase 3: 572(outbuf, size, 0...) and 572(outbuf, cmd, size...)
  54i_sys572_buffer_exam_20261018_091303.txt:36: 572(outbuf, 0, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:37: 572(outbuf, 1, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:38: 572(outbuf, 2, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:39: 572(outbuf, 3, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:40: 572(outbuf, 4, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:41: 572(outbuf, 5, 1024) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:6: [*] Phase 1: sys 572(heap_page, flag, outbuf, 1) for flag bits 0-31
  54j_sys572_vm_deep_20261018_083604.txt:32: 572(heap, 0, outbuf, 0x4000) = 0  [0]=0x00000003_10D40000
  54j_sys572_vm_deep_20261018_083604.txt:38: 572(heap, 0, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:39: 572(heap, 1, outbuf, 0x4000) = 0  [0]=0x00000003_10D40000
  54j_sys572_vm_deep_20261018_083604.txt:45: 572(0, 0, outbuf, 0) = -1  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:49: 572(gpu, 0, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:50: 572(gpu, 1, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:51: 572(gpu, 2, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:52: 572(gpu, 3, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:53: 572(gpu, 4, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:54: 572(gpu, 5, outbuf, 1) = 0  [0]=0x00000000_00000000
  54j_sys572_vm_deep_20261018_083604.txt:58: 572(heap, 1, outbuf, 16) = 0
  54l_rwx_verify_20261018_091853.txt:24: 572(gpu, outbuf, 0x200) = 0
  54l_rwx_verify_20261018_091853.txt:25: 572(outbuf, 0x200, 0) = 0
  54i_sys572_buffer_exam_20261018_091303.txt:1: === PROBE 54i: SYS 572 BUFFER EXAMINATION ===
  54i_sys572_buffer_exam_20261018_091303.txt:5: 572(0, outbuf, 64) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:6: 572(0, outbuf, 256) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:7: 572(0, outbuf, 1024) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:8: 572(0, outbuf, 4096) = -1
  54i_sys572_buffer_exam_20261018_091303.txt:34: [*] Phase 3: 572(outbuf, size, 0...) and 572(outbuf, cmd, size...)
  54i_sys572_buffer_exam_20261018_091303.txt:36: 572(outbuf, 0, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:37: 572(outbuf, 1, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:38: 572(outbuf, 2, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:39: 572(outbuf, 3, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:40: 572(outbuf, 4, 1024) = 0  [0]=0x00000000_00000000
  54i_sys572_buffer_exam_20261018_091303.txt:41: 572(outbuf, 5, 1024) = 0  [0]=0x00000000_00000000
  54l_rwx_verify_20261018_091853.txt:24: 572(gpu, outbuf, 0x200) = 0
  54l_rwx_verify_20261018_091853.txt:25: 572(outbuf, 0x200, 0) = 0
  42i_vmquery_20261016_070711.txt:9: 572 allocDmem(query): ret=-1

### AF_ROUTE 43o Detailed Scan
  File: 43o_afroute_kaslr_20261016_180647.txt (1099 bytes)
  L1: === PROBE 43o: AF_ROUTE KASLR DEFEAT ===
  L3: pid: 79
  L4: --- STEP 1: Create AF_ROUTE socket ---
  L5: AF_ROUTE socket fd=22
  L7: --- STEP 2: Build RTM_GET message ---
  L8: RTM_GET message built: 108 bytes
  L9: Sending to fd=22...
  L10: write ret=-1
  L12: --- STEP 3: Read response ---
  L13: read ret=108 bytes
  L15: --- KERNEL POINTER SCAN ---
  L16: kernel pointers found: 0
  L18: --- Response hex dump ---
  L19: +000: 6C 00 05 04 00 00 00 00 03 00 00 00 01 00 00 00
  L20: +010: 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00
  L21: +020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  L22: +030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  L23: +040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  L24: +050: 00 00 00 00 00 00 00 00 00 00 00 00 10 02 00 00
  L25: +060: 00 00 00 00 00 00 00 00 00 00 00 00
  L27: --- Response header ---
  L28: msglen=108 ver=5 type=4 flags=0x3 addrs=0x1 errno=0
  L30: --- STEP 4: RTM_GET for specific destinations ---
  L31: loopback: write failed
  L32: gateway: write failed
  L33: self: write failed
  L34: broadcast: write failed
  L35: dns: write failed
  L37: --- STEP 5: Passive listen for routing messages ---
  L38: passive read: 108 bytes
  L40: === PROBE 43o COMPLETE ===

### Hex Dump Deep Scan (looking for kptr bytes in raw dumps)

### Values Near Known Kernel Text Base (0xffffffff8a9c0000)
  
Output saved to C:\PS5contrib\evidence\deep_result_scan.md
