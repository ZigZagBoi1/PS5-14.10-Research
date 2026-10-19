# Deep Result File Forensic Scan
# Date: 2026-10-18
# Scanner: deep_result_scanner.py

Total result files: 170

## Summary Statistics
- Kernel pointer candidates: 20
- Deobfuscated kernel pointer candidates: 0
- Userland code pointer candidates: 203
- Heap metadata candidates: 115
- Unusual return values: 2968
- Non-zero buffer data: 1

## Detailed Findings by File

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

### phase1_identity_layout/01_identity_20261015_184244.txt
**USERLAND CODE POINTERS:**
  Line 17: 0x000000080B8E4000
    Context: libkernel_base: 0x80b8e4000

### phase1_identity_layout/08_read_offsets_20261015_185427.txt
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

### phase2_kernel_objects/12_nwake_robust_20261015_190720.txt
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

### phase2_kernel_objects/13_nwake_oracle_20261015_190841.txt
**KERNEL POINTERS:**
  Line 39: 0xFFFFF80000000000
    Context: 0xfffff80000000000: 68318 ns
  Line 40: 0xFFFFF80040000000
    Context: 0xfffff80040000000: 68238 ns
  Line 41: 0xFFFFF80080000000
    Context: 0xfffff80080000000: 68078 ns
  Line 42: 0xFFFFF800C0000000
    Context: 0xfffff800c0000000: 68158 ns
  Line 43: 0xFFFFF80100000000
    Context: 0xfffff80100000000: 68158 ns
  Line 44: 0xFFFFF80140000000
    Context: 0xfffff80140000000: 67997 ns
  Line 45: 0xFFFFF80180000000
    Context: 0xfffff80180000000: 68238 ns
  Line 46: 0xFFFFF801C0000000
    Context: 0xfffff801c0000000: 68077 ns
  Line 47: 0xFFFFF80200000000
    Context: 0xfffff80200000000: 68078 ns
  Line 48: 0xFFFFF80240000000
    Context: 0xfffff80240000000: 67837 ns
  Line 49: 0xFFFFF80280000000
    Context: 0xfffff80280000000: 67917 ns
  Line 50: 0xFFFFF802C0000000
    Context: 0xfffff802c0000000: 68318 ns
  Line 51: 0xFFFFF80300000000
    Context: 0xfffff80300000000: 68398 ns
  Line 52: 0xFFFFF80340000000
    Context: 0xfffff80340000000: 68238 ns
  Line 53: 0xFFFFF80380000000
    Context: 0xfffff80380000000: 68078 ns
  Line 54: 0xFFFFF803C0000000
    Context: 0xfffff803c0000000: 67917 ns
  Line 55: 0xFFFFF80400000000
    Context: 0xfffff80400000000: 67837 ns

### phase2_kernel_objects/14_device_ioctl_20261015_191602.txt
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

### phase2_kernel_objects/18_dmem_phys_20261015_192222.txt
**HEAP METADATA CANDIDATES:**
  Line 11: 0x00000000002C0000 (size=0x2C000, flags=0x0)
    Context: 0x00000000002c0000 from +0x10950 ALIGNED
  Line 12: 0x0000000000400027 (size=0x40002, flags=0x7)
    Context: 0x0000000000400027 from +0x16a58
  Line 75: 0x00000000002C0000 (size=0x2C000, flags=0x0)
    Context: phys=0x00000000002c0000: MAPPED nz=0

### phase3_signals_codexec/25b_sigalt_ign_20261015_194744.txt
**KERNEL POINTERS:**
  Line 15: 0xFFFFF80010000000
    Context: verify: sp=0xfffff80010000000 flags=0x0

### phase3_signals_codexec/26d_find_ret_20261015_195332.txt
**KERNEL POINTERS:**
  Line 9: 0xFFFFFFFD42945A14
    Context: offset to code: 0xfffffffd42945a14 (-11767883244)

### phase3_signals_codexec/26f_kstack_crash_20261015_195707.txt
**KERNEL POINTERS:**
  Line 13: 0xFFFFF80010000000
    Context: verified: 0xfffff80010000000

### phase4_ipc_network/30b_fcntl_scm_20261015_201028.txt
**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**
  Line 10: ret=1024 (0x00000400)
    Context: writev 16x64: rv=1024
  Line 11: ret=1024 (0x00000400)
    Context: readv 16x64: rv=1024
  Line 12: ret=1024 (0x00000400)
    Context: writev 1024x1: rv=1024

### phase4_ipc_network/31_sockopt_fuzz_20261015_202000.txt
**HEAP METADATA CANDIDATES:**
  Line 11: 0x0000000000000218 (size=0x21, flags=0x8)
    Context: get TCP_MAXSEG           rv=0 len=4 val=0x00000218,deaddead

### phase4_ipc_network/31b_tcpinfo_dump_20261015_202500.txt
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

### phase4_ipc_network/31c_ps5opts_fuzz_20261015_203000.txt
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

### phase7_heap_exploitation/41p_libkernel_gadgets_20261015_232718.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x00000008149E8000
    Context: text base: 0x00000008149E8000
  Line 8: 0x0000000814A30000
    Context: data base: 0x0000000814A30000

### phase7_heap_exploitation/41p_libkernel_gadgets_20261015_232807.txt
**USERLAND CODE POINTERS:**
  Line 6: 0x0000000832AEC000
    Context: text base: 0x832AEC000
  Line 8: 0x0000000832B34000
    Context: data base: 0x832B34000

### phase7_heap_exploitation/41q_segment_readability_20261015_232935.txt
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

### phase7_heap_exploitation/41r_eboot_gadgets_20261015_233051.txt
**USERLAND CODE POINTERS:**
  Line 59: 0x000000081737C000
    Context: libkernel data at 0x81737C000 sz=0x20000

### phase7_heap_exploitation/41v_got_dump_20261015_233933.txt
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

### phase7_heap_exploitation/41w_kernel_rw_20261015_234305.txt
**USERLAND CODE POINTERS:**
  Line 5: 0x00000008281F0000
    Context: libkernel base: 0x8281F0000
  Line 6: 0x00000008281F0000
    Context: syscall stub: 0x8281F0000+0xB57

### phase7_heap_exploitation/41z_chain_hijack_20261015_235238.txt
**HEAP METADATA CANDIDATES:**
  Line 44: 0x0000000000000301 (size=0x30, flags=0x1)
    Context: chain+0x298 -> slot 0x31080E3E0 = 0x000000301

### phase9_kaslr_defeat/42b_kaslr_defeat_20261016_065521.txt
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

## Targeted Analysis

### sys 624 Values (from 51b)
  51b_accessible_syscall_deep_20261016_214832.txt:17: 624(): ret=0x00000000_00000D30

### sys 572 Values
  47a_dispatch_deep_20261016_195632.txt:119: ver=55 → ret=572 (0x23C)
  51a_sony_syscall_survey_20261016_214814.txt:24: [vm] 572: ret=0 (0x00000000_00000000) [SUCCESS]
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
