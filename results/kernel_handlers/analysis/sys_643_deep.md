# deep_643.bin — REA code analysis

Input: 16,384 bytes (`0x4000`). SHA-256: `710eca73f4191dd85e9b1ee3c73fb644e380f7dbaddaa49ab5c3866d0a8bde95`. Base kernel RVA: `0xa37660`. Recorded syscall: `643`, `1` argument slots.

The input is a raw little-endian x86-64 kernel-memory window, not an ELF and not one function. Addresses below use binary-relative `+offset`; kernel RVA is `base RVA + offset`, and the recorded runtime virtual address is `0xffffffff8a9c0000 + RVA`. The base and syscall identity come from the adjacent `handler_map.json` and `RE_CONTEXT.md`; they are contextual metadata, not symbols embedded in this file. No dump code was executed.

Read this report with `deep_643.rea.asm` (RVA addresses), `deep_643.rea.offsets.asm` (file offsets), the Ghidra/REA C recovery, and function metadata. The linear disassembly covers every supplied byte; automatic C recovery is approximate and can miss disconnected switch arms, infer wrong types, or split one physical function into fragments. External targets, structure-field names and helper names are unresolved unless explicitly described as an inference. Original source names, comments, macros, typedefs and complete source files cannot be recovered from these stripped windows.

## Main handler: confirmed behavior

`+0x00..+0x2f` is the complete syscall body. It saves `td` in `r14` and the argument-block pointer in `rbx`, loads the low 32-bit word at `uap+0`, and calls a printf-like external routine with a constant format pointer (`+0xf..+0x18`). It then reloads that 32-bit word, loads `p = *(td+8)`, and executes `*(uint32_t *)(p+0xa34) |= value` (`+0x1d..+0x23`). The function returns zero at `+0x29..+0x2f`.

```c
/* Descriptive reconstruction; field names are not recovered symbols. */
int syscall_643(void *td, const uint64_t *uap) {
    log_like(external_format, (uint32_t)uap[0]);
    void *process = load_ptr(td, 8);
    store_u32(process, 0xa34, load_u32(process, 0xa34) | (uint32_t)uap[0]);
    return 0;
}
```

There is no visible capability check, bit mask, null check, copyin/copyout, atomic prefix or lock in these 48 bytes. Only the current thread's associated object at `td+8` is used; no target PID or caller-chosen kernel pointer is accepted. The argument block is the kernel syscall marshaling structure, so `[uap]` is not an unchecked dereference of an arbitrary user pointer. The operation can set bits, cannot clear them, and ignores the upper 32 bits of the ABI argument slot.

The exact meaning and consumers of the process field `+0xa34` are not provided by this dump. Earlier adjacent notes label this a process debug/security flag and imply escalation; the assembly confirms the OR but cannot establish those consequences. Absence of a local check also does not determine whether the syscall is available to all caller profiles or whether external syscall filtering applies.

## Neighboring code and boundaries

The remaining 16 KiB is mostly unrelated object/VFS-style lifecycle code. It must not be attributed to syscall 643. This is evident both from the syscall's unconditional return at `+0x2f` and from later signatures operating on different structures and dispatching through operations tables. The operations-table calls, mount-like object fields, locks and reference-release patterns support VFS roles; the broader-dump strings below identify PPR PFS and several original function names.

`+0x30` is a separate leaf dispatcher: it indexes a global array using byte `(*(arg+0x20)+0x9d)`, fetches callback `+0x40`, returns if null, and otherwise tail-jumps to it. `sub/ror/cmp` before indirect dispatch checks whether the target belongs to a compiler-generated valid-target set. The slow path at `+0x68` reports a control-flow integrity violation and still reaches the callback. It is not an authorization test on syscall 643.

`+0xa0` creates global object pools of sizes `0x110`, `0xa8`, `0x2c8`, `0x310` when needed; it then selects a path using object flag `+0x9a`, nested state byte `+0x1a`, and filesystem-operation callbacks. It assembles descriptor records, handles nested locks, tests/sets flags and initializes object fields. Its own return/canary path is near `+0x442`; additional work extends to the final cold path preceding `+0x7f0`.

`+0x8a0` is a large teardown/cleanup routine. It dispatches several operations with CFI target-set checks, reports nonzero results, processes object fields `+0x410`, `+0x450`, `+0x784`, and repeatedly releases pointers at fields `+0x140`, `+0x1a8`, `+0x210`, `+0x278`, `+0x2e0`, `+0x348`. It is not a syscall permission chain.

`+0x2150` begins a much larger routine that traverses paths/state and replaces/releases many of the same objects. The dump ends mid-routine at `+0x4000`; e.g. a direct branch at `+0x3e71` targets `+0x418d`, outside this input. A complete reconstruction of this neighboring routine is impossible from this window. An apparent entry around `+0x1da0` shares the preceding frame/epilogue and should be treated cautiously rather than assuming every apparent block is a separate function.

## Errors and side effects

The main handler returns zero regardless of the logger's return. Its one explicit persistent side effect is the 32-bit OR at process offset `0xa34`; logging is the other observable call. Neighbor routines can return or log errno-like values, allocate/free objects and perform indirect calls. None of those neighboring error paths are reachable from the visible main-handler body.

## Identity recovered from broader-dump strings

`deep_643.rea.referenced_strings.json` resolves RIP-relative strings using the adjacent byte-matched kernel dump. At `+0xf`, the logger format is **`[KERNEL] set_chicken_switches(%x)`**. The strongest supported handler name is therefore `set_chicken_switches`; this does not by itself identify the meaning of individual bits in process field `+0xa34`.

The following code is firmly identified as **PPR PFS**, rather than merely generic VFS inference: the source-path string at `+0x21a` names `ppr_pfs_vfsops.c`, and diagnostic function strings name `ppr_pfs_mount` (`+0x2cc`), `ppr_pfs_unmount` (`+0x963`), `pfs_root` (`+0x156f`), `pfs_statfs` (`+0x168a`), `pfs_sync` (`+0x17ac`), `ppr_pfs_vget` (`+0x1b97`), and `mountppfs` (`+0x2242`). Consequently the entry roles can be refined: `+0xa0` is mount setup, `+0x8a0` unmount, `+0x14d0` root lookup, `+0x1630` statfs, `+0x16d0` sync, `+0x1b40` vnode-get handling, and `+0x2150` mountppfs and its large option/superblock path.

The truncated mountppfs body references option names `playgo`, `mkeymode`, `sblock_offset`, `ppkg_opt`, `sigverify`, `casesensitive`, plus package-vnode lookup, filesystem-version, block-size, superblock/ICV verification and read-only mount diagnostics. These directly ground its role as protected filesystem mount handling. They must not be attributed to the 48-byte chicken-switch syscall. The strings are additional broader-dump evidence, not embedded data in the supplied 16 KiB input.

## Function and entry catalogue

This catalogue covers conventional frame entries and identified leaf entries. Roles with generic wording remain unresolved. A late frame setup/cold entry is explicitly identified where detected; frame-pattern matches are not proof of function boundaries.

| File offset | Kernel RVA | Role |
|---:|---:|---|
| `+0x0` | `0xa37660` | set_chicken_switches syscall: logged 32-bit process-field OR; complete. |
| `+0x30` | `0xa37690` | Leaf operations-table dispatcher with null callback handling and CFI slow path at +0x68. |
| `+0x68` | `0xa376c8` | CFI slow path within +0x30 dispatcher; not a separate ABI function. |
| `+0xa0` | `0xa37700` | ppr_pfs_mount: initializes PPFS inode pools, validates mount state/options and invokes filesystem operations. |
| `+0x7f0` | `0xa37e50` | Small object helper with two external operations and canary validation. |
| `+0x8a0` | `0xa37f00` | ppr_pfs_unmount: callback dispatch, vnode flush, mount object/reference cleanup and diagnostics. |
| `+0x14d0` | `0xa38b30` | pfs_root: root vnode lookup via operations table, optional pre/post helpers and failure logging. |
| `+0x1630` | `0xa38c90` | pfs_statfs: filesystem statistics helper, error logging and canary verification. |
| `+0x16d0` | `0xa38d30` | pfs_sync: filesystem sync, callback/lock/wait handling and read-only modification diagnostics. |
| `+0x1b40` | `0xa391a0` | ppr_pfs_vget and related vnode-get entry family: allocation, lookup, state transitions and cleanup. |
| `+0x1fe0` | `0xa39640` | Optional callback wrapper and nested object flag/word handling. |
| `+0x2110` | `0xa39770` | Paired external entry hooks. |
| `+0x2130` | `0xa39790` | Paired external exit hooks in opposite order. |
| `+0x2150` | `0xa397b0` | mountppfs: protected-filesystem mount option/superblock verification, object setup and cleanup; truncated. |

## Per-entry call and validation evidence

The ranges below end at the next listed entry and are a navigation aid, not authoritative function extents. Direct-call targets use **binary-relative signed offsets**; convert with the base RVA. Repeated targets are collapsed. Indirect calls and immediate comparisons are retained to expose unresolved dependencies.

### Entry +0x0

set_chicken_switches syscall: logged 32-bit process-field OR; complete.

Direct/indirect call evidence: `+0x18: call   0xffffffffff825db0`


### Entry +0x30

Leaf operations-table dispatcher with null callback handling and CFI slow path at +0x68.

Direct/indirect call evidence: No call instruction in this navigation range.

Representative validation/state tests: `+0x5d: cmp    rax,0x8bc`.

### Entry +0x68

CFI slow path within +0x30 dispatcher; not a separate ABI function.

Direct/indirect call evidence: `+0x82: call   0xffffffffffa18260`


### Entry +0xa0

ppr_pfs_mount: initializes PPFS inode pools, validates mount state/options and invokes filesystem operations.

Direct/indirect call evidence: `+0xdd: call   0xffffffffffba9640`; `+0x129: call   0xffffffffffa03a80`; `+0x201: call   0xffffffffffba9bf0`; `+0x22e: call   0xffffffffffc784f0`; `+0x273: call   0xffffffffffb547a0`; `+0x284: call   0xa83d0`; `+0x2b7: call   0xffffffffffb57430`; `+0x31f: call   0xffffffffffb2a690`; `+0x34f: call   r15`; `+0x35e: call   0xffffffffffb2a780`; `+0x3a8: call   0xffffffffffba7970`; `+0x404: call   0xffffffffffbc3080`; `+0x410: call   0xffffffffffbc15c0`; `+0x43d: call   0xffffffffff825db0`; `+0x478: call   0xffffffffffbc3120`; `+0x487: call   0xffffffffffb153a0`; `+0x50c: call   0xffffffffffb12de0`; `+0x542: call   0x2150`; `+0x558: call   0xffffffffffb12ac0`; `+0x595: call   0xffffffffffb12e00`; `+0x625: call   0x2144c0`; `+0x63f: call   0xffffffffffdc62a0`; `+0x658: call   0x214e50`; `+0x6dc: call   0xffffffffffba9dc0`; `+0x75b: call   0xffffffffffa8f3a0`; `+0x770: call   0xffffffffffa8f940`; `+0x7d1: call   0xffffffffffcc6050`; `+0x7e2: call   0xffffffffffa18260`

Representative validation/state tests: `+0xf0: cmp    QWORD PTR [rip+0x31b7c38],0x0`; `+0xfa: test   BYTE PTR [rbx+0x9a],0x1`; `+0x1b7: test   BYTE PTR [rbx+0x9a],0x1`; `+0x1dd: cmp    al,0x1`; `+0x33d: cmp    rax,0x72`; `+0x355: cmp    r12d,0xffffffff`; `+0x389: cmp    al,0x1`; `+0x446: cmp    rax,QWORD PTR [rbp-0x30]`; `+0x4ab: test   al,0x1`; `+0x52f: test   BYTE PTR [rbx+0x9a],0x1`; `+0x5ea: cmp    BYTE PTR [rax+0x19],0x1`; `+0x5f0: test   BYTE PTR [rbx+0x9a],0x8`.

### Entry +0x7f0

Small object helper with two external operations and canary validation.

Direct/indirect call evidence: `+0x831: call   0x1e2d80`; `+0x845: call   0xffffffffff821c20`; `+0x85c: call   0xffffffffffba9fc0`; `+0x867: call   0xffffffffffba9ef0`; `+0x88d: call   0xffffffffffcc6050`

Representative validation/state tests: `+0x877: cmp    rcx,QWORD PTR [rbp-0x28]`.

### Entry +0x8a0

ppr_pfs_unmount: callback dispatch, vnode flush, mount object/reference cleanup and diagnostics.

Direct/indirect call evidence: `+0x900: call   0xffffffffffb2a690`; `+0x936: call   r14`; `+0x945: call   0xffffffffffb2a780`; `+0x977: call   0xffffffffff825db0`; `+0x9b4: call   0xffffffffffb12ab0`; `+0xa06: call   0xffffffffffb12e00`; `+0xaeb: call   0xffffffffffe39330`; `+0xafe: call   0x1d1790`; `+0xb31: call   0x1270d0`; `+0xb77: call   0x66030`; `+0xb8a: call   0xfffffffffff10c60`; `+0xbd1: call   0xfffffffffff0e100`; `+0xbe1: call   0xffffffffffefd380`; `+0xc08: call   0x66530`; `+0xcce: call   0xfffffffffff00c50`; `+0xce4: call   0xffffffffff822580`; `+0xd08: call   0x127380`; `+0xd1a: call   0xffffffffff851390`; `+0xd46: call   0x7390`; `+0xd70: call   0xffffffffffa8f3a0`; `+0xd8e: call   0xfffffffffffe7d00`; `+0xd9f: call   0xffffffffffa8f940`; `+0xdc1: call   0x15c1f0`; `+0xe1b: call   0xfffffffffff13370`; `+0xe8c: call   0xffffffffffb12ac0`; `+0xe9c: call   0xffffffffffa907f0`; `+0xf51: call   0xfffffffffff132b0`; `+0x1097: call   0x1ba100`; `+0x11ec: call   0xffffffffffb312f0`; `+0x12e9: call   0xffffffffff933e10`; `+0x1303: call   0xffffffffffc784f0`; `+0x131b: call   0x2144c0`; `+0x1324: call   0xffffffffffd0a420`; `+0x1330: call   0x214e50`; `+0x1339: call   0xffffffffffb12de0`; `+0x1342: call   0xffffffffffca7410`; `+0x13d5: call   0xffffffffffcdd250`; `+0x1419: call   0xffffffffffcc6050`; `+0x142d: call   0xffffffffffa18260`; `+0x144e: call   0xffffffffffdba2f0`; `+0x145a: call   0xffffffffffdba1b0`; `+0x14ab: call   0x2633b0`

Representative validation/state tests: `+0x8d1: cmp    DWORD PTR [rbx+0x410],0x0`; `+0x921: cmp    rax,0x72`; `+0x93c: cmp    r12d,0xffffffff`; `+0x97c: cmp    r14d,0x6`; `+0x994: test   r13d,0x80000`; `+0x9c4: cmp    eax,0x2`; `+0xa30: cmp    ebx,0x6`; `+0xa42: cmp    DWORD PTR [rbx+0x410],0x0`; `+0xa53: cmp    QWORD PTR [rbx+0x868],0x0`; `+0xa8a: cmp    rax,0x5`; `+0xad6: cmp    r14d,0x6`; `+0xb93: cmp    eax,0x6`.

### Entry +0x14d0

pfs_root: root vnode lookup via operations table, optional pre/post helpers and failure logging.

Direct/indirect call evidence: `+0x1516: call   0xffffffffffb2a690`; `+0x154f: call   r13`; `+0x155e: call   0xffffffffffb2a780`; `+0x1583: call   0xffffffffff825db0`; `+0x15ad: call   0xffffffffff9339e0`; `+0x15dc: call   0xffffffffffb12de0`; `+0x1614: call   0xffffffffffa18260`; `+0x1622: call   0xffffffffffcc6050`

Representative validation/state tests: `+0x1537: cmp    rax,0xf`; `+0x1555: cmp    r12d,0xffffffff`; `+0x1591: cmp    rax,QWORD PTR [rip+0x31b67a8]`; `+0x15eb: cmp    rax,QWORD PTR [rbp-0x30]`.

### Entry +0x1630

pfs_statfs: filesystem statistics helper, error logging and canary verification.

Direct/indirect call evidence: `+0x1677: call   0xffffffffffef2c50`; `+0x169e: call   0xffffffffff825db0`; `+0x16c8: call   0xffffffffffcc6050`

Representative validation/state tests: `+0x16b4: cmp    rax,QWORD PTR [rbp-0x20]`.

### Entry +0x16d0

pfs_sync: filesystem sync, callback/lock/wait handling and read-only modification diagnostics.

Direct/indirect call evidence: `+0x172c: call   0x1ba110`; `+0x176d: call   0x66530`; `+0x1781: call   0x66030`; `+0x17c0: call   0xffffffffff825db0`; `+0x1800: call   0xffffffffff822580`; `+0x185b: call   r15`; `+0x1880: call   0xffffffffffb133d0`; `+0x18d8: call   0xffffffffffa8f3a0`; `+0x18e3: call   0xffffffffffb13550`; `+0x1940: call   0xffffffffffb12710`; `+0x1980: call   0xffffffffffb55d40`; `+0x19ae: call   0xffffffffffb12de0`; `+0x19c5: call   0xffffffffffa8f940`; `+0x19d0: call   0xffffffffffb13980`; `+0x19f7: call   0xffffffffffd9d040`; `+0x1a09: call   0xffffffffffd9d850`; `+0x1a51: call   0xffffffffffc784f0`; `+0x1acf: call   0xffffffffffb57430`; `+0x1af0: call   0xffffffffffcc6050`; `+0x1af7: call   0xffffffffffdba2f0`; `+0x1b03: call   0xffffffffffdba1b0`; `+0x1b16: call   0x2633b0`; `+0x1b2d: call   0xffffffffffa18260`

Representative validation/state tests: `+0x1735: cmp    DWORD PTR [rbx+0x438],0x0`; `+0x1742: cmp    DWORD PTR [rbx+0x410],0x0`; `+0x184f: cmp    rax,0x6ff`; `+0x186d: cmp    ecx,0x4`; `+0x1876: cmp    eax,0x1`; `+0x18ff: cmp    DWORD PTR [rbx+0x1d4],0x0`; `+0x190c: test   BYTE PTR [rbx+0x1c4],0x80`; `+0x191d: test   BYTE PTR [rax+0x20],0xd`; `+0x1923: cmp    DWORD PTR [rbp-0x64],0x3`; `+0x192d: cmp    DWORD PTR [rbx+0x158],0x0`; `+0x1945: cmp    eax,0x2`; `+0x194e: cmp    eax,0x4d`.

### Entry +0x1b40

ppr_pfs_vget and related vnode-get entry family: allocation, lookup, state transitions and cleanup.

Direct/indirect call evidence: `+0x1b83: call   0xa8410`; `+0x1bad: call   0xffffffffff825db0`; `+0x1c22: call   0xffffffffffa04220`; `+0x1c3f: call   0xffffffffffb10900`; `+0x1c62: call   0xffffffffffa04a60`; `+0x1ca1: call   0x1ba110`; `+0x1cb5: call   0x1ba0e0`; `+0x1d23: call   0xffffffffffb10d50`; `+0x1dc0: call   0xa8640`; `+0x1e36: call   0x1ba030`; `+0x1e78: call   0xffffffffff92e6a0`; `+0x1e88: call   0xffffffffff92f190`; `+0x1ec2: call   0xffffffffffb13b60`; `+0x1ecb: call   0xffffffffffb12de0`; `+0x1f62: call   0x1ba0d0`; `+0x1fa4: call   0x1d14f0`; `+0x1fcb: call   0xffffffffffcc6050`

Representative validation/state tests: `+0x1bba: cmp    QWORD PTR [r15],0x0`; `+0x1c07: cmp    eax,0x200000`; `+0x1d75: cmp    rax,QWORD PTR [rbp-0x30]`; `+0x1df6: cmp    QWORD PTR [r15],0x0`; `+0x1e6b: test   al,0x1`; `+0x1e8d: cmp    DWORD PTR [rbx+0x410],0x0`; `+0x1f6d: cmp    QWORD PTR [r12+0x30],rax`; `+0x1f83: cmp    QWORD PTR [rcx],0x1`; `+0x1f89: cmp    QWORD PTR [rbx+0x278],0x0`.

### Entry +0x1fe0

Optional callback wrapper and nested object flag/word handling.

Direct/indirect call evidence: `+0x2026: call   0xffffffffffb2a690`; `+0x205e: call   r12`; `+0x206d: call   0xffffffffffb2a780`; `+0x20af: call   0xffffffffffc70c80`; `+0x20b8: call   0xffffffffffb12de0`; `+0x20f3: call   0xffffffffffa18260`; `+0x2104: call   0xffffffffffcc6050`

Representative validation/state tests: `+0x204a: cmp    rax,0xf`; `+0x2061: cmp    r15d,0xffffffff`; `+0x208a: cmp    WORD PTR [rax+0x60],0x0`; `+0x20cd: cmp    rcx,QWORD PTR [rbp-0x30]`.

### Entry +0x2110

Paired external entry hooks.

Direct/indirect call evidence: `+0x2114: call   0xffffffffffa2eeb0`; `+0x2119: call   0xffffffffff92de60`


### Entry +0x2130

Paired external exit hooks in opposite order.

Direct/indirect call evidence: `+0x2134: call   0xffffffffff92ded0`; `+0x2139: call   0xffffffffffa2f110`


### Entry +0x2150

mountppfs: protected-filesystem mount option/superblock verification, object setup and cleanup; truncated.

Direct/indirect call evidence: `+0x21af: call   0xffffffffffca73c0`; `+0x21c4: call   0x2144c0`; `+0x21ee: call   0xffffffffffd0a2c0`; `+0x21fd: call   0x214e50`; `+0x222d: call   0xffffffffffb57430`; `+0x2259: call   0xffffffffff825db0`; `+0x226a: call   0x66030`; `+0x228d: call   0xffffffffffc784f0`; `+0x22ae: call   0xffffffffffd0a420`; `+0x232a: call   0xfffffffffff13370`; `+0x2348: call   0xffffffffffa8f3a0`; `+0x2384: call   0xffffffffffa8f940`; `+0x239b: call   0xffffffffffb12ac0`; `+0x23b0: call   0xffffffffffa907f0`; `+0x23f6: call   0x1d1790`; `+0x2464: call   0x1d14f0`; `+0x248d: call   0x1ba030`; `+0x24a9: call   0xffffffffffa90770`; `+0x250c: call   0xffffffffffba9c70`; `+0x25ae: call   0xffffffffffba7970`; `+0x2614: call   0xfffffffffff132b0`; `+0x26d9: call   0xffffffffff933e10`; `+0x282b: call   0x1ba100`; `+0x292a: call   0xffffffffffb312f0`; `+0x29ad: call   0xffffffffffe39330`; `+0x2a1e: call   0xffffffffffb12e00`; `+0x2a56: call   0x15c1f0`; `+0x2aa3: call   0xffffffffffca7410`; `+0x2b05: call   0xffffffffffe9a3d0`; `+0x310d: call   0x66530`; `+0x31ed: call   0xffffffffff822580`; `+0x3347: call   0xffffffffff8b3ac0`; `+0x34af: call   0xffffffffff8b3a40`; `+0x357b: call   0xffffffffffb23040`; `+0x3680: call   0xffffffffffcf6e30`; `+0x36c5: call   0xffffffffffb12a00`; `+0x3a2f: call   0xffffffffffb14050`; `+0x3a49: call   0xffffffffffcc6050`; `+0x3d4d: call   0xffffffffffb10240`; `+0x3d5a: call   0xffffffffffba74a0`; `+0x3d62: call   0xffffffffffb10360`; `+0x3e80: call   0xffffffffff92dfb0`; `+0x3f68: call   0x69b0`; `+0x3f77: call   0xffffffffffb12de0`; `+0x3f8d: call   0xffffffffff933cf0`; `+0x3fcf: call   0xffffffffffdba2f0`; `+0x3fdb: call   0xffffffffffdba1b0`

Representative validation/state tests: `+0x226f: cmp    QWORD PTR [rbp-0x160],0x0`; `+0x22f8: test   BYTE PTR [r14+0x410],0x1`; `+0x230d: cmp    eax,0x1`; `+0x2316: cmp    QWORD PTR [r14+0x5f8],0x0`; `+0x2354: test   BYTE PTR [rdi+0x1c4],0x80`; `+0x2511: cmp    eax,0x1`; `+0x2546: cmp    eax,0x1`; `+0x257b: cmp    eax,0x1`; `+0x258a: cmp    eax,0x1`; `+0x25e5: cmp    eax,0x1`; `+0x25ee: cmp    eax,0x2`; `+0x25f7: cmp    eax,0x3`.

## REA recovery evidence index

The table ties this analysis to the primary REA/Ghidra procedure dossiers. `body bytes` is Ghidra ownership, not physical function size; missing-table arms and cold fragments can lie outside it. Evidence IDs resolve in `.rea.dossiers.jsonl.gz` and `.rea.evidence.json.gz`. The recovered C was reviewed alongside instruction evidence; indirect jumps rendered as calls are decompiler limitations, not original source behavior.

| Offset | Recovered procedure | Body bytes | Evidence ID |
|---:|---|---:|---|
| `0x0` | `sys_643` | 48 | `ev_00adfffcd4816d62b006e1f422e67525c3287c5f286724310b2900a5113473dd` |
| `0x30` | `sub_00a37690` | 99 | `ev_109a0fea091fa900fb7d33d9edee893146559860203b5f098bf4c62eafdd45cf` |
| `0xa0` | `sub_00a37700` | 1868 | `ev_e3386cdfca1f4e9520a0d351fb3eaec0a17fbe0af6a9695db7e74e6bb55b05cd` |
| `0x7f0` | `sub_00a37e50` | 164 | `ev_245010c3b7e8dc41deb19992e221848adf6dcb5a8f44177f62895247c9fb65e8` |
| `0x8a0` | `sub_00a37f00` | 3110 | `ev_4e46d9ddcda3be49da0fb7dc2b4a6adaff550f8231c345f1f577de056ec32a92` |
| `0x14d0` | `sub_00a38b30` | 345 | `ev_ee8dd59906347535624cd7c4fbf5f9bcc141620eb430c1253ea88c73392156fa` |
| `0x1630` | `sub_00a38c90` | 159 | `ev_67c434fbc0248958cfe97ecb58020c1ea1db34c7b56532d91c345c456e4a66a2` |
| `0x16d0` | `sub_00a38d30` | 1130 | `ev_0fef14b1af01ed5861593173c311f0511c99bdab523810a409a84667f3dfd467` |
| `0x1b40` | `sub_00a391a0` | 1170 | `ev_9846c8f598f98fd919d5d1f88c70fdc6366775e02868db52676aa8e74302479c` |
| `0x1fe0` | `sub_00a39640` | 299 | `ev_cea5999014976dd876398958757ed5ba896d856b23cd737e70540b2049632250` |
| `0x2110` | `sub_00a39770` | 18 | `ev_996d80374a9492375a2beb1dd2f8ef9e60d2e1368c3bab3311b3caf6eda0d6e2` |
| `0x2130` | `sub_00a39790` | 18 | `ev_a5a6cbc8d9511482e7557997c8fd5433d365ad59b43f52b8cf43edd8f18adb4b` |
| `0x2150` | `sub_00a397b0` | 5917 | `ev_1fa52579708b205ea60c09eea415de21cf279bd217af56503474af8c39115399` |

## Supplemental recovery audit

A final coverage pass recovered 6 additional synthetic block entries in `deep_643.rea.extra_fragments.c`. These are blocks omitted from primary function pseudocode (including disconnected dispatch arms or paths beyond unresolved transfers). They are **not additional original ABI functions**: inherited register values, the parent stack frame, exact switch edges and decompiler-imposed block boundaries remain uncertain. The full assembly remains the reference. The selected offsets are in `deep_643.rea.extra_fragments.selection.json`, with complete individual records in `.dossiers.jsonl.gz` and the canonical bundle in `.evidence.json.gz`.

| Synthetic entry offset | REA evidence ID |
|---|---|
| `0x35ae` | `ev_5667b16cdd0f5798594ad19121ed54fdfe870fb439c2c3ad10cf1d36bbf57f27` |
| `0x3795` | `ev_d98759b0d7fd17a2d7329f14f42301052a3182a28be53a776f8fb1d759649574` |
| `0x3840` | `ev_bfff7d52a4694b5e5fc96fcaabcaa0626b9b8ca89fa649488752c87d12aa72dc` |
| `0x38fa` | `ev_5873979e8428015e9a41bd04d3977cb07bf9c79858a898dfb2a1e8e031574f6c` |
| `0x39c1` | `ev_c638f320fea0d8b7a1f512ef453cf87023c982a1ecdcf296d2b92208778d1639` |
| `0x3a50` | `ev_b38adb7bcbc6aa8fcea27e7e9ba85765ac506236dc10e199a24a5b546d99c8a7` |
