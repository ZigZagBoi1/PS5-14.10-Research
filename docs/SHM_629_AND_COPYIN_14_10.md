# 629 shm is a mapping-level stub; copyin does fault pages in (14.10, 2026-11-05)

Scope: three measurements taken on the live console (192.168.1.121:9026, fw 14.10,
loader pid 124) while repairing probes 1248a / 1249a / 1250a. Every number below is a
recorded call result, not an inference. Probe logs:
`results/phase17_new_vectors/1249a_sys607_path_oracle_20261105_165652.txt`,
`1250a_shm_faultin_and_exec_20261105_165710.txt`,
`1250b_shm_shape_and_copyin_20261105_165752.txt`,
`1250c_shm_object_inventory_20261105_165829.txt` (binary; carries a loader fault blob).

## 1. 629 argument shape — arg2 is `oflag`, not a size

Probe 1250a sent `629(1, 0x4000, fl, 0)` for nine `fl` values and got EINVAL 22 every
time. The decoded flags test is `test r15d,0xffdff1fc ; jne error`, and
`0x4000 & 0xffdff1fc == 0x4000`, so the size 0x4000 in slot 2 failed that check before
any flag value could matter. Probe 1250b moved the size out of slot 2:

| call | rv | errno |
|---|---|---|
| `629(1, 0, 0)` | -1 | 22 EINVAL |
| `629(1, 1, 0)` | -1 | 22 EINVAL |
| `629(1, 2, 0)` | **22** | 22 (stale) |
| `629(1, 3, 0)` | -1 | 22 EINVAL |
| `629(1, 0x200/0x201/0x203/0x20000/0x200000, 0)` | -1 | 22 EINVAL |
| `629(1, 1, 0x4000, 0)` | -1 | 22 EINVAL |
| `629("<name>", 1, 0)` for shm, /shm, /SceShm, / | -1 | 22 EINVAL |

So: **arg1 == 1 is the anon sentinel, arg2 is `oflag`, arg3 is `mode`, and oflag = 2
(O_RDWR) is the only accepted value.** oflag = 1 dies on `test r15b,1` (O_WRONLY
rejected); 0x200/0x20000/0x200000 die on the 0xffdff1fc mask; oflag = 0 passes both
checks and is still refused, which reads as "a create must ask for O_RDWR".

Probe 1250c confirmed the return value is a descriptor: three consecutive
`629(1, 2, 0)` calls returned **23, 24, 25** in one process.

## 2. The object is well-formed on paper

`fstat(23)` returned 0 and filled a FreeBSD-11-layout `struct stat`:

- `+0x08` `0x0000000100009000` — inode
- `+0x10` `0x0000000000000001` — nlink = 1, mode = 0, uid = 0 (nlink_t/mode_t/uid_t packed)
- `+0x58` `0x0000000000004000` — **st_size = 0x4000**
- everything else (dev, rdev, all three timespecs, blocks, blksize, flags) zero

A fresh 0x4000-byte shared object, exactly what the 0x200000 size-class split in the
create path at `0x91bca0` predicts.

## 3. …but the mapping cannot be faulted in, and reading it kills the game

`477(0, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, 23, 0)` returned **0x310D44000**
(no error). The very first userland read of that page, `memory.read_byte(0x310D44000)`,
took the process down. The loader's fault blob (magic `0x13371337`, trapframe at
blob+0x20) records:

| field | offset | value |
|---|---|---|
| RIP | +0xB8 | `0x00000000108824C0` (loader code) |
| CS | +0xC0 | `0x43` (user) |
| RFLAGS | +0xC8 | `0x10297` |
| RSP | +0xD0 | `0x310B9C6F0` |
| SS | +0xD8 | `0x3B` |
| tf_addr (CR2) | +0xA0 | `0x0000000310D44000` — the shm mapping |
| tf_err | +0xB0 | **`0x4`** = P=0, W=0, U=1 |
| tf_trapno | +0x98 low dword | **`0xC` = 12 = T_PAGEFLT** |
| registers | +0x20/+0x28/+0x30 | rdi=`0x310CE2EA0`, rsi=`0x310D44000`, rdx=`0x1` |

`rdi=dst, rsi=addr, rdx=1` is the loader's one-byte read helper; it faulted reading
source `0x310D44000`.

The load-bearing detail is **err = 4: the page is not present and the fault was a user
read**. A demand-zero page behind a working vm_object would have been faulted in by
`vm_fault` and returned zeros — that is exactly what the anonymous mapping does (§4).
Instead the fault was fatal, so the vm_object behind the 629 descriptor cannot supply
pages at all.

**Conclusion: 629 is a stub at the mapping level too.** It hands out a descriptor, an
inode, a size and a successful mmap, but the object has no pager and no swap backing, so
no page can ever be materialised. This is the same shape as the UMTX_OP_SHM(25) stub in
`docs/UMTX_454_EVIDENCE.md`, and it closes shm as a route to an executable or
kernel-readable mapping.

**Cost note:** this probe was filed CRASH_CLASS: LOW and it took the *game* down, not
just the Lua process (port 9026 closed afterwards). Any probe that touches a 629 mapping
must be filed MEDIUM or higher, and the read must be treated as the last run of a session.

## 4. `copyin` DOES fault demand-zero pages in — 1240a's "PTE absent" claim is withdrawn

Probe 1250b mapped `0x8000` bytes anonymous, made a socketpair, and read user VAs
kernel-side with `write(sock, va, len)`:

| step | write | errno | bytes received |
|---|---|---|---|
| [A1] cold page, never touched by userland | **8** | (stale) | `0000000000000000` |
| [A2] same page after one userland read | 8 | | `0000000000000000` |
| [A3] second page of the mapping, still cold | 8 | | `0000000000000000` |
| [A4] second page after one userland write of 0x5A | 8 | | `5A00000000000000` |
| [A5] control: unmapped `0x10000000` | -1 | 14 EFAULT | — |
| [A6] control: NULL | -1 | 14 EFAULT | — |
| [A7] 0x2000 bytes from the last mapped page | 8192 | | zeros |

The cold page copied out zeros. Therefore **FreeBSD `copyin` on this kernel faults
demand-zero pages in normally**, and EFAULT means the VA is genuinely unmapped. Probe
1240a's inference "the mapping is not present" from `write(socket, va, 0x20) == -1
EFAULT` was invalid — the EFAULT it saw was about its own address, not about copyin
behaviour. Any document that cites 1240a for a "kernel copyin does not fault" property
must be corrected.

## 5. 607 is present, resolves paths, and stops at a privilege check

Probe 1249a (repaired) produced a clean errno matrix:

| argument | rv | errno |
|---|---|---|
| `/app0/eboot.bin` | -1 | **13 EACCES** |
| `/dev/null`, `/`, `/app0`, `/dev` | -1 | 22 EINVAL |
| `/user`, `nosuchpath`, `""` | -1 | 2 ENOENT |
| `607(NULL, buf)` | -1 | 14 EFAULT |
| `607(path, NULL)` | -1 | **13 EACCES** |

Reading the ladder off those codes:

1. `copyinstr` runs first (NULL path → EFAULT 14).
2. The VFS lookup runs next (missing path → ENOENT 2). So 607 **is live on 14.10** and
   its namei-like callee at `0xafba6e0` works.
3. Gate A is the vnode subtype test `cmp dword [vnode+0x1d4],1`: directories and
   `/dev/null` fail it with EINVAL, a regular file passes.
4. A privilege check then refuses with **EACCES 13** — and it fires *before* arg1 is
   touched, since `607(path, NULL)` returns the same EACCES rather than EFAULT.

That last point is what closes the oracle: the 0x88-byte block (static .data pointer,
vnode, cred, td) is unreachable because the refusal precedes both the `0x609c00`
sanitizer and the `copyout`. This is the dynamic confirmation of the static prediction
in `docs/CAPABILITY_TAG_MAP_14_10.md` that 607 is gated on `cred+0x58` — with the
correction that the gate reports EACCES rather than zeroing the block and returning 0.

Residual value: 607 is a free filesystem oracle. ENOENT / EINVAL / EACCES distinguishes
"does not exist" / "exists but is not a regular file" / "exists and is a regular file",
from an unprivileged process, with no crash cost. It leaks no pointers.

## 6. 674 argument shapes are not interchangeable - a blind sweep took the game down (2026-11-05 17:03)

Probe 1251a was first written to calibrate 674 by trying three argument shapes in
sequence and keeping the first that worked. The first call (55f's shape:
`674(buf, 72, 512, countp, 0x40000000)`) returned normally, but the probe never
reached its end marker and the loader - and the game behind it - went away. The
remaining two shapes were `arg5 = 0` and a plain-Lua-number variant, and one of them
is the prime suspect. There is no capture, so the fatal step is not identified; the
rewritten probe prints a `step N ok` marker after every section so the next run
localises it if it happens again.

Rules that come out of it:

- **Call 674 once, with the shape that is already known to work**:
  `STRIDE = 72`, `MAX = 512`, `arg5 = 0x40000000`, buffer size
  `STRIDE * MAX + 0x100`. The slack is not decoration - 55f allocates it.
- **Never probe an unknown syscall argument shape "just to see"** when the previous
  shape already worked. A wrong flag on 674 costs a relaunch at best.
- **Create every mapping before taking the snapshot.** A 674 snapshot cannot describe
  a mapping that did not exist when it was taken; the first draft reported "no record
  covers it" for all five targets for exactly this reason.
- **`memory.read_dword` and `memory.read_byte` return uint64 tables, not numbers.**
  The first run died at `attempt to compare table with number` on
  `n < 0 or n > 512`. Every read needs `N()` before any arithmetic, comparison or
  `%X` formatting.
