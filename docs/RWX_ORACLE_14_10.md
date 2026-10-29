# Executing a page we own on 14.10

Status: **measured — user mappings do not execute.** This is the first direct
test; the earlier W^X verdicts were syscall returns (`mprotect` always `-1`,
`mmap` returning RW for an RWX request) rather than an attempt to run from one
of our own pages.

## Why the thread entry had to be pinned first

`thr_create(430)` starts a thread from the ucontext we supply, and until now
every working probe entered at `syscall.pipe.fn_addr` — the fcall stub — with a
gadget chain on the stack (904a, 910a). A thread entry is an arbitrary
instruction pointer, so the oracle needs an entry other than the stub to be
proven safe first, otherwise "the page faults" and "entering at anything but
the stub is wrong" look identical.

## Measurements

### 928a — uncontrolled, not evidence
`probes/phase17_new_vectors/928a_exec_page_oracle.lua` started the *control*
thread at `pop_rdi` (a two-byte match `5F C3`). The child printed 449 bytes of
raw context to stdout and took the game down before any result line. A two-byte
pattern match can sit mid-instruction, so the control itself was unsound. No
conclusion.

### 928b — the page faulted, but the control was still the stub only
`probes/phase17_new_vectors/928b_exec_page_oracle.lua`:

```
[A] control, entry=fn          rv=0, out=88   (getpid ran, chain works)
[B] code page holds 0xC3       dword=0xC3
[C] mprotect74 -1, vm548_a -1, vm548_b -1, mtype585_a 1, mtype585_b 1
[D] spawn entry=code_page      raw context dump, process died
```

The dump is our own 0x500-byte context buffer: `MAGIC` `0x480`, `SS` `0x3b`,
`RIP` `0x310F08000` (the code page), `RSP` `0x310F17E00` (our stack). A fault
printing the context it faulted on is the only thing in this run that emits
those bytes — the same dump appeared for 928a's wild child and for nothing
else.

### 928c — the control that makes it evidence
`probes/phase17_new_vectors/928c_exec_page_control.lua`:

```
[A] entry=fn            rv=0  out1=95            alive=95
[B] entry=store gadget  rv=0  out2=0x1234        alive=95
[C] entry=code_page     raw context dump, process died
```

`[B]` enters a real eboot instruction pair — `mov [rdi],rax; ret` at the
`store` gadget — with `RDI` pointing at `out2` and `RAX = 0x1234`. The write
landed (`out2 = 0x1234`), the `ret` fell into the same chain, `getpid` stored
95 into `out1`, `thr_exit(431)` ended the thread, and the process stayed up.
So: any executable address works as an entry, the chain works, and cleanup
works. The only variable left in `[C]` is the page.

### 934a — a shared mapping with PROT_EXEC requested explicitly
`probes/phase17_new_vectors/934a_shm_rx_page.lua`, on pid 102:

```
shm_open   fd=22                ftruncate 0
RW alias   mmap prot=3  addr=0x311060000   wrote 0xC3
RX alias   mmap prot=5  addr=0x311064000   read back 0xC3   (the page is readable)
stack      block=0x311088000 start=0x311097E00
spawn      [BEFORE] entry=0x311064000  ->  context dump, process died
```

`mmap` accepted `PROT_READ|PROT_EXEC` and returned a mapping that reads back the
byte, so the request is not rejected — the permission is dropped, and the
fault happens on instruction fetch at the alias. Same for `PROT_READ|PROT_WRITE|PROT_EXEC`
on the fallback path.

## Conclusion

Every mapping we can create is NX: anonymous GPU memory (928b/928c) and a
shared POSIX shm object mapped `PROT_READ|PROT_EXEC` (934a) both fault on the
first instruction fetch, while an eboot gadget entered the same way runs to
completion (928c `[B]`: `out2=0x1234`, chain ran, thread exited, process
alive). `mprotect(7)` and both `548` shapes return `-1`; `585` returns `1`
without changing anything.

Running our own machine code therefore requires a kernel primitive that
changes a page's protection - it cannot be reached from userland syscalls
that are reachable today. A faulting thread is fatal to the whole process, so
each attempt costs a game restart.

## 939b-939e: the X bit is dropped when the entry is created (2026-10-28)

The earlier sections inferred the wall from faults. `sys 547` reports the
VM entry's protection word directly, so the wall can be measured without
executing anything (`results/phase17_new_vectors/939e_entry_prot_oracle_20261028_204919.txt`, pid 141):

| mapping | requested prot | entry prot (547 +0x10) | entry flags (+0x14) |
|---|---|---|---|
| anonymous GPU | 3 (RW) | `0x3` | `0x610020` |
| file, `MAP_PRIVATE` | 3 (RW) | `0x3` | `0x10024` |
| file, `MAP_PRIVATE` | 5 (R\|X) | **`0x1`** | `0x1002C` |
| file, `MAP_PRIVATE` | 7 (RWX) | **`0x3`** | `0x10024` |
| file, `MAP_SHARED` | 5 (R\|X) | **`0x1`** | `0x18020` |

`mmap` accepts `PROT_EXEC`, returns a usable mapping, and builds the entry
with X removed. That explains every earlier result and closes the file-backed
avenue that 928b/934a could not test:

* `mprotect` refuses 0/1/3 and *always* refuses 5 and 7
  (`939b`: `mprotect(rw, PAGE, 0|1|3) = 0`, `5|7 = -1`), consistent with a
  `max_prot` derived from the stripped value: there is nothing to re-grant.
* a file mapping with `prot=5` reads back the file's bytes, and the first byte
  of the file we wrote is `0xC3` (`939c`: `first byte=195`), so the mapping is
  real - only its execute bit is gone.
* `/av_contents/content_tmp` is writable from the loader (`open(...O_RDWR|O_CREAT)`
  = fd 24, `write` = 8), so this was not a permission problem on the file.

Reaching executable memory from userland is therefore impossible on 14.10 by
construction, not by a policy check that can be argued around: the kernel never
writes an executable user PTE. The only executable bytes available to us are
those already mapped by the loader (eboot and the modules), which is why the
`thr_create` chain runs gadget code and nothing else.

`open(5)` detail worth keeping: the path must be a **raw Lua string** argument,
not `uint64(path)`. `930a` wrapped every path in `uint64()` and every call
pcall-failed; `939b` passes the string and gets a real fd.

### The last loophole is closed too: no writable file backs an executable mapping

The only way left to obtain executable memory would be to share a page with a
mapping the kernel already made executable. `940a` measured it
(`results/phase17_new_vectors/940a_exec_backing_file_20261028_205023.txt`):

* `open("/app0/eboot.bin", O_RDONLY)` = fd 23, **`O_RDWR` = -1**;
* `mmap(fd, PAGE, prot=1, MAP_SHARED)` succeeds but returns `0x120101001D3D154F`,
  not `\x7fELF` - the file is an encrypted SELF container, so the bytes on disk
  are not the bytes that execute;
* `mmap(fd, PAGE, prot=3, MAP_SHARED)` = -1, so even the read-only fd cannot
  produce a writable shared mapping.

The decrypted text the loader runs is therefore a kernel-side object that
nothing in userland can reach. Writing executable code requires a kernel
primitive, and that is where the remaining work is.

## 951a-953a: MAP_FIXED over an execute-only entry does not inherit X (2026-10-29)

Every earlier probe created a *new* entry, where the X bit is stripped before
the entry exists. The one route left untested was replacing an entry the kernel
had already built as executable. `sys 547` reports such an entry: eboot text
from `ebase` to `ebase+0x494000` reads `prot=0x4` (execute-only) for its whole
span.

**951a** (`results/phase17_new_vectors/951a_mapfixed_over_exec_20261029_201443.txt`)

1. `547` on five pages below the fcall stub: each reports `start=0x3108D8000
   end=0x310968000 prot=0x4`.
2. `mmap(target, PAGE, 7, MAP_FIXED|MAP_ANON, -1)` returns the target address.
3. `547` on the same page still reports `prot=0x4`.
4. The page accepts a byte write and reads it back (`0xC3`).

So the mapping is replaced with writable memory while the region record keeps
the old protection word.

**952a** (`952a_mapfixed_exec_spawn_20261029_201641.txt`) answers whether that
page executes. Control and test run in one process:

```
--- C: control, entry=store gadget ---
  C ok=true rv=0 out2=1234 (want 1234) out1=594 alive=594
--- D: entry=MAP_FIXED page (holds 48 89 07 C3) ---
77<binary>
```

The control's eboot entry runs (`out2=0x1234`, parent alive); the same shape
entered at the replaced page produces binary output and takes the process down
before the parent's next line. The replacing mapping is writable but not
executable.

**953a** (`953a_mapfixed_mprotect_x_20261029_201910.txt`) removes the last
doubt - that the page had merely not been replaced:

```
self write read back C3078948
entry after mmap: prot=0x4
qword +8 = 0x0   qword +0x10 = 0x0
mprotect(4) ret=-1
mprotect(5) ret=-1
mprotect(6) ret=-1
```

The bytes past our write are zero, so the eboot page really was replaced by
anonymous zero-filled memory. And `mprotect` refuses to grant execute to it in
every form. The `prot=0x4` that `547` keeps reporting describes the original
region, not the replacement's `max_prot`: if it were the new entry's limit,
`mprotect(4)` would succeed.

`MAP_FIXED` therefore closes the same way as every other route: it can make a
page writable, never executable, and cannot reuse a pre-existing X to do it.
