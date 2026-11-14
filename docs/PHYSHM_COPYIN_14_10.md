# physhm: the mapping is not supervisor memory, it is not present at all

**Status:** measured on 14.10 (probe 1240a, 2026-11-05) plus static arithmetic from
`docs/USER_ACCESS_FAMILY_AUDIT.md`. This retires a claim in `docs/CHANGELOG.md`.

## 1. Why this was worth a probe

`docs/CHANGELOG.md:2012` recorded that `mmap(0, 0x1000, RW, MAP_SHARED, fd, 0)` over a `629`
descriptor returns a full 34-bit address, and that the first user access faults, and concluded that
the result is a *supervisor-accessible mapping*: a page mapped into the user address range whose PTEs
are not user-accessible.

That reading would have been the most valuable object in the corpus. The user-access helpers gate on
`rdi + rdx <= 0x800000000000` and then `and rdi, 0x7fffffffffff` (`docs/USER_ACCESS_FAMILY_AUDIT.md`
section 1). A PTE with U/S = 0 sitting at, say, `0x310D3C000` passes both steps, and a supervisor page
is readable from CPL0 regardless of SMAP. So a `copyin` from it would succeed and deliver kernel-side
bytes into a socket we own - a read primitive - while ring 3 could never touch it directly.

## 2. The measurement

`probes/phase17_new_vectors/1240a_physhm_copyin.lua`, result
`results/phase17_new_vectors/1240a_physhm_copyin_20261105_131220.txt` (744 bytes).

| step | call | result |
|---|---|---|
| control | `socketpair(1,1,0,&fds)` then `write(sock, marker, 0x20)` | 0x20 written, peer receives the marker |
| open | `629(1, 2, 0, a3)` for `a3` in 0..3 | descriptors **24, 25, 26, 27** |
| map | `mmap(477, 0, 0x4000, 3, MAP_SHARED=1, 24, 0)` | **0x310D3C000** |
| kernel copyin | `write(sock, 0x310D3C000, 0x20)` | **-1, errno 14 EFAULT** |

The fourth row is the whole result. `write` on a socket pair reaches `copyin`, which is entry 1 of the
user-access family: `rsi + rdx <= 0x800000000000` passes for `0x310D3C000 + 0x20`, `[proc + 0x591]` is
0, the `stac` window opens, and the `rep movs` faults anyway. A present supervisor page cannot fault
there. A page whose PTE is simply absent can, and does, and the onfault handler turns that into
EFAULT.

So the object behind a `629` descriptor never populates the mapping. `mmap` on it returns an address
and nothing else - no vm_page is attached, no PTE is valid, and the first touch on either side of the
privilege boundary is a not-present fault.

## 3. What this changes

`docs/CHANGELOG.md:2012` is corrected in place. The operational consequence is that physhm is a
**guaranteed-fault generator at a chosen 34-bit address**, not a readable region:

* it is still a usable way to make a child fault at a value we picked, which is what the kernel-base
  oracle in `probes/phase17_new_vectors/1001a_kernel_map_sweep.lua` does with RIP instead;
* it is *not* a route to any kernel-side read, and the earlier note's "there is no write path" stands
  for the same reason, just with the correct mechanism.

## 4. The measurement that separates the two readings, and it is cheap

The EFAULT argument assumes the fault is a *not-present* fault. That follows from the uaccess code,
but it is inference, not a reading of page state. Two independent discriminators exist:

* **`mincore` (sys 78, three arguments).** It reports residency without touching the page: rv 0 and
  `vec[i] & 1` set means the page is in core. `probes/phase17_new_vectors/1240b_physhm_residency.lua`
  runs it on a touched anonymous page (control - must read resident or the probe states that no
  verdict is admissible), an untouched anonymous page, the physhm mapping, and one kernel address.
  A touched page that reads resident plus a physhm page that reads non-resident settles it, and the
  probe costs one ordinary connection with no faulting child and no relaunch.
* **the #PF error code.** Spawn a child whose RIP is the physhm address (`thr_create(430)`, `+0xe0`
  RIP, `+0xc0` 0x43, `+0x108` 0x480, `+0x110` 0x10000, `+0xf8` RSP), let the loader's SIGSEGV chain
  emit its 0x80-byte blob, and read `blob + 0x30`: bit 0 clear is not-present, bit 0 set with bit 2
  clear is present-but-denied. This is the fallback if `mincore` turns out to be a stub, and it costs
  a relaunch every time it runs.

## 5. Probe defect that cost the session

1240a ended with the loader wedged (`LOADER-STUCK: accepted, no reply`). The cause is probe-side and
has nothing to do with physhm: the probe used `read` (syscall 3) with a flags argument on a socket
with nothing queued, and `read` blocks. **On this loader, use `recvfrom` (syscall 29) with
`0x80` = MSG_DONTWAIT**, or only attempt the receive when the preceding write returned more than zero.
`MSG_WAITALL` is `0x40` and is the opposite of what a probe wants; the two constants are one keystroke
apart and the wrong one is silent.

## 6. Standing rule earned

A successful `mmap` is not evidence of a mapping. Only a successful access is. Every future claim of
the form "X maps Y" needs an access through the mapped range, and where the interesting direction is
kernel-side, that access has to be a syscall that copies from the range - not a ring-3 read.