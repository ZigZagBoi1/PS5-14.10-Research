# sys 674 `virtual_query_all`: the magic word nobody ever passed

Status: **measured on 14.10, 2026-11-04 18:52** (probe 1196a, capture
`results/phase17_new_vectors/1196a_virtual_query_all_magic_20261104_185203.txt`), plus static reading of
the 13.60 body `0x8b47b980`.

## 1. Why the syscall looked dead for a month

Every sweep in this repository (1170a-1181a, 353a/354x, the 600-680 isolation sweep) called the Sony range
with either all-zero arguments or a 0xA5A5A5A5-filled buffer. 674 answered `-1` every time and was filed as
"ENOSYS-ish, uninteresting".

The body's first real check is:

```
8b47b9d3: cmp dword ptr [r14 + 0x20], 0x40000000     ; r14 = uap
8b47b9db: je  0x8b47b9fb
8b47b9dd: jmp 0x8b47bd2d                             ; return 0x16 EINVAL
```

**The fifth argument must be `0x40000000`.** With zeros the handler returns EINVAL before it touches
anything, which is indistinguishable from "not implemented" at the syscall boundary, because the loader's
`get_error_string()` path reports `-1` for every failure.

## 2. Argument layout (from the body, confirmed by the measurement)

| uap offset | arg | meaning |
|---|---|---|
| `+0x00` | a0 | user output buffer pointer (incremented by `stride` per record) |
| `+0x08` | a1 | stride **and** copy length: `min(stride, 0x48)` |
| `+0x10` | a2 | maximum number of records (loop bound) |
| `+0x18` | a3 | unused on the entry path |
| `+0x20` | a4 | **magic dword, must equal 0x40000000** |

Flow: `0x8b4ebb00(4)` (a gate — returns nonzero for every shape we tried except the correct one), then
`vmspace = [proc+0x200]`, `vm map lock 0x8ac86820`, `rbx = [map+8]` (first entry), then for each entry:

```
8b47bac6: call 0x8b47a710   ; (entry, start, end, &rec[rbp-0x78], 1, 1) -> fills a 0x48-byte record
8b47baff: call 0x8ac191d0   ; copyout(rec, out_ptr + i*stride, min(stride,0x48))
8b47bb08: out_ptr += stride
```

## 3. Measured output

`674(out=buf, stride=0x48, count=4, 0, 0x40000000)` returned **0** and wrote four records:

| # | +0x00 start | +0x08 end | +0x10 | +0x18 | +0x20 / +0x28 (label bytes) |
|---|---|---|---|---|---|
| 0 | `0x0F558000` | `0x0F9EC000` | 0 | 5 | `00 64 78 65 63 75 74 61` / `62 6C 65 00` |
| 1 | `0x0FB58000` | `0x0FB70000` | 0 | 1 | same |
| 2 | `0x0FD58000` | `0x0FE9C000` | 0 | 3 | same |
| 3 | `0x0FE9C000` | `0x0FED8000` | 0 | 3 | same |

Reading the label bytes as a NUL-terminated ASCII string gives `\0dxecutable\0` at `+0x20`, i.e. the label
is the word **executable** with a one-byte skew that this probe did not resolve (the record is bzero'd and
then a 0x20-byte copy lands at `rec+0x1d`, so the label field and the qword boundary do not line up).

Every other field in the record is zero. **There is no kernel pointer in the record** — starts and ends are
our own userland VAs (`0x0F5..`, `0x0FB..`, `0x0FD..` = the 245-270 MB region, our own segments) and the
only nonzero words are the protection word at `+0x18` (values 1, 3, 5 seen) and the label.

So 674 is a **clean process-vm_map enumerator**, not a leak. It is valuable as ground truth (a second,
independent view of our address space besides `kinfo_proc`/procfs) and it is *not* a kernel read.

## 4. The class this opens (the actually important part)

674 is the first measured example in this corpus of a Sony syscall that is **alive but gated on a magic
dword** that every previous sweep zeroed. That means the whole "Sony range returns -1" conclusion in
`docs/ATTACK_SURFACE.md` is weaker than it looked: a `-1` from these handlers can mean "wrong magic" just
as easily as "not implemented", and the errno is not visible through the loader's return path.

A static scan of all 301 resolved handler bodies for `cmp [uap+disp], imm` with `imm >= 0x1000` found only
this one site plus one unrelated `mov word [r14+0xa], 0x4000` in sys 363 — because most Sony handlers
delegate to inner functions before validating. So the gates have to be found **behaviourally**, which is what
probe 1196b does: it offers six structured shapes (`MAGIC` in a0/a1/a3/a4, a size word, a version word
`0x10`, and a swapped `(size, buf)` order) to 18 info-family syscalls:

`646 get_kernel_mem_statistics`, `671 get_page_table_stats`, `642 get_map_statistics`,
`618 get_paging_stats_of_all_objects`, `611 get_paging_stats_of_all_threads`, `613 get_resident_count`,
`615 get_resident_fmem_count`, `627 get_cpu_usage_all`, `641 get_cpu_usage_proc`,
`604 dl_get_metadata`, `608 dynlib_get_info_ex`, `649 dynlib_get_obj_member`,
`656 dynlib_get_info_for_libdbg`, `659 dynlib_get_list2`, `660 dynlib_get_info2`,
`672 dynlib_get_list_for_libdbg`, `676 cpumode_yield`, `675 reserve_2mb_page`, with 674 as the control.

The two names worth the most if they turn out to be gated rather than absent are **646 get_kernel_mem_statistics**
(kernel region counters/addresses = a KASLR break) and **671 get_page_table_stats** (page-table walks).

## 5. Probe bug that killed the loader (recorded so it is not repeated)

Phase 2 of 1196a called `674(buf, 0x48, 0x40, 0, MAGIC)` into a **0x800-byte** `memory.alloc` and then read
back 0x40 records = `0x1200` bytes. `memory.read_qword` past the end of the allocation takes SIGSEGV inside
the Lua process, the loader's fault handler prints its `0x13371337` blob into the TCP stream (which is why
the capture shows raw bytes after the `[2]` line: magic `37 13 37 13`, signal `0x0b` = SIGSEGV) and the
process dies. `pcall` does not protect against this — the fault is not a Lua error.

**Rule: a probe must never read past `memory.alloc`; size the buffer to `count * stride` or clamp the read
loop to the allocation.**
