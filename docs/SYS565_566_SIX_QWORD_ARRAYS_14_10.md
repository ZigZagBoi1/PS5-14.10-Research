# syscalls 565 and 566: six qwords at per-thread +0x160 and +0x190

## The shape

Both bodies are in the thread-control cluster and both write caller data into a six-entry qword
array inside a kernel object. 565 (`0x6034e0`) writes **masked** values at `[obj + idx*8 + 0x160`;
566 (`0x603710`) writes **unmasked** values at `[obj + idx*8 + 0x190`, where `obj = [thread + 0x3f8]`.

Argument decoding, 565:

    6034ee  mov r12d,[rsi+8]        ; arg1 = index
    6034f2  mov r13, [rsi+0x10]     ; arg2 = value
    6034f6  movabs rcx,0xfffffff0007b0000
    603506  cmp r12,6 / setae al    ; index must be < 6
    60350d  test r13,rcx / setne cl ; value may only use bits outside that mask
    60351b  mov r15d,[rsi]          ; arg0 = thread id (or a small handle)
    603528  movabs rcx,0x100000070 / and rax,r13 / cmp rax,rcx  ; and cmp rax,0x6e
    603540  movabs rax,0xfff8400ff / and r13,rax                ; second-stage mask
    6035cd  mov rbx,[rax+0x3f8]     ; obj
    603608  mov [rbx+r12*8+0x160],r13

566 is the same skeleton with `lea eax,[r13-6]; cmp eax,-7; jb` admitting `{-1, 0..5}` (index -1
means "all six"), and the store is

    6037e5  mov [r15+r13*8+0x190], r12     ; r12 = [rsi+0x10], no masking at all
    603874  mov [rbx+r13*8+0x190], r12     ; same store inside the list walk

so 566 accepts **any 64-bit value** and places it at a caller-chosen slot of a six-qword kernel
array. Both bodies end by kicking the target thread through `0x602d40` / `0x602e80`, which read
`[obj+0x400]`, set bits in `[obj+0x380]`, and issue `0x81e4d0(id, 4|5|6)` - an IPI or
scheduler notification.

## The lookup, and what it costs

    lea eax,[r15-1] / cmp eax,0x1869e / ja  takes the handle path
    603747  mov rdi,[rdi+0x140] / call 0x26d0a8     ; capability check on the caller
    603764  call 0x53c170                            ; handle -> object
    603780  call 0x609890                            ; object+0x10 -> [+0x140] -> check
    60378d  mov r14d,1                               ; EPERM when that check fails

    the other path is the thread hash resolver already decoded in THR_LOOKUP_14_10.md:
    6037ad  call 0xb92420(tid, curproc->p_pid)       ; ESRCH 3 when the tid is not ours

So a caller may aim at any thread **of its own process**; a foreign tid returns ESRCH.

## What the block is: the OPMC family

The 13.60 sysent name table names the block. `docs/sysent-names-13.60.csv` lines 565-569 and
627-628 give 563 `opmc_enable`, 564 `opmc_disable`, **565 `opmc_set_ctl`**, **566 `opmc_set_ctr`**,
567 `opmc_get_ctr`, 625 `opmc_set_hw`, 626 `opmc_get_hw`. OPMC is the console's wrapper over the
AMD performance-monitoring counters, so the two six-entry qword arrays are **per-thread PMC control
words (+0x160) and counter values (+0x190)**, and the thread kick is the cross-core notification that
reloads or restarts the counters. That reading explains every shape in this document at once: six
slots for six hardware counters, a restricted bit mask on the control words (reserved and
counter-select fields), no mask on the counter values, and an index bound of 6.

This also means the block is *expected* to be per-thread and kernel-owned, and the write is a
configuration write, not an object overwrite.

The corpus already measured the argument surface on 14.10 (`docs/CHANGELOG.md:2938-3012`, probes
177a-177d): all four of 563-566 return `0` to six zero arguments; 565 accepts index
`{0,1,2,3,4}` and rejects 7 and above; 566 accepts `{0,1,2,3,4,0xFFFFFFFF}`; the first argument must
be 0 in every case; there is no state between calls and **no read side** - 567 `opmc_get_ctr`
rejected twelve argument layouts. 625/626 are present and return `-1` (`docs/ATTACK_SURFACE.md:190-240`,
`docs/COPYOUT_TABLE_INDEX_AUDIT.md:287`, body `ffffffff8afc4cf0`, one bounded six-entry jump table).
A stub that accepts every value and reads nothing is what a console with the PMC units fused off
looks like, and it is also what a pure argument-checking stub looks like; the two are
indistinguishable from outside, and neither is a memory primitive.

## The two readings tested before the identification

Two candidate readings were tested and one was rejected:

- **Not the debug registers.** The DR installer at `0xa07860` loads DR0-DR3 and DR6/DR7 from
  RIP-relative globals (`a078e7 mov rax,[rip+0x31ac932] / a078ee mov dr0,rax`), not from a
  per-thread block, and the context switch save/restore at `0x25234d`- `0x25255d` copies the six
  registers through registers, not through this structure.
- **Unresolved.** An image-wide scan finds 37 sites that load a qword from `[reg+0x190]` and
  dereference it. Six of them share one shape and are the only ones that read a plausible kernel
  field:

      37bfd8  mov rdi,[rbx+0x190] ; 37bfdf mov eax,[rdi+0x7c]
      37c2c5  mov rdi,[rbx+0x190] ; 37c2cc mov eax,[rdi+0x7c]
      a81dc1  mov rdi,[rbx+0x190] ; a81dc8 mov eax,[rdi+0x7c]
      ac5e23  mov rdi,[rbx+0x190] ; ac5e2a mov ecx,[rdi+0x7c]
      ae6ad8  mov rdi,[rbx+0x190] ; ae6adf mov eax,[rdi+0x7c]
      ae6cf8  mov rdi,[rbx+0x190] ; ae6cff mov eax,[rdi+0x7c]

  None of them is shown to take `rbx` from `[thread+0x3f8]`, and several are in assertion and
  error-string helpers where the base is a different object that happens to have a field at +0x190.
  Treating them as consumers would be the same guessing that produced the retracted rows earlier in
  this project.

## Verdict

565 `opmc_set_ctl` and 566 `opmc_set_ctr` are a **bounded write into the calling thread's PMC
control and counter slots** - six slots, index bound 6, control words masked, counter values free,
target thread restricted to the caller's own process by resolver `0xb92420(tid, p_pid)`. The object
is a per-thread PMC descriptor, not a general kernel structure, and the arrays are six entries wide
with the index checked before the store, so there is no OOB and no confused-object shape.

Nothing is gained by a caller-chosen counter value: the counters are written, not read back, and
567 `opmc_get_ctr` has never accepted a layout. The only interesting residual is *microarchitectural*
- if the PMC units were live, a caller who can set control words and start counters on its own thread
could count events while other code runs. The 14.10 measurements say they are not live (no state, no
read side, every value accepted), so this is closed as a stub, not as a primitive.

Reopening condition: a layout for 567 `opmc_get_ctr` that returns the counter the caller set through
566. That would turn the pair into a counting oracle, which is still not a memory read.

## Reproduce

    python .local/dis_565.py     # bodies 0x6034e0 and 0x603710
    python .local/scan_3f8.py    # 312 [reg+0x3f8] accesses image-wide
    python .local/scan_160_190.py# 698 [+0x160]/[+0x190] accesses, 37 load-then-deref
    python .local/dis_drblk.py   # the DR installer at 0xa07860
