# The 14.10 aio guard is a value test, not a path test

Written 2026-11-05. Static analysis of the **13.60** body of `aio_multi_wait` (syscall 663, body RVA
`0x3b0210`) plus the measured 14.10 behaviour already recorded in
[docs/AIO_MODE0_GUARD_14_10.md](AIO_MODE0_GUARD_14_10.md). No new runtime measurement is claimed here;
§6 is the experiment that would settle it.

## 1. The argument shape, decoded

The argument unpacker at RVA `0x3b01f0`:

```
0x3b01f4 mov rax,[rsi]        ; uap[0]  ids
0x3b01f7 mov edx,[rsi+8]      ; uap[8]  count
0x3b01fa mov rcx,[rsi+0x10]   ; uap[0x10] status out
0x3b01fe mov r8d,[rsi+0x18]   ; uap[0x18] mode
0x3b0202 mov r9,[rsi+0x20]    ; uap[0x20] timeout POINTER
```

The fifth argument is a **pointer to a 4-byte value**, not a value and not a timespec:

```
0x3b04bd mov r14,[rbx+0x60]        ; the pointer
0x3b04c8 test r14,r14 ; je 0x3b0517 ; NULL = no timeout supplied
0x3b04e4 lea rsi,[rbx+0x108]
0x3b04eb mov edx,4
0x3b04f0 mov rdi,r14
0x3b04f3 call 0x8ac19280            ; copyin(user ptr, &stack_dword, 4)
```

A NULL pointer takes the `je` and skips the copy; anything else copies exactly four bytes.

## 2. Two allocations, and the one that matters

```
0x3b0524 mov r14,[rbx+0x20]        ; count
0x3b0534 lea rax,[r14*8]
0x3b053c lea rdi,[rax+rax*2]       ; count * 0x18
0x3b0540 call 0x8b5c8b50           ; status array -> r12   (only when tunable 0x8b4c78d0 != 0)
...
0x3b0576 imul rdi,r14,0x38
0x3b0586 call 0x8b5c8b50           ; waiter-node array -> r14   (unconditional)
0x3b05bc mov [rbx+0x40],r14        ; <-- FIXED base of the node array
```

`[rbx+0x40]` is what the cleanup loop later frees and what the mode-0/3+ link path reloads.

## 3. The loop advances one register and pins the other

```
0x3b05db inc r15          ; index
0x3b05de add r14,0x38     ; r14 walks the node array
0x3b05e2 add r8,0x18      ; r8 walks the status array
```

So per iteration `r14` is the `i`-th node of the array, while `[rbx+0x40]` stays at the base.

## 4. The dispatch is a value test on three code paths

```
0x3b078c mov eax,[rbx+0x2c]   ; mode
0x3b078f cmp eax,1
0x3b0792 jne 0x3b0839         ; not 1 -> 0x3b0839
0x3b0839 mov rcx,[rbx+0x40]   ; rcx = node[0], once, from the fixed base
0x3b0841 cmp eax,2
0x3b0844 jne 0x3b08e5         ; not 2 -> 0x3b08e5   <-- mode 0 AND mode 3..0xFF
```

* **mode 1** (0x3b0798) and **mode 2** (0x3b084a) link `r14` - the per-index node. One node per
  request; the unlink and the free are consistent.
* **mode 0 and every mode >= 3** fall to `0x3b08e5`, which reloads `rcx = [rbx+0x40]` - the array
  **base** - on **every** iteration:

```
0x3b08e5 mov rax,[rbx+0x58]
0x3b08f0 mov rax,[rax+0x28]
0x3b08f4 mov rax,[rax+rdx*8]   ; request for this index
0x3b08f8 mov r13,[rax+0x20]
0x3b0924 mov rcx,[rbx+0x40]    ; <-- node[0] again
0x3b093a mov [rcx],rax         ; node->lock   = &[rbx+0x104]  (this thread's frame)
0x3b0944 mov [rcx+0x10],rax    ; node->chan   = &[rbx+0xe0]
0x3b0900 mov [rcx+0x20],eax    ; node->status
0x3b0965 mov [rcx+0x30],rax    ; node->next   = old list head
0x3b0969 mov [r13+0x50],rcx    ; request->waiters = node[0]
0x3b096d mov [rcx+0x18],r13    ; node->owner  = THIS request (overwrites the previous one)
```

With `count >= 2` the same `node[0]` ends up at the head of every request's waiter list and its
`owner` field ends up naming only the last one.

## 5. Why that is a use-after-free, in the cleanup code

```
0x3b0de3 imul rax,r14,0x38
0x3b0de7 mov r12,[rdx+rax+0x18]   ; node[i].owner
0x3b0e25 cmp qword [r12+0x50],0
0x3b0e2d mov rcx,[r13+0x18]       ; node[i].owner again
0x3b0e31 mov rax,[rcx+0x50]       ; the list the owner claims
0x3b0e35 cmp rax,r13 ; je unlink_head
0x3b0e40 loop: rcx=rax ; rax=[rax+0x30] ; cmp rax,r13 ; jne loop
0x3b0e4c rax=[rax+0x30] ; [rcx+0x30]=rax   ; unlink from the middle
...
0x3b0f93 mov rdi,[rbx+0x40]
0x3b0f9e call 0x8b5c8df0          ; free(node_array)
```

The unlink removes `node[i]` from the list of the request that `node[i].owner` names - the **last**
request. Every earlier request keeps `request->waiters == node[0]`, and `node[0]` is then freed with
the array. When one of those earlier requests completes or is cancelled, its waiter walk reaches a
freed node: reads through `[node+0x30]`, unlinks through `[node+0x18]`, and wakes through
`[node]`/`[node+0x10]` - which are also the **departed thread's stack addresses**
(`[rbx+0x104]`, `[rbx+0xe0]`).

## 6. The gap this leaves in 14.10

What was measured on 14.10 (probes 1219a/1221a, four independent stubs, ids NULL, timeout NULL, and
real pending requests):

| mode | count | result |
|---|---|---|
| 0 | 1 | 0, status written |
| 0 | 2 | **-1 EINVAL**, status untouched |
| 0 | 3 | **-1 EINVAL**, status untouched |
| 1 | 2 | 0, one status word per id |
| 2 | 2 | 0, one status word per id |

Mode 0 is refused at `count > 1` before the id list is even copied in (`ids == NULL` yields EINVAL,
not EFAULT). In 13.60 no such refusal exists: mode 0 `count 2` passes both bounds (`0x3b03a3` is the
count bound, `0x3b041c` the mode bound) and reaches `0x3b08e5`.

Modes **3 and above were never measured**. The 13.60 dispatch puts them on exactly the same
instructions as mode 0. Either 14.10's guard tests the *path* - and 3 is refused too, closing the
class - or it tests the *value 0*, which is the cheapest possible patch for a bug report that named
mode 0, and mode 3 is the same UAF one integer away.

## 7. The experiment that settles it, and why it is cheap

The id-validation loop runs before any wait: an id of 0 is skipped with status `0x80020003` and the
function returns without sleeping (that is how 1219a got its mode-1/mode-2 rows). So a zero-id call at
`count = 2` answers the question without ever blocking:

```
663(ids={0,0}, count=2, out, mode=M, timeout=NULL)   for M in 0..8, 0x10, 0x40, 0xFF
```

`-1 EINVAL` = the guard covers the path. `0` with two `0x80020003` status words = the guard covers the
value 0 only, and the shared-node link is reachable on 14.10.

A real pending request does **not** return on its own: probe 1235b called mode 0 `count 1` with one
pending read and the timeout dword set to 20, and the call never came back (LOADER-STUCK). The wait
has to be woken by the request completing, so any use-after-free test needs the 663 call on a child
thread (the child-syscall capability from probe 1234a) while the parent completes the request. That is
the follow-up, and it is only worth building if the zero-id sweep says the path is open.

## 8. Measured: the guard covers the path, not the value (probe 1236a, 2026-11-05)

Boot: reboot, so the kernel moved; the probe derives `libkernel_base` at run time
(`0x839AF03B7 + 0x3B7`). Zero ids, `count = 2`, timeout NULL, one call per mode:

| mode | ret | status words |
|---|---|---|
| 0x00 | -1, err 22 | untouched |
| 0x01 | 0 | 80020003 80020003 |
| 0x02 | 0 | 80020003 80020003 |
| 0x03 | **-1, err 22** | untouched |
| 0x04 | -1, err 22 | untouched |
| 0x05 | -1, err 22 | untouched |
| 0x06 | -1, err 22 | untouched |
| 0x07 | -1, err 22 | untouched |
| 0x08 | -1, err 22 | untouched |
| 0x10 | -1, err 22 | untouched |
| 0x40 | -1, err 22 | untouched |
| 0xFF | -1, err 22 | untouched |

and at `count = 3`, modes 0x03/0x04/0x05/0x10/0xFF are all `-1 err 22` with the status buffer
untouched. `pid` stayed 80 throughout.

**Verdict: the 14.10 guard is a path test.** It refuses `mode not in {1,2}` at `count > 1`, which is
exactly the set of values that reach the shared-node path `0x3b08e5` in 13.60. There is no integer
neighbour that reopens the aio shared-waiter use-after-free: the whole class is closed, not just the
literal mode 0. The reasoning in §6 that a cheap value test would be "one integer away" was the right
question and the wrong answer.

This also retires the child-thread follow-up sketched in §7: there is no reachable state in which
`count >= 2` links one node twice, so there is nothing to race.

**Residual, not a route:** a real pending request cannot be waited on from a single-threaded probe at
all. Probe 1235b called mode 0 `count 1` with one pending read and a 20-unit timeout pointer and never
returned; a second connection then got zero bytes. Whatever the timeout dword means, `aio_multi_wait`
blocks until the request completes, so any future aio timing work must put the call on a child thread
(1234a capability) with an exit path (1234a's `jmp $` mistake).
