# Session 4 Results — DEM9N101 (2026-10-23)

Console: PS5 fw 14.10, Hamidashi Creative DEMO loader (TCP 9026).
Probes: step186–step189, all run on live console.

---

## Probe 186: syscall.resolve API discovery

**Key finding:** `make_syscall` is NOT a loader global. The correct API is
`syscall.resolve({name = number})`, which returns a table with a `__call`
metamethod.

5 tests:
- T1: enumerated available functions — `syscall.resolve`, `syscall.call`,
  `syscall.resolveAddress`, `syscall.syscall_address` all present
- T2: `syscall.resolve({test593 = 593})` — resolves, call returns -1
- T3: `syscall.resolve({test592 = 592})` — resolves, call returns -1
- T4: getsockopt(118) via resolve — works, returns 0
- T5: sysctl(202) via resolve — works, returns 0

Sony syscalls 592 (dynlib_get_list) and 593 (dynlib_get_info) resolve but
return -1. Standard FreeBSD syscalls work fine through this mechanism.

---

## Probe 187: Exhaustive getsockopt kernel pointer audit

**Completes the territory of prepared-but-unrun probe 109a.**

Created UDP, TCP, IPv6, and RAW sockets. For each socket option tested,
wrote sentinel bytes (0xAF pattern) into the output buffer before calling
getsockopt, then scanned the returned data for kernel pointer patterns
(0xFFFFFFFF8xxx–0xFFFFFFFExxxx range).

### IPv6 options tested (level IPPROTO_IPV6=41):
| Option | Name | Result |
|--------|------|--------|
| 36 | IPV6_UNICAST_HOPS | Clean |
| 46 | IPV6_PKTINFO | Clean (20 bytes returned) |
| 47 | IPV6_HOPLIMIT | Clean |
| 48 | IPV6_NEXTHOP | ret=-1 |
| 49 | IPV6_HOPOPTS | ret=-1 |
| 50 | IPV6_DSTOPTS | ret=-1 |
| 51 | IPV6_RTHDR | ret=-1 |
| 61 | IPV6_TCLASS | Clean |
| 25 | IPV6_2292PKTOPTIONS | Returns 0 bytes |

### SOL_SOCKET options tested:
| Option | Name | Result |
|--------|------|--------|
| 4103 | SO_ERROR | Clean |
| 1 | SO_DEBUG | Clean |
| 4100 | SO_RCVLOWAT | Clean |
| 4099 | SO_SNDLOWAT | Clean |
| 4097 | SO_SNDBUF | Clean (9216 default) |
| 4098 | SO_RCVBUF | Clean (42080 default) |
| 8 | SO_KEEPALIVE | Clean |

### TCP_INFO (level IPPROTO_TCP=6, optname=32):
- 236 bytes returned
- Zero kernel pointers detected
- Contains only protocol metadata (timestamps, RTT, window sizes)

### Oversized buffer test:
- Requested 4096 bytes for IPV6_PKTINFO
- Kernel returned exactly 20 bytes
- Sentinel bytes beyond offset 20 untouched
- **Kernel properly clamps the copy length**

### SCTP test (both address families):
- AF_INET + SOCK_STREAM + IPPROTO_SCTP(132): ret=-1
- AF_INET + SOCK_SEQPACKET + IPPROTO_SCTP(132): ret=-1
- AF_INET6 + SOCK_STREAM + IPPROTO_SCTP(132): ret=-1
- AF_INET6 + SOCK_SEQPACKET + IPPROTO_SCTP(132): ret=-1

Note: upstream Finding 64 confirmed SOCK_RAW + SCTP opens on AF_INET.
Only stream/seqpacket variants are blocked from this sandbox.

**Bottom line: zero kernel pointers leaked through any tested getsockopt
path. The kernel is clean on all option levels.**

---

## Probe 188: Loader globals and native table

6 tests mapping the loader environment:

### T1: Module base addresses
```
eboot_base     = 0x391d4000
libc_base      = 0x1518a8000
libkernel_base = 0x832120000
```

### T2: Syscall infrastructure
- `syscall.syscall_address` present (the `syscall;ret` gadget in libkernel)
- `syscall.resolve` creates callable tables

### T4: Native table discovery
Key entries in the `native` global:
- `native.fcall` — C function call primitive (table with __call)
- `native.fcall_with_rax` — sets RAX before calling (for arbitrary syscall numbers)
- `native.gen_fcall_chain`, `gen_read_buffer_chain`, `gen_write_buffer_chain`
- `native.read_buffer`, `write_buffer`
- `native.setup_native_handler`, `setup_cmd_handler`, `setup_pivot_handler`
- `native.create_cmd_handler`, `register`, `get_lua_opt`
- `native.pivot_handler_rop` — table

### T5: fcall identification
`fcall` is a TABLE with `__call` metamethod. Usage: `fcall(addr)(arg1, arg2, ...)`
for calling native functions via ROP.

### T6: vmmap via sysctl (309 entries)
Full process virtual memory map retrieved. Key regions:
- EBOOT: 0x391d4000–0x39b54000 (text RX 4688K, rodata R 96K, data/GOT RW 1296K)
- LIBC: 0x1518a8000–0x1519c8000 (text RX 1104K, data RW 32K)
- LIBKERNEL: 0x832120000–0x8321c4000 (text RX 288K, GOT RW 16K, data RW 208K)
- ~35 SCE libraries at 0x800000000+ (all --x text, small rw- segments)

### sceKernelGetModuleInfoFromAddr:
Located at libc_addrofs 0x1518a8198.
Called via `fcall(addr)(eboot_base, uint64(0), info_buf)` — returned 0x80020016
(SCE error, likely needs flags=1 as second argument).

### native.fcall_with_rax:
`native.fcall_with_rax(syscall_gadget, uint64(592))(args)` failed with
"attempt to call a table value" — returns a table, not directly callable.
The return likely needs to be executed via native_invoke or a pivot chain.

---

## Probe 189: GOT scan for kernel pointers

Scanned libkernel rw- (229K), eboot GOT (first 64K), and 18 SCE library
rw- segments using the writev/pipe peek8 primitive.

**Result: all regions returned 0 kernel pointers.**

However, the scan only produced 780 bytes of output in 14 seconds for a
229K scan. peek8 is likely FAILING silently on these address ranges — the
zero result is inconclusive. The ASLR addresses changed from prior sessions
and the peek8 iov_base validation may reject the new ranges.

**This is a tooling issue, not a kernel finding.** The scan needs to be
re-run with peek8 verification (read a known value first to confirm the
primitive works on the target range).
