# Changelog — PS5 14.10 Kernel Research

## 2026-10-18: CVE-2026-58083 PS5 14.10 assessment

- Recorded the upstream kqueue copy-on-fork timer-knote UAF and its stated FreeBSD release scope.
- Audited saved probes 20, 21, and 27: timer filters work in the tested path, but copy-on-fork is not exercised and tested process-creation calls return -1.
- PS5 14.10 applicability and patch status remain unknown. Corrected stale kqueue summaries that described `kevent` as universally blocked.
- No PS5 vulnerability trigger or exploitation test was performed; see `docs/CVE-2026-58083-PS5-14.10.md`.

## 2026-10-18: CVE-2026-45258 PS5 14.10 assessment

- Confirmed the upstream FreeBSD advisory and fix for the `/dev/dsp` mmap offset overflow; PS5 applicability remains unverified because no Sony driver comparison or prior device result is available.
- Added probe 54a for low-impact open/close availability checks only. It does not issue ioctl/mmap calls or submit overflow parameters, and remains prepared pending an on-device run.
- Documented what the upstream sources establish, current PS5 evidence gaps, and the limits of the access-only probe in `docs/CVE-2026-45258-PS5-14.10.md`.

## 2026-10-18: Static review of prepared retests 53a–53d

- The four prepared probes (`53a`–`53d`) were statically reviewed against `docs/RETEST_PLAN_53.md` and the 2026-10-17 evidence audit: no concrete static errors found, no probe sources changed, and the retest-plan SHA-256 values re-verified as current.
- None of the probes has been run; the evidence rules, run order (53a first — it can stop the loader session; 53d last), and "what does not count" criteria in `docs/RETEST_PLAN_53.md` are unchanged.
- Review observations retained: `53b` exercises only the `proto=0` fallback, and its five consecutive `MSG_DONTWAIT` receives run with no inter-call delay — a silently dropped response is not evidence that the kernel did not respond; `53b`'s `response_kinds` result is unused; `53d` counts `RESTORE-FAILED` slots under `unknown`.
- Review environment note: no automated Lua parser was available; the pass was manual and line-level, with hazard checks (duplicate markers, `goto`, non-ASCII) clean.

## 2026-10-17: Evidence-audit corrections

- Probe 43o's RTM_GET write returned `-1`; its read returned 108 bytes with zero detected pointers and unresolved attribution. AF_ROUTE leak and patch status remain unestablished.
- Probe 43p ends before the first AIO result; separate probe 19g records `aio_error rv=-1`. A kernel-level AIO kill is not evidenced.
- Probes 43a/43b are header-only (145 B / 116 B) and contain no result or kill record.
- Probe 47b did not write-test CClosure offset `+0`; its conclusion is unresolved.
- Probes 53a–53d are prepared for these retests and have not been run. See [the evidence audit](EVIDENCE_AUDIT_2026-10-17.md).

## 2026-10-17: Probe 51c — Survey Part 2 (Evidence Correction)

### Key Findings
- The saved raw output contains results only for 625 and 626, both -1.
- It does **not** show syscall 661 being called or a process kill boundary. The earlier attribution of the stop to 661 and the claim that the whole 661–670 group is sandbox-enforced were unsupported and are withdrawn.
- The separate 43p AIO probe ends at standard `aio_error` syscall 317, before reaching its planned Sony-range scan. It supplies no result for Sony syscall 663.

### Next
Any future probe must be interpreted from its saved raw per-call output; do not infer a syscall result from a planned probe sequence or a missing log tail.

---

- Probe sources 52a (survey 627–676) and 52b (syscall 624 VM-map experiment) are present, but no saved outputs were found; neither has a result to interpret.

## 2026-10-17: Probes 51a + 51b — Sony Syscall Survey & Deep Testing

### Key Findings
- **51a: 7 accessible Sony syscalls from first ~55 tested.** 596 (dynlib), 572 (vm), 624 (vm, ret=3377), 563-566 (proc). Output truncated before completing full 110.
- **51b: 11 total accessible Sony syscalls.** Added 585 (mtypeprotect), 606, 643 (event group), 640 (accepts buffer, returns zeros).
- **Correction (2026-10-17):** syscall 624 changed from 3377 to 3376 across the two saved processes. Its 13.60 handler reads a scalar field from a VM-related object; two values do not establish a live counter or side channel.
- **No kernel pointers** in any output buffer. KASLR defeat via Sony syscall info leak: NEGATIVE.

### Analysis
The saved 51a/51b logs cover only part of the Sony range. Their non-error returns are observations for specific arguments, not proof of general accessibility or exploitability. Static analysis of 13.60 handlers gives follow-up hypotheses; see `docs/CROSS_FIRMWARE_PATTERN_RESEARCH.md`.

### Next Steps
- Complete the survey (syscalls 627-676 untested)
- Correlate syscall 624 with controlled VM state only if an existing probe result or a deliberate future session justifies it; no saved 52b result is present
- Test 606/643 with proper event structures (may be evdev/notification syscalls)
- Test 640 with different arg structures (returned 0 with all-zero buffer)

---

## 2026-10-17: Probes 50a-50d — Exotic Protocols, Timers, Tunneling, Exhaustion

### Key Findings
- **50a: 86 exotic protocol packets, no crashes.** IGMP, GRE (recursive), ESP, AH, PIM, OSPF, VRRP, IP-in-IP, batch protocol sweeps — all robust.
- **50b: TCP keepalive options blocked.** TCP_KEEPIDLE/INTVL/CNT return -1. SO_KEEPALIVE works. Probe timed out after Section A.
- **50c + 50d: 0 bytes received — loader broken.** Both probes fail to produce any output. PS5 accepts TCP on 9026 but doesn't execute Lua. Even `print("PING")` returns nothing. PS5 needs loader restart.

### Analysis
Saved runs 48b (39 SCTP variants), 48c (83 IPv6 packets), 49a (182 TCP segments), 49b (280 IPv6 fragments) and 50a (86 exotic-protocol packets) reached COMPLETE. These are bounded send/output observations, not proof of complete handler coverage, network hardening or absence of vulnerabilities. The loader becoming unresponsive after the timer manipulation probe (50b) is notable — timer callbacks may have left the per-connection process spawning in a bad state.

### After Loader Restart
- **50c retried:** fd limit at 63 connections (sandbox cap), backlog flood timed out. Sections B-H not reached.
- **50d retried:** Still 0 bytes. **Consistently kills the loader** — all subsequent probes fail until PS5 restart. Even minimal test probes die after 50d runs. This is the most interesting failure: persistent loader corruption from a single probe.

### Pending
- 50d needs probe-writing session to debug Lua source for parse errors vs real kernel/loader bug
- 50c needs backlog flood section to use nonblocking connect (MSG_DONTWAIT or fcntl)

---

## 2026-10-17: Probes 49a + 49b — TCP Stateful Injection & IPv6 Fragment Reassembly (No Crashes)

### Key Findings
- **49a: TCP_INFO leaks sequence numbers** (Finding 70) — SND_NXT at offset +108, RCV_NXT at +112. Before: CLI=`0x7F10A75E`, SRV=`0x57DB27AD`. After 100B/50B exchange: exact delta match. Differential analysis works reliably.
- **49a: RST with exact seq didn't tear down connection** — state remained ESTABLISHED=4. The log reports 182 injected segments and COMPLETE; no challenge ACK exchange or RFC 5961 compliance is established.
- **49a port fix**: original ports 44444/55555 were ≥40000 (blocked by PS5 port policy). Fixed to 31337/31338.
- **49b: 280 IPv6 fragments, zero crashes.** Teardrop overlaps, queue exhaustion (50 incomplete + 101-frag bomb), max-size 65535B, over-max 65784B, atomic frags, 10 interleaved IDs reverse-completing, ext hdr combos, nested frag-in-frag, fragmented ICMPv6 — the log records these cases being sent and the run reaching COMPLETE; it does not establish that every intended reassembly handler processed them.

### Analysis
Saved tests cover the following four bounded sets; they do not exhaust these attack surfaces:
- SCTP chunk parser (39 variants, probe 48b)
- IPv6 extension headers (83 variants, probe 48c)
- TCP state machine injection (182 segments, probe 49a)
- IPv6 fragment reassembly (280 fragments, probe 49b)

The logs report **39 SCTP variants, 83 IPv6 packets, 182 TCP segments and 280 IPv6 fragments**, and each reaches COMPLETE. These counts use different units and do not establish handler coverage or RFC compliance. In 49a the observed TCP state remained ESTABLISHED after RST injection; that alone does not confirm RFC 5961 challenge ACK behavior. The 49b output does not independently establish RFC 5722 fragment-drop behavior.

### New Primitive
TCP_INFO seq number leak + raw IP socket + loopback checksum bypass = precise TCP injection into live connections. Confirmed working but TCP state machine handles it cleanly.

### Next Escalation Paths
1. Timer manipulation — keepalive/persist timer abuse over extended periods
2. High-volume resource exhaustion — thousands of connections/fragments to hit memory limits
3. Cross-protocol tunneling — IPv6-in-IPv4 (proto 41), GRE encapsulation edge cases
4. Less-tested protocol handlers — IGMP, PIM, VRRP, ESP/AH (simpler parsers, less audited)
5. PC-coordinated network attacks — real network packets from external host

---

## 2026-10-16: Probes 48b + 48c — SCTP and IPv6 Fuzz (No Crashes)

### Key Findings
- **48b: SCTP chunk parser robust** — 39 malformed SCTP variants via loopback raw socket, all delivered, zero crashes. INIT/SACK/COOKIE/ABORT/FWD_TSN/multi-chunk/unknown types all handled.
- **48c: IPv6 extension header parser robust** — 83 malformed IPv6 packets, zero crashes. HBH overrun, Routing Type 0 CVE, fragment overlaps/bombs, 16-deep header nesting, ICMPv6 option len=0, payload length mismatches all survived.
- Both loopback (127.0.0.1/::1) and LAN IP (10.0.0.96) delivery confirmed working via raw sockets.

### Analysis
The cited packet tests reached their completion markers; parser coverage and general hardening remain unestablished. Historical follow-up proposals:
1. **State-dependent SCTP** — complete INIT handshake to establish association, then send DATA/SACK/FWD-TSN on live state
2. **Real IPv6 fragment reassembly** — proper first+last fragment pairs with valid offsets, then overlaps and timing
3. **NDP cache poisoning** — valid-checksum NS/NA/RA to manipulate neighbor cache
4. **Protocol interaction** — IPv6-in-IPv4 tunneling, GRE/ESP encapsulation edge cases

---

## 2026-10-16: Probes 48a + 46c — MASSIVE Network Attack Surface Discovered

### Key Findings
- **★★ SCTP raw socket OPEN** (48a): `socket(AF_INET, SOCK_RAW, 132)` returns fd=22. Stream/dgram/seqpacket fail. Raw SCTP = direct access to kernel SCTP chunk processing.
- **★★ IPv6 fully available** (48a): TCP, UDP, RAW, ICMPv6 all open. 17 raw IPv6 protocols. Dual-stack possible (IPV6_V6ONLY can be disabled).
- **143 raw IPv4 protocols** (48a): Every protocol 0-142 creates a socket. GRE, ESP, AH, IGMP, PIM, VRRP all reachable.
- **IP options listener works** (46c): UDP+RAW sockets bound, IP_RECVOPTS set. 0 packets received (PC injector not running). Infrastructure validated.

### Impact
Network-side kernel attack surface is far larger than expected. SCTP, IPv6 NDP/fragmentation, and exotic protocol handlers are all reachable from the PC and represent thousands of lines of rarely-audited FreeBSD kernel code.

### Next Steps
- Write SCTP attack probes (INIT/COOKIE/DATA chunk fuzzing)
- Write IPv6 NDP and fragment reassembly probes
- Run coordinated PC+PS5 IP options injection test

---

## 2026-10-16: Probes 47a + 46a re-run — Syscall 557 Return Patterns, CClosure Test Pending

### Key Findings
- **Syscall 557 return patterns** (47a + 46a re-run): tested struct inputs produced argument-dependent values. In 47a, positive versions followed `517 + ver`, while version zero returned 16901; 46a recorded 1038/1039 for two struct inputs. No kernel pointer or exploit was demonstrated; these samples do not establish full semantics or rule out vulnerabilities.
- **Syscall 620 is a no-op** — always returns 0, doesn't modify buffers.
- **47a Section C (CClosure write test) SKIPPED** — address parse bug, `__call` string has no `0x` prefix. This was a historical hypothesis; writability alone would not establish code execution.
- SCM_RIGHTS over socketpair: sendmsg/recvmsg succeed but cmsg data is zeros.
- LOCAL_PEERCRED: uid=1, gid=1, pid=0 (sandbox).

### Probe 47b: Historical CClosure Read-Only Conclusion (unresolved by audit)
- Fixed uint64 format bug and re-ran CClosure analysis
- The write loop covered `{16,24,32,40,48}` and omitted `+0`; the later audit found conflicting interpretations of the candidate offset.
- Some other offsets were reported writable, but their layout and effect on dispatch were not established.
- ROP-shaped metadata was writable; probe 45c later recorded tested syscall results persisting after selected mutations, so an execution role is not established
- The claim that all metatable functions have read-only `+0` is not supported by a write test.
- **Code execution through loader dispatch was not demonstrated; CClosure `+0` remains unresolved.** Retest 53d is prepared.

---

## 2026-10-16: Probes 46a-46d — Loader Internals + Socket Bypass

### Key Findings
- **Syscall 557 is version-dependent** (46a): `{ver=1,size=0x200}` returns 518 vs 16901. Kernel writes back to struct buffer. Probe crashed on format bug before full sweep.
- **Structural observation (46b):** syscall objects share a reported C-function __call address; the truncated log does not identify its implementation or relationship to the ROP-shaped metadata
- **socketpair works** (46d): `socketpair(AF_LOCAL, SOCK_STREAM)` returns fd pair via make_syscall. Not in resolve() namespace. New IPC primitive.
- Socket creation identical between make_syscall and resolve — no hidden bypass
- SCTP still dead (-1)

### Status
Network-side attacks (TCP from PC) are the top priority. Need to run `tcp_fuzz_server_v2.py` on PC and send 46b_tcp_enhanced_listener.lua.

---

## 2026-10-16: Probe 45c — Earlier ROP/fn_addr Execution Interpretation Challenged

### Tested syscall results persisted across selected metadata mutations
- Probe 45c recorded syscall results persisting despite changed/invalid `fn_addr` values and tested chain corruption; it did not identify the complete dispatch implementation
- The tested `fn_addr` values (ud2, null, unmapped) produced no crash while syscall results continued; this does not by itself identify the complete dispatch implementation
- Corrupting the tested chain entries did not change the recorded getpid result; do not generalize beyond the entries tested
- Sysctl returns valid data even when fn_addr points to NOP+ret
- fn_addr value `0x9FE5_11100130` is NOT in any loaded module's text range

### Retracted Findings
- **W^X "defeat" (44a) was not demonstrated** — the test's syscall result persisted after selected metadata changes; no controlled code-page execution effect was recorded
- **fn_addr/slot0 arbitrary-function-call primitive is not established** — writes persisted, but the tested calls did not change after selected mutations
- **The earlier ROP-chain exploitation model is unsupported for the tested calls** — the dispatch implementation remains unidentified

### Remaining Attack Surface
- Tested syscall numbers via make_syscall(); probe 46b's C-function observation does not establish the implementation
- Heap R/W via GPU mmap
- Network-side packet injection (TCP/IP from PC)
- Sony syscall investigation (557/620)
- Loader internals reverse engineering

---

## 2026-10-16: Probes 45a-45b — Shellcode Execution Doubts

- 45a: Shellcode appears to execute (no crash) but all buffer writes return sentinel values
- 45b: Return value is ALWAYS pid regardless of eax. `xor eax,eax; ret` returns pid=128 (impossible if executing). All memory writes from shellcode fail. Raised first suspicion that shellcode isn't running.

---

## 2026-10-16: Probes 44a-44d — W^X DEFEATED (RETRACTED — see 45c above)

### ★★★ BREAKTHROUGH: Native Code Execution (44a)
- `sceKernelMtypeprotect(585)` with `PROT_READ|PROT_WRITE|PROT_EXEC` grants execute permission on mmap'd pages
- NOP sled, `mov eax` shellcode, and direct `syscall` instruction all execute from the page
- Combined with fn_addr redirect (43i), we have arbitrary native x86-64 code execution
- **W^X was the hardest wall in PS5 exploitation. It is now broken.**

### Other Results
- Syscall 557 (44b): returns 0x4205 as process type/sandbox query, no kernel pointers
- Sockopt heap corruption (44c): not exploitable, kernel clamps copy length
- Creative KASLR (44d): NET_RT_IFLISTL returns 6.5KB (no kptrs), kern.usrstack readable, all other paths blocked

### Status
**This historical status is superseded by probe 45c and the evidence audit.** Native code execution was not established, so KASLR defeat is not the sole remaining blocker. The 43o AF_ROUTE request and 43a/43b KLD calls remain inconclusive; see the correction at the top of this changelog and the prepared 53a–53d retests.

---

## 2026-10-16: Phase 10 Full Probe Sweep (43a-43p)

> **Evidence correction (2026-10-17):** The saved 43p output ends immediately before the first AIO call result. The historical statement below that it was an instant kill is unsupported by the output and is withdrawn. See `docs/SECONDARY_EXPLOIT_AUDIT_13.60.md`.

Sent all 16 Phase 10 probes. Several direct KASLR paths remain unresolved because the corresponding requests failed or their captures ended before results.

### Critical Finding
- **Historical interpretation, not established by current evidence:** fn_addr + slot0 writes persisted (43i), but that did not prove a function-call primitive. Probe 45c showed tested syscall results persisting after specific metadata mutations; it did not identify the complete dispatch implementation.

### Promising Leads
- **Syscall 557 returns 16901** (43g) — live Sony-custom syscall, unknown function. Needs targeted investigation.
- **mtypeprotect returns 1 for RWX** (43h, 43k) — the return did not establish executable memory or code execution; probe 45c undermines the proposed fn_addr dependency for the tested calls.
- **Syscall 620 returns 0** (43k) — another live Sony syscall.

### Paths Previously Labeled Dead Ends (Evidence-Audit Status Below)
- AF_ROUTE KASLR (43o): RTM_GET write failed; read returned 108 bytes with zero detected pointers; response attribution, leak and patch status unresolved
- AIO via make_syscall (43p): saved run ends before the first AIO call result; no conclusion can be drawn
- kldstat (43a): header-only 145-byte capture — outcome unknown
- kldsym (43b): header-only 116-byte capture — outcome unknown
- kinfo_proc full dump (43d): only sentinel values, no kernel pointers
- kern.proc.filedesc (43d): blocked
- kern.proc.vmmap (43d): blocked even with 256K buffers
- sysctl operations (43f): securelevel-labeled write returned -1; coredump/debug/maxproc reads failed and their conditional writes were not reached; somaxconn was read, not write-tested
- sysarch GET_GSBASE (43c): returns 0
- ioctl via make_syscall (43e): returns -1
- dup/dup2 (43e): returns -1
- thr_new (43e): crashes process
- kern.msgbuf (43j): returns 8 bytes only (filtered)
- mincore KASLR oracle (43l): kernel VA probes all -1
- sockopt overflow (43m): kernel clamps copy, not exploitable
- /dev/hid ioctl (43n): Sony error 0x80740004

### Other Findings
- fstat works via make_syscall (43e) — no kernel pointers but confirms stat struct access
- kinfo_proc process name is "boot.bin" (43d)
- kern.boottime readable: 0x6AD29A84 (43j)
- /dev/null, /dev/zero, /dev/urandom all open (43n)
- 32GB address (0x800000000) mapped in process VA space (43l)

### Status
**Blocker: KASLR defeat.** We have the function call primitive (43i) but no kernel address to call. All direct info leak paths are dead. Remaining vectors: Sony syscall 557/620 investigation, mtypeprotect exec test, network-side attacks (TCP/IP options from real network).
# 2026-10-18: CVE-2026-58083 scope check

Added a source-backed assessment of FreeBSD CVE-2026-58083 and the PS5 14.10 evidence. Existing probes demonstrate kqueue timer-filter activity, but do not exercise the CVE's copy-on-fork path; the saved process-creation probe records `fork`, `rfork`, and `thr_new` returning -1. No PS5 vulnerability or fix status is established. Corrected stale kqueue summaries that said `kevent` was always blocked. See [CVE-2026-58083-PS5-14.10.md](CVE-2026-58083-PS5-14.10.md).

