-- CRASH_CLASS: LOW
-- PROBE 143q: KASLR defeat — sysctl pcblist + IPv6 pktopts + SCM_RIGHTS
--
-- Context: 143p confirmed IPv6 2292 options work (19,20,24).
-- This probe tests ALL remaining conventional KASLR techniques.
--
-- RESULTS (2026-10-22):
-- [A] pipe works (read_fd+1 = write_fd), socketpair via make_syscall(135) works
-- [B] sysctl name2oid WORKS — kern.osreldate=900000, kern.version confirmed
-- [C] net.inet.tcp.pcblist — name2oid FAILED (Sony removed pcblist sysctl)
-- [D] net.inet.udp.pcblist — name2oid FAILED
-- [E] IPv6 2292PKTOPTIONS (opt 25) getsockopt → 0 bytes (empty, blocked)
-- [F] SCM_RIGHTS fd passing — sendmsg OK, recvmsg ancillary STRIPPED (controllen=0)
-- [G] 40 of 57 sysctl names found, NONE contain kernel pointers
-- [H] /dev listing: 78 entries including sbl_srv, a53mm, dbggc, encdec, duid
-- [I] /dev/fd: only 3 fds visible (0,1,2) — heavily filtered
-- [J] hw.model="100-000000189" (AMD PS5 APU), kern.version="r230171/releases/14.10"
--
-- VERDICT: ALL conventional KASLR info leak paths are DEAD on 14.10.
-- Sony stripped pcblist, sanitized AF_ROUTE, blocked 2292PKTOPTIONS readback,
-- stripped SCM_RIGHTS ancillary data, and removed most sysctl names.
-- Next: thread race conditions for UAF-based kernel pointer leak.

print("=== PROBE 143q: KASLR SUMMARY ===")
print("See results file for full output from split runs")
print("")

-- This probe was split into multiple micro-probes for stability.
-- Combined results:

print("[RESULT] pipe: works (read_fd, read_fd+1)")
print("[RESULT] socketpair: works via make_syscall(135)")
print("[RESULT] pipe2(542): ret=-1 (blocked)")
print("[RESULT] sysctl name2oid: works via MIB {0,3}")
print("[RESULT] kern.osreldate: 900000")
print("[RESULT] kern.version: r230171/releases/14.10 Sep 28 2026 02:18:33")
print("[RESULT] kern.osrelease: 0.0-prototype")
print("[RESULT] hw.model: 100-000000189 (AMD PS5 APU)")
print("[RESULT] hw.ncpu: 16")
print("[RESULT] hw.pagesize: 16384 (16KB)")
print("[RESULT] hw.availpages: 0x22270 (139888 = 2.14GB)")
print("[RESULT] machdep.tsc_freq: 1596030924 Hz")
print("[RESULT] net.inet.tcp.pcblist: name2oid FAILED (removed)")
print("[RESULT] net.inet.udp.pcblist: name2oid FAILED (removed)")
print("[RESULT] net.inet.raw.pcblist: name2oid FAILED (removed)")
print("[RESULT] IPv6 2292PKTOPTIONS(25): getsockopt returns 0 bytes (blocked)")
print("[RESULT] SCM_RIGHTS: ancillary data stripped on recv (controllen=0)")
print("[RESULT] /dev entries: 78 total")
print("[RESULT] /dev/fd: filtered to 3 fds (0,1,2)")
print("[RESULT] sysctl names found: 40 of 57 tested")
print("[RESULT] ZERO kernel pointers in ANY sysctl output")
print("")
print("[VERDICT] ALL conventional KASLR info leak paths DEAD on 14.10")
print("=== PROBE 143q COMPLETE ===")
