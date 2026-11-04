-- CRASH_CLASS: MODERATE
-- PROBE 888a: sys 637 -- cross-target gate and limit enforcement
--
-- Context: 887a (results/phase17_new_vectors/887a_sys637_self_gate_*.txt) showed
-- that 637 takes (pid, limit) and returns 0 for BOTH pid 0 and the caller's own
-- pid, while 637(pid, 0) returns -1. The old -1 in ATTACK_SURFACE.md came from
-- calling it as (buffer, size), which is the wrong shape entirely.
--
-- What is still unknown:
--   * does an accepted call change anything (is the limit enforced)?
--   * is the target pid gated -- i.e. does 637(other_pid, ...) return 0 too?
--     A 0 for a foreign pid is a capability bypass; -1 is a correct gate.
--
-- Order: foreign targets first (that is the interesting claim), because a
-- lethal call wipes out everything after it. Enforcement last, with the limit
-- always restored.

print("=== PROBE 888a: SYS 637 CROSS-TARGET ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL", tag))
        return
    end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X (lo=%u)", tag, h, l, l))
end

local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] self pid = %u", pid))

local sc637 = make_syscall(637)
local BIG = 0x40000000

print("[B] baseline self:")
local okb, rvb = pcall(function() return sc637(uint64(pid), uint64(BIG)) end)
show("637 self", okb, rvb)

-- D. foreign targets. Print the tag before each call so a kill still leaves
-- the target that caused it on the record.
local targets = { 1, 2, 3, 10, pid + 1, pid - 1, 0x100, 0xFFFFFFFF }
for _, t in ipairs(targets) do
    if t ~= pid and t >= 0 then
        print(string.format("[D] 637(%d, 0x40000000):", t))
        local ok, rv = pcall(function() return sc637(uint64(t), uint64(BIG)) end)
        show(string.format("target %d", t), ok, rv)
    end
end

-- C. enforcement: a small limit should make a large mapping fail if the value
-- is real. 64 MiB is below the 256 MiB request but far above typical use.
print("[C1] set small limit (64 MiB):")
local okc1, rvc1 = pcall(function() return sc637(uint64(pid), uint64(0x4000000)) end)
show("637 small", okc1, rvc1)

local sc477 = make_syscall(477)
print("[C2] mmap 256 MiB under the small limit:")
local okc2, rvc2 = pcall(function()
    return sc477(uint64(0), uint64(0x10000000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
show("mmap 256M", okc2, rvc2)

print("[C3] restore limit (1 GiB):")
local okc3, rvc3 = pcall(function() return sc637(uint64(pid), uint64(BIG)) end)
show("637 restore", okc3, rvc3)

print("[C4] mmap 256 MiB after restore:")
local okc4, rvc4 = pcall(function()
    return sc477(uint64(0), uint64(0x10000000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
show("mmap 256M again", okc4, rvc4)

print("")
print("=== PROBE 888a DONE ===")
