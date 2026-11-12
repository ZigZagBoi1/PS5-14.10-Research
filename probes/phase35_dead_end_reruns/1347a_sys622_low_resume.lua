-- CRASH_CLASS: HIGH
-- PROBE 1347a: the 622 commands below 0x100 (resumable), plus 0x372/0x520 sub sweep
--
-- Context: 1346a called cmd 0x00 with arg3 null and size 0x40 and the process
-- died before printing a line (results/phase35_dead_end_reruns/
-- 1346a_sys622_low_commands_20261109_104306.txt holds the header and the [A]
-- banner only), so table slot 0 of the low dispatch is live and lethal. The
-- dispatch is read out of the 13.60 body (results/kernel_handlers/asm/
-- sys_622_deep.asm:79-90): commands <= 0x270 that are not in 0x100..0x133 or
-- 0x201..0x271 index a table at 0x178057c by the raw command, so 0x01..0xFF
-- reaches real entries. 305a measured only the fifteen unauthenticated
-- commands inside 0x100..0x133 and every one of them answered 0 with
-- 0xFFFFFFFF in the caller's buffer (device not found).
--
-- 0x372 and 0x520 are separate: 7dd081 calls 0x29a570 with (thread, arg1,
-- &status) and 7dd077 calls 0xc02050 the same way, so neither reads arg2..arg 4
-- and neither can fault on the buffer. Only arg1 = 0 was ever tried (241a).
--
-- START_C resumes the sweep. Move it past a command that kills and re-send.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1346a_sys622_low_commands_20261109_104306.txt
--   probes/phase17_new_vectors/241a_sys622_layout.lua (one cmd per table)
--   probes/phase17_new_vectors/305a_sys622_unauth.lua (the 15 unauthenticated cmds)
--   results/kernel_handlers/analysis/sys_622_deep.md (dispatch and sub-handlers)
--   docs/ATTACK_SURFACE.md:98 (0x400 group kills after a successful copyin)
--
-- Every call prints its own line before the next one, so a death names it.

local START_C = 0x01

print("=== PROBE 1347a: 622 LOW COMMANDS ===")
print(string.format("start=0x%02X", START_C))
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(val)
    if val == nil then return "nil" end
    local text = tostring(val)
    if text == "-1" then return "-1" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return text
end

local sc622 = make_syscall(622)
local sc477 = make_syscall(477)
local buf = memory.alloc(0x200)

local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0 and to_num(page) ~= 0
print(string.format("pid=%d page=%s valid=%s", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), sgn(page), tostring(page_valid)))

local function fill()
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
end
local function changed()
    local n = 0
    for i = 0, 0x1F do
        if safe_rd(buf + i * 4) ~= 0xDEADBEEF then n = n + 1 end
    end
    return n
end
local function call622(cmd, sub, addr, size)
    fill()
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(sub), uint64(buf), addr, uint64(size), uint64(0))
    end)
    return (ok and sgn(ret) or "PCALL-FAIL"), changed(),
        sgn(safe_rd(buf)), sgn(safe_rd(buf + 4)), sgn(safe_rd(buf + 8))
end

-- ============================================================
-- [A] 0x372 and 0x520, arg1 = 0..31, no buffer needed
-- ============================================================
print("")
print("[A] 0x372 / 0x520, sub 0..31, arg3 null")
for _, cmd in ipairs({ 0x372, 0x520 }) do
    for sub = 0, 31 do
        local ret, nch, d0, d1 = call622(cmd, sub, uint64(0), 0x40)
        print(string.format("  cmd=0x%03X sub=%-2d ret=%-20s changed=%d buf=%s %s", cmd, sub, ret, nch, d0, d1))
    end
end

-- ============================================================
-- [B] the low sweep, arg3 null; a copyin-dependent handler returns -1
-- ============================================================
print("")
print(string.format("[B] cmd 0x%02X..0xFF, arg3 null, size 0x40", START_C))
local survivors = {}
local silent = 0
for cmd = START_C, 0xFF do
    local ret, nch, d0, d1, d2 = call622(cmd, 0, uint64(0), 0x40)
    if ret ~= "-1" then
        print(string.format("  cmd=0x%03X ret=%-20s changed=%d buf=%s %s %s", cmd, ret, nch, d0, d1, d2))
        survivors[#survivors + 1] = cmd
    elseif cmd % 16 == 0 then
        print(string.format("  cmd=0x%03X -1", cmd))
    end
    silent = silent + 1
end
print(string.format("[B] done: %d commands, %d answered, %d returned -1", 0x100 - START_C, #survivors, silent))

-- ============================================================
-- [C] the phase-B survivors with a mapped arg3 page
-- ============================================================
print("")
print("[C] phase-B survivors, arg3 = mapped page")
if page_valid then
    for _, cmd in ipairs(survivors) do
        local ret, nch, d0, d1, d2 = call622(cmd, 0, page, 0x40)
        print(string.format("  cmd=0x%03X ret=%-20s changed=%d buf=%s %s %s", cmd, ret, nch, d0, d1, d2))
    end
else
    print("  page not mapped, skipped")
end

print("")
print("=== PROBE 1347a COMPLETE ===")
