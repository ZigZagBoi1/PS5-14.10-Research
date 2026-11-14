-- CRASH_CLASS: HIGH
-- PROBE 1348a: 622 low commands, one connection per segment, arg3 = a mapped page
--
-- Context: 1347a measured the two direct-call commands - 0x372 answers 0 with
-- 0x8002004E in the caller's buffer for every sub 0..31 (the triple auth gate,
-- so it is closed) and 0x520 returns -1 for every sub (its callee 0x29a570
-- refuses). Its phase B then died inside cmd 0x01..0x0F before reaching the
-- 0x10 progress line, so at least one of the first fifteen low commands is
-- lethal with a null arg3.
--
-- 1346a had already shown cmd 0x00 kills with a null arg3. The 0x400 group's
-- pattern was the opposite - a null arg3 returns -1 and a mapped arg3 kills -
-- so this probe repeats the low sweep with arg3 pointing at a zero page of
-- 0x40 bytes, which is the shape that lets those handlers reach their body.
--
-- START_C and USE_PAGE are the two knobs. Every command prints its own short
-- line, so a death names the command after the last printed one.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1346a_sys622_low_commands_20261109_104306.txt
--   results/phase35_dead_end_reruns/1347a_sys622_low_resume_20261109_104444.txt
--   probes/phase17_new_vectors/305a_sys622_unauth.lua
--   results/kernel_handlers/asm/sys_622_deep.asm:79-90
--
local START_C = 0x01
local USE_PAGE = true

print("=== PROBE 1348a: 622 LOW, PAGE ARG3 ===")
print(string.format("start=0x%02X page=%s", START_C, tostring(USE_PAGE)))
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

-- zero the page so a handler that reads it sees a null-filled struct
if page_valid then
    for i = 0, 7 do safe_wd(page + i * 4, 0) end
end

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

local addr = uint64(0)
if USE_PAGE and page_valid then addr = page end

print("")
print(string.format("[B] cmd 0x%02X..0xFF, size 0x40", START_C))
for cmd = START_C, 0xFF do
    fill()
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), addr, uint64(0x40), uint64(0))
    end)
    local r = ok and sgn(ret) or "PCALL-FAIL"
    local n = changed()
    if n > 0 then
        print(string.format("  0x%03X %s ch=%d %s %s %s", cmd, tostring(r), n, sgn(safe_rd(buf)), sgn(safe_rd(buf + 4)), sgn(safe_rd(buf + 8))))
    else
        print(string.format("  0x%03X %s ch=0", cmd, tostring(r)))
    end
end
print("[B] done")

print("")
print("=== PROBE 1348a COMPLETE ===")
