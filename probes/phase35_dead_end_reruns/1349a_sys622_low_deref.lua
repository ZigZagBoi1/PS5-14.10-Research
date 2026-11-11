-- CRASH_CLASS: HIGH
-- PROBE 1349a: what the first low 622 command dereferences
--
-- Context: cmd 0x01 kills the process with a null arg3 (1347a) and with arg3
-- pointing at a zeroed 0x40-byte page (1348a). cmd 0x00 kills too (1346a).
-- Every command in 0x100..0x133 answers "device not found" instead, so the low
-- table is not the same handler set. A kill on a *zeroed* struct is the
-- signature of a pointer taken from the struct - or of a lookup that returns
-- NULL and is used anyway. The two differ: if the handler follows a pointer we
-- supplied, filling the page with a valid user address keeps it alive; if the
-- pointer comes from a failed lookup, nothing we put in the page matters.
--
-- This probe calls cmd 0x01 with the same page under three fills, each shape
-- one relaunch apart if it dies:
--   [A] every qword of the page = the page's own address (a valid pointer to
--       more of the same), size 0x40
--   [B] every qword = 0 then 0xFF..FF, size 0x40 (a null and a sentinel fill)
--   [C] the self-pointer fill again with size 0, so no copyin happens
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1346a_sys622_low_commands_20261109_104306.txt
--   results/phase35_dead_end_reruns/1347a_sys622_low_resume_20261109_104444.txt
--   results/phase35_dead_end_reruns/1348a_sys622_low_page_20261109_104528.txt
--   results/kernel_handlers/asm/sys_622_deep.asm:79-90

print("=== PROBE 1349a: LOW 622 DEREF SHAPE ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
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

local function fillq(q)
    for i = 0, 0xFF do safe_wq(page + i * 8, q) end
end
local function fillbuf()
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
end
local function call(cmd, sub, addr, size)
    fillbuf()
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(sub), uint64(buf), addr, uint64(size), uint64(0))
    end)
    return ok and sgn(ret) or "PCALL-FAIL"
end

local self = uint64(0)
if page_valid then self = uint64(string.format("0x%X%08X", ph % 0x100000000, pl % 0x100000000)) end

print("")
print("[A] cmd 0x01, page full of its own address, size 0x40")
if page_valid then
    fillq(self)
    print(string.format("  ret=%s buf=%s %s", tostring(call(0x01, 0, page, 0x40)), sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
else
    print("  page not mapped")
end

print("")
print("[B] cmd 0x01, page = 0xFFFFFFFFFFFFFFFF, size 0x40")
if page_valid then
    fillq(uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)))
    print(string.format("  ret=%s buf=%s %s", tostring(call(0x01, 0, page, 0x40)), sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
else
    print("  page not mapped")
end

print("")
print("[C] cmd 0x01, page full of its own address, size 0")
if page_valid then
    fillq(self)
    print(string.format("  ret=%s buf=%s %s", tostring(call(0x01, 0, page, 0)), sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
else
    print("  page not mapped")
end

print("")
print("=== PROBE 1349a COMPLETE ===")
