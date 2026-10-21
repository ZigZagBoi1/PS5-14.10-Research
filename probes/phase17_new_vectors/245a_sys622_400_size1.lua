-- CRASH_CLASS: HIGH
-- PROBE 245a: is the 622 cmd 0x400 crash driven by arg4 at all
--
-- Context: three measured shapes -
--   arg3 NULL, size 0x40 -> -1, alive (copyin from NULL fails, handler returns)
--   arg3 page, size 0x40 -> process dies
--   arg3 NULL, size 0    -> process dies
-- The NULL/size-0x40 case is the only one that returns, and it is the only one
-- where the copy is refused. So the crash happens on every path where the copy
-- succeeds, plus on size 0 where the copy is a no-op.
--
-- This probe separates "the copy size comes from arg4" from "the copy size is
-- hardcoded": if a one-byte size with a valid page still dies, arg4 is not the
-- copy size and the handler is copying a fixed number of bytes out of arg3.
-- The control runs first so the capture proves the process was healthy, and the
-- measurement runs last because it may not come back.

print("=== PROBE 245a: 622 CMD 0x400, SIZE 1 ===")
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
        local low = l % 0x100000000
        if low == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, low)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return text
end

print(string.format("PID: %d", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local sc622 = make_syscall(622)
local sc477 = make_syscall(477)
local buf = memory.alloc(0x200)

local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0
print(string.format("page=%s valid=%s", sgn(page), tostring(page_valid)))

local function call622(label, cmd, sub, addr, size)
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(sub), uint64(buf), addr, uint64(size), uint64(0))
    end)
    print(string.format("  %-28s ret=%-22s buf[0]=%-22s buf[4]=%s",
        label, ok and sgn(ret) or "PCALL-FAIL", sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
end

-- ============================================================
-- [A] controls: the shapes that returned before
-- ============================================================
print("")
print("[A] controls")
call622("NULL size 0x40", 0x400, 0, uint64(0), 0x40)
call622("NULL size 1", 0x400, 0, uint64(0), 1)
call622("NULL size 0x18", 0x400, 0, uint64(0), 0x18)

-- ============================================================
-- [B] the measurement: a one-byte size with a valid page
-- ============================================================
print("")
print("[B] measurement")
if page_valid then
    call622("page size 1", 0x400, 0, page, 1)
else
    print("  skipped: no page")
end

print("")
print("=== PROBE 245a COMPLETE ===")
