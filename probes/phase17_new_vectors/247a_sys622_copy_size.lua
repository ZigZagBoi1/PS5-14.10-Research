-- CRASH_CLASS: HIGH
-- PROBE 247a: the 622 cmd 0x400 copy size, measured by sliding arg3 to the
--             end of a mapped page
--
-- Context: 245a showed the crash is not driven by arg4 (arg3 = page with size 1
-- still dies), so the handler copies a fixed number of bytes from arg3. 246a
-- tried to measure that with arg3 = end - 0x18 and returned -1, but the address
-- was built by adding to the low dword and lost its high half, so the call
-- pointed at an unmapped address and the -1 was the copyin failing on garbage.
--
-- The address here is rebuilt as a full uint64 from the hi/lo halves, which is
-- the documented idiom, and the room is increased in steps inside one run:
--
--   room < copy size  -> copyin hits the end of the mapping, returns EFAULT,
--                        the handler returns -1 and the process lives
--   room >= copy size -> the copy succeeds and the process dies
--
-- So the run returns a column of -1 rows and stops at the first room that fits.
-- The last row printed is one step below the copy size, and the missing row is
-- the size itself.

print("=== PROBE 247a: 622 CMD 0x400 COPY SIZE, SLIDING ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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
local sc547 = make_syscall(547)
local buf = memory.alloc(0x200)
local region = memory.alloc(0x40)

local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0
print(string.format("page=%s valid=%s", sgn(page), tostring(page_valid)))

-- ============================================================
-- [A] region record
-- ============================================================
print("")
print("[A] 547 region record")
local room = 0
if page_valid then
    for i = 0, 7 do pcall(function() memory.write_qword(region + i * 8, uint64(0)) end) end
    local ok, ret = pcall(function() return sc547(page, uint64(region)) end)
    local start_v = safe_rq(region)
    local end_v = safe_rq(region + 8)
    print(string.format("  ret=%s start=%s end=%s", ok and sgn(ret) or "PCALL-FAIL", sgn(start_v), sgn(end_v)))
    local sh, sl = get_hi_lo(start_v)
    local eh, el = get_hi_lo(end_v)
    if eh == ph and el > pl then room = el - pl end
    print(string.format("  room from the page start = 0x%X", room))
end

-- ============================================================
-- [B] ascending room; the run dies at the first room that fits the copy
-- ============================================================
print("")
print("[B] measurement")
local steps = { 0x18, 0x19, 0x20, 0x28, 0x30, 0x40, 0x60, 0x80, 0xC0, 0x100, 0x150, 0x200, 0x400 }
if page_valid and room > 0 then
    for _, k in ipairs(steps) do
        if k > room then break end
        local low = pl + room - k
        local addr = uint64(string.format("0x%X%08X", ph, low))
        for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
        local ok, ret = pcall(function()
            return sc622(uint64(0x400), uint64(0), uint64(buf), addr, uint64(0x40), uint64(0))
        end)
        print(string.format("  room=0x%-4X arg3=%s ret=%-22s buf[0]=%-22s buf[4]=%s",
            k, sgn(addr), ok and sgn(ret) or "PCALL-FAIL", sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
    end
else
    print("  skipped: no usable room")
end

print("")
print("=== PROBE 247a COMPLETE ===")
