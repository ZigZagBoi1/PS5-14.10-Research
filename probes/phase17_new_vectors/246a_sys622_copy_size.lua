-- CRASH_CLASS: HIGH
-- PROBE 246a: how many bytes does 622 cmd 0x400 take from arg3
--
-- Context: 245a showed the crash is not driven by arg4 - arg3 pointing at a
-- mapped page with size 1 still kills the process, while arg3 NULL returns -1
-- for every size tried. So the handler copies a fixed number of bytes from
-- arg3, and the 13.60 analysis names the candidates (0x18, 0x19, 0x30, 0x150).
--
-- 547 reports the mapped region for an address, so the page boundary is a
-- measuring stick: put arg3 exactly k bytes before the end of the mapping. A
-- copyin of N bytes then succeeds when N <= k and fails with EFAULT when N > k.
-- An EFAULT is a return, not a death, so the pair (dies, returns) separates
-- "the copy fit" from "the copy crossed the boundary".
--
-- One boundary position per run: 0x18 bytes of room here. If the call returns
-- -1, the fixed copy is larger than 0x18 and the next run moves closer to the
-- end. If it dies, the copy is 0x18 bytes or less and the crash is something
-- after the copy rather than an overrun of it.

print("=== PROBE 246a: 622 CMD 0x400 COPY SIZE ===")
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
-- [A] the region record for the page
-- ============================================================
print("")
print("[A] 547 region record")
local start_v, end_v = nil, nil
if page_valid then
    for i = 0, 7 do pcall(function() memory.write_qword(region + i * 8, uint64(0)) end) end
    local ok, ret = pcall(function() return sc547(page, uint64(region)) end)
    start_v = safe_rq(region)
    end_v = safe_rq(region + 8)
    print(string.format("  ret=%s start=%s end=%s", ok and sgn(ret) or "PCALL-FAIL", sgn(start_v), sgn(end_v)))
end

-- how many bytes of mapping remain from the page start
local room = 0
if start_v and end_v then
    local sh, sl = get_hi_lo(start_v)
    local eh, el = get_hi_lo(end_v)
    if eh == ph and el > pl then room = el - pl end
    print(string.format("  region covers the page: %s, room = 0x%X", tostring(eh == ph and el > pl), room))
end

-- ============================================================
-- [B] the measurement: arg3 with exactly 0x18 bytes of room
-- ============================================================
print("")
print("[B] measurement: arg3 = end - 0x18")
if room > 0x18 then
    local addr = uint64(pl + room - 0x18)
    print(string.format("  arg3 = %s", sgn(addr)))
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
    local ok, ret = pcall(function()
        return sc622(uint64(0x400), uint64(0), uint64(buf), addr, uint64(0x40), uint64(0))
    end)
    print(string.format("  ret=%-22s buf[0]=%-22s buf[4]=%s",
        ok and sgn(ret) or "PCALL-FAIL", sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))
else
    print("  skipped: no usable room")
end

print("")
print("=== PROBE 246a COMPLETE ===")
