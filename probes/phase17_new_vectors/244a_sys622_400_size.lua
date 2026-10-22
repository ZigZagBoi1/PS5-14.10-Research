-- CRASH_CLASS: HIGH
-- PROBE 244a: does the 622 cmd 0x400 kill depend on the size argument
--
-- Context: with the six-slot layout the 0x400 group returns -1 for a null arg3
-- and kills the process for a mapped readable page as arg3 (243a). The 13.60
-- analysis says the dispatch targets copyin from arg3 into a 64-byte stack
-- buffer using the size in arg4 (capped at 0x40), but that several
-- sub-handlers use hardcoded sizes (0x18, 0x19, 0x30, 0x150) instead.
--
-- One measurement per run, because the process does not survive:
--   arg4 = 0 with a mapped arg3.
-- If the process dies anyway, the copy size is not arg4 and a fixed-size copy
-- larger than its destination is the explanation. If the call returns, then
-- arg4 is the size and the earlier kill at 0x40 means the destination is
-- smaller than 0x40.

print("=== PROBE 244a: 622 CMD 0x400 SIZE 0 ===")
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

-- control: null arg3 is known to return -1 without dying
for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
local okC, retC = pcall(function() return sc622(uint64(0x400), uint64(0), uint64(buf), uint64(0), uint64(0), uint64(0)) end)
print(string.format("control arg3=null size=0   ret=%-22s buf[0]=%s", okC and sgn(retC) or "PCALL-FAIL", sgn(safe_rd(buf))))

-- the measurement
print("")
print("measurement: cmd 0x400, arg3 = mapped page, size 0")
for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
local okM, retM = pcall(function() return sc622(uint64(0x400), uint64(0), uint64(buf), page, uint64(0), uint64(0)) end)
print(string.format("  ret=%-22s buf[0]=%-22s buf[4]=%s",
    okM and sgn(retM) or "PCALL-FAIL", sgn(safe_rd(buf)), sgn(safe_rd(buf + 4))))

print("")
print("=== PROBE 244a COMPLETE ===")
