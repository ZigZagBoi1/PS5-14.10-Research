-- CRASH_CLASS: LOW
-- PROBE 240a: 660 against the module handles that 592 hands out
--
-- Context: 660 is the handler that copies out a module record
-- (struct h660_info: size, 256-byte name, four segments, segment count; the
-- caller must set the size gate to 0x160 first). Every handle tried so far -
-- the two values 659 returns, 0, and pointer-shaped values - returned -1 with
-- the gate word untouched, so nothing was copied out.
--
-- 659 is described as "dynamic module handle enumeration" and 592 is
-- dynlib_get_list: the ordinary way a process learns its module handles. This
-- probe asks 592 for the list and feeds each handle to 660, printing the name
-- and segment count when a call succeeds.

print("=== PROBE 240a: 660 WITH 592 MODULE HANDLES ===")
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
    if type(val) == "number" then val = uint64(val) end
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

local sc592 = make_syscall(592)
local sc660 = make_syscall(660)

-- ============================================================
-- [A] 592 dynlib_get_list
-- ============================================================
print("")
print("[A] 592 { handles_out, capacity, count_out }")

local CAP = 256
local list = memory.alloc(CAP * 4 + 0x100)
local count = memory.alloc(0x10)
for i = 0, CAP - 1 do safe_wd(list + i * 4, 0) end
safe_wq(count, 0)

local okA, retA = pcall(function() return sc592(uint64(list), uint64(CAP), uint64(count)) end)
print(string.format("  ret=%s count=%s", okA and sgn(retA) or "PCALL-FAIL", sgn(safe_rd(count))))

local handles = {}
if okA then
    for i = 0, CAP - 1 do
        local h = safe_rd(list + i * 4)
        if h and h ~= 0 then handles[#handles + 1] = h end
    end
end
print(string.format("  handles: %d", #handles))

-- ============================================================
-- [B] 660 for each handle
-- ============================================================
print("")
print("[B] 660 { module_handle, pad, info_inout } gate 0x160")

local info = memory.alloc(0x200)
local hits = 0
for index, handle in ipairs(handles) do
    for i = 0, 0x3F do safe_wq(info + i * 8, uint64(0)) end
    safe_wq(info, uint64(0x160))
    local ok, ret = pcall(function() return sc660(uint64(handle), uint64(0), uint64(info)) end)
    if not ok then
        print(string.format("  handle=0x%X -> PCALL-FAIL", handle))
        break
    end
    local r = sgn(ret)
    if r ~= "-1" then
        hits = hits + 1
        local name = ""
        for i = 0, 63 do
            local ch = safe_rd(info + 8 + i * 4)
            if ch == nil or ch == 0 then break end
            name = name .. string.char(ch % 256)
        end
        local segcount = safe_rd(info + 0x120)
        print(string.format("  handle=0x%X ret=%s size=%s segcount=%s name=%q",
            handle, r, sgn(safe_rd(info)), sgn(segcount), name))
        for s = 0, 3 do
            local base = info + 0x108 + s * 0x10
            local addr = safe_rd(base)
            local size_s = safe_rd(base + 8)
            local prot = safe_rd(base + 12)
            if addr and addr ~= 0 then
                print(string.format("    seg[%d] addr=0x%X size=0x%X prot=0x%X", s, addr, size_s or 0, prot or 0))
            end
        end
    end
end
print(string.format("  handles that returned a record: %d of %d", hits, #handles))

print("")
print("=== PROBE 240a COMPLETE ===")
