-- CRASH_CLASS: LOW
-- PROBE 143f: sys 670 on FRESH process — first call behavior
-- Isolation sweep got ret=0 on fresh process but probe 143e got -1.
-- Hypothesis: 670 is a one-shot call that returns 0 only once.
-- This probe does MINIMAL setup before calling 670.

print("=== PROBE 143f: SYS 670 FRESH ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function wd(addr, val) memory.write_dword(addr, val) end
local function wq(addr, val) memory.write_qword(addr, val) end

--------------------------------------------------------------------
-- [A] IMMEDIATE first call to 670 — no other syscalls first
--------------------------------------------------------------------
print("--- [A] immediate 670 ---")

local sc670 = make_syscall(670)
local ok1, rv1 = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok1 then
    local rh, rl = get_hi_lo(rv1)
    print("[A] FIRST call ret=" .. rl .. " raw=" .. hex(rv1))
else
    print("[A] FIRST call FAIL: " .. tostring(rv1))
end

-- Second call — does it change?
local ok2, rv2 = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok2 then
    local rh, rl = get_hi_lo(rv2)
    print("[A] SECOND call ret=" .. rl .. " raw=" .. hex(rv2))
else
    print("[A] SECOND call FAIL: " .. tostring(rv2))
end

-- Third call
local ok3, rv3 = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok3 then
    local rh, rl = get_hi_lo(rv3)
    print("[A] THIRD call ret=" .. rl)
end

--------------------------------------------------------------------
-- [B] Call 670 with buffer — first call in fresh connection
-- (The loader spawns fresh connection per TCP, but same process)
--------------------------------------------------------------------
print("")
print("--- [B] 670 with output buffer ---")

local buf = memory.alloc(0x200)
for off = 0, 0x1FF, 4 do wd(buf + off, 0xDDDDDDDD) end

local ok4, rv4 = pcall(function()
    return sc670(uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok4 then
    local rh, rl = get_hi_lo(rv4)
    print("[B] ret=" .. rl)
    local changed = false
    for off = 0, 0xFC, 4 do
        local v = safe_rd(buf + off) or 0
        if v ~= 0xDDDDDDDD then
            changed = true
            print("[B] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
    if not changed then print("[B] buffer unchanged") end
end

--------------------------------------------------------------------
-- [C] pid check
--------------------------------------------------------------------
print("")
print("--- [C] pid ---")
local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("[C] pid=" .. pid)

--------------------------------------------------------------------
-- [D] Try 670 with arg1 = pid (maybe it's a process query?)
--------------------------------------------------------------------
print("")
print("--- [D] 670(pid) ---")

local ok5, rv5 = pcall(function()
    return sc670(uint64(pid), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok5 then
    local rh, rl = get_hi_lo(rv5)
    print("[D] 670(pid=" .. pid .. ") ret=" .. rl)
end

-- Try with buf as arg2
for off = 0, 0x1FF, 4 do wd(buf + off, 0) end
local ok6, rv6 = pcall(function()
    return sc670(uint64(pid), uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0))
end)
if ok6 then
    local rh, rl = get_hi_lo(rv6)
    print("[D] 670(pid,buf,sz) ret=" .. rl)
    for off = 0, 0x7C, 4 do
        local v = safe_rd(buf + off) or 0
        if v ~= 0 then
            print("[D] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
end

--------------------------------------------------------------------
-- [E] Quick test of other live handlers (663,664,666,667,669)
-- Try with pid as arg1
--------------------------------------------------------------------
print("")
print("--- [E] live handlers with pid ---")

local live = {663, 664, 666, 667, 669}
for _, sn in ipairs(live) do
    local sc = make_syscall(sn)
    local ok7, rv7 = pcall(function()
        return sc(uint64(pid), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok7 then
        local rh, rl = get_hi_lo(rv7)
        if rl ~= 4294967295 then
            print("[E] sys " .. sn .. "(pid) ret=" .. rl .. " raw=" .. hex(rv7))
        end
    end

    for off = 0, 0x1FF, 4 do wd(buf + off, 0) end
    local ok8, rv8 = pcall(function()
        return sc(uint64(pid), uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0))
    end)
    if ok8 then
        local rh, rl = get_hi_lo(rv8)
        local b0 = safe_rd(buf) or 0
        if rl ~= 4294967295 or b0 ~= 0 then
            print("[E] sys " .. sn .. "(pid,buf,sz) ret=" .. rl .. " buf[0]=0x" .. string.format("%08X", b0))
        end
    end
end

--------------------------------------------------------------------
-- [F] fcntl via make_syscall — deeper test
--------------------------------------------------------------------
print("")
print("--- [F] fcntl deeper ---")

local sc_fcntl = make_syscall(92)

-- Try F_GETFD=1 on stdout (fd=1)
local ok_fg, rv_fg = pcall(function()
    return sc_fcntl(uint64(1), uint64(1))
end)
if ok_fg then
    local rh, rl = get_hi_lo(rv_fg)
    print("[F] F_GETFD(stdout) = " .. rl)
end

-- Try F_GETFL=3 on stdin (fd=0)
ok_fg, rv_fg = pcall(function()
    return sc_fcntl(uint64(0), uint64(3))
end)
if ok_fg then
    local rh, rl = get_hi_lo(rv_fg)
    print("[F] F_GETFL(stdin) = " .. rl)
end

-- F_GETFL on the network socket (which is our connection)
-- The loader probably uses fd 3 or 4 for the client socket
for fd = 3, 25 do
    ok_fg, rv_fg = pcall(function()
        return sc_fcntl(uint64(fd), uint64(3))
    end)
    if ok_fg then
        local rh, rl = get_hi_lo(rv_fg)
        if rl ~= 4294967295 then
            print("[F] fd=" .. fd .. " flags=0x" .. string.format("%X", rl))
        end
    end
end

print("")
print("=== DONE ===")
