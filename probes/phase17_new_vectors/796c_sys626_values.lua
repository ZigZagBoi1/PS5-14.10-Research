-- CRASH_CLASS: MODERATE
-- PROBE 796c: the 626 cases that were never satisfied -- arg4 and arg5 both non-NULL
--
-- 13.60 case at 0x604eb9 (one of cmds 1..6): arg2|arg3 must be 0, arg4 must be non-NULL,
-- arg5 must be non-NULL, then it copyins from arg5 into [rbp-0x120] and from arg4 into
-- [rbp-0xa0] via 0x8afc3c50 and tail-calls with them. That is the mirror shape of the
-- rdmsr case (0x604f32), which uses a single out pointer: an MSR write takes values.
--
-- 796a/796b satisfied only arg4, so every cmd except 5 failed. This probe supplies both,
-- with zero-filled pages first (the same value the firmware's own initialiser writes),
-- then reads the pages back to see whether the kernel treated them as inputs or outputs.

print("=== PROBE 796c: syscall 626 value arguments ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function addrnum(v)
    if type(v) == "table" then
        if v.h and v.l then return u64(v.h, v.l) end
        return uint64(to_num(v))
    end
    return uint64(to_num(v))
end
local function q(buf)
    local h, l = get_hi_lo(safe_rq(buf))
    return string.format("%08X%08X", h, l)
end

local sc626 = make_syscall(626)
local p4 = memory.alloc(0x400)
local p5 = memory.alloc(0x400)
local function zero(p)
    for i = 0, 0x3FC, 4 do safe_wd(p + i, 0) end
end

print("[A] cmd 1..6 with arg2=0 arg3=0 arg4=page5 arg5=page6 (both zero-filled)")
local ok_cmds = {}
for cmd = 1, 6 do
    zero(p4)
    zero(p5)
    local ok, rv = pcall(function()
        return sc626(uint64(cmd), uint64(0), uint64(0), addrnum(p4), addrnum(p5))
    end)
    local r = ok and to_num(rv) or -999
    print(string.format("  cmd=%d ret=%d a4=%s a5=%s", cmd, r, q(p4), q(p5)))
    if ok and r == 0 then ok_cmds[#ok_cmds + 1] = cmd end
end

print("")
print("[B] idx sweep for answering cmds, both pointers zero")
for _, cmd in ipairs(ok_cmds) do
    for idx = 0, 8 do
        zero(p4)
        zero(p5)
        local ok, rv = pcall(function()
            return sc626(uint64(cmd), uint64(0), uint64(idx), addrnum(p4), addrnum(p5))
        end)
        local r = ok and to_num(rv) or -999
        print(string.format("  cmd=%d idx=%d ret=%d a4=%s a5=%s", cmd, idx, r, q(p4), q(p5)))
        if not ok then break end
    end
end

print("")
print("[C] arg2 sweep at each answering cmd, idx 0")
for _, cmd in ipairs(ok_cmds) do
    local line = string.format("  cmd=%d", cmd)
    for _, a2 in ipairs({ 0, 1, 2, 3 }) do
        zero(p4)
        zero(p5)
        local ok, rv = pcall(function()
            return sc626(uint64(cmd), uint64(a2), uint64(0), addrnum(p4), addrnum(p5))
        end)
        line = line .. string.format("  a2=%d:r=%d", a2, ok and to_num(rv) or -999)
    end
    print(line)
end

print("")
print("[D] alive")
