-- CRASH_CLASS: MODERATE
-- PROBE 796a: syscall 626 with the real argument shape (arg2=0, arg3=index, arg4=out, arg5=0)
--
-- Context: 13.60 body 0x604cf0. cmd = arg1 selects one of six cases through a jump table
-- outside the capture. The case at 0x604f32 gates on arg2==0, arg4!=0, arg5==0 and
-- arg3 <= 3-or-7 (CPU dependent), then does rdmsr with
--   ecx = (arg3*2)|0xc0010241        when arg3 <= 3
--   ecx = (arg3*2)+0xc0010189        when arg3 >  3
-- and copyout 8 bytes to arg4. Earlier probes passed an MSR number as arg1 and got -1:
-- arg1 is a command, arg3 is the index.
--
-- This probe: cmd 1..6 with the passing shape, then arg3 sweep for whichever cmds answer.

print("=== PROBE 796a: syscall 626 MSR read ===")
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

local function show_q(buf)
    local h, l = get_hi_lo(safe_rq(buf))
    return string.format("%08X%08X", h, l)
end

local sc626 = make_syscall(626)
local out = memory.alloc(0x40)
for i = 0, 0x3F, 4 do safe_wd(out + i, 0xCDCD0000 + i) end

print("[A] cmd sweep, arg2=0 arg3=0 arg4=out arg5=0")
local answered = {}
for cmd = 1, 6 do
    for i = 0, 0x3F, 4 do safe_wd(out + i, 0xCDCD0000 + i) end
    local before = show_q(out)
    local ok, rv = pcall(function()
        return sc626(uint64(cmd), uint64(0), uint64(0), addrnum(out), uint64(0))
    end)
    local r = ok and to_num(rv) or -999
    print(string.format("  cmd=%d ret=%d out=%s (was %s)", cmd, r, show_q(out), before))
    if ok and r == 0 then answered[#answered + 1] = cmd end
end

print("")
print("[B] arg3 sweep for cmds that answered: " .. tostring(#answered))
for _, cmd in ipairs(answered) do
    for idx = 0, 8 do
        for i = 0, 0x3F, 4 do safe_wd(out + i, 0xCDCD0000 + i) end
        local ok, rv = pcall(function()
            return sc626(uint64(cmd), uint64(0), uint64(idx), addrnum(out), uint64(0))
        end)
        local r = ok and to_num(rv) or -999
        print(string.format("  cmd=%d idx=%d ret=%d out=%s", cmd, idx, r, show_q(out)))
        if not ok then break end
    end
end

print("")
print("[C] arg2/arg5 controls at the first answering cmd (should be rejected)")
if #answered > 0 then
    local cmd = answered[1]
    local shapes = {
        { 0, 0, "arg2=1" },
        { 0, 1, "arg5=1" },
        { 3, 0, "arg2=3" },
    }
    for _, s in ipairs(shapes) do
        local ok, rv = pcall(function()
            return sc626(uint64(cmd), uint64(s[1]), uint64(0), addrnum(out), uint64(s[2]))
        end)
        print(string.format("  %s ret=%d", s[3], ok and to_num(rv) or -999))
    end
    local ok, rv = pcall(function()
        return sc626(uint64(cmd), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  arg4=0 ret=%d", ok and to_num(rv) or -999))
end

print("")
print(string.format("[D] alive out[0]=%s", show_q(out)))
