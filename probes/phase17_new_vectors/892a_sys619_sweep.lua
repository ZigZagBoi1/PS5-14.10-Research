-- CRASH_CLASS: LOW
-- PROBE 892a: sys 619 -- a body that returns 78 unconditionally
--
-- The 13.60 decompile returns 78 with no argument loads, yet every 14.10 test
-- returned -1 (probe 179a, fifteen layouts; 706a, with a SIGSYS shield). Either
-- the handler never runs on 14.10, or the value is refused before the body.
-- This sweep varies only the argument count, with a known-good control after.

print("=== PROBE 892a: SYS 619 SWEEP ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function show(tag, ok, rv)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end

local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] control: getpid = %u", pid))

local sc619 = make_syscall(619)
local z = uint64(0)
local buf = memory.alloc(0x100)
print("[B] argument count, all zeros:")
for n = 0, 6 do
    local ok, rv
    if n == 0 then ok, rv = pcall(function() return sc619() end)
    elseif n == 1 then ok, rv = pcall(function() return sc619(z) end)
    elseif n == 2 then ok, rv = pcall(function() return sc619(z, z) end)
    elseif n == 3 then ok, rv = pcall(function() return sc619(z, z, z) end)
    elseif n == 4 then ok, rv = pcall(function() return sc619(z, z, z, z) end)
    elseif n == 5 then ok, rv = pcall(function() return sc619(z, z, z, z, z) end)
    else ok, rv = pcall(function() return sc619(z, z, z, z, z, z) end) end
    show(string.format("narg=%d zeros", n), ok, rv)
end

print("[C] plausible pointers:")
local okp, rvp = pcall(function() return sc619(uint64(buf), z, z, z) end)
show("619(buf,0,0,0)", okp, rvp)
print(string.format("  buf[0]=0x%08X", to_num(pcall(function() return memory.read_dword(buf) end) or 0)))

local okq, rvq = pcall(function() return sc619(uint64(pid), z, z, z) end)
show("619(pid,0,0,0)", okq, rvq)

print("")
print("=== PROBE 892a DONE ===")
