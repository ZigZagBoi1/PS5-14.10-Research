-- CRASH_CLASS: LOW
-- PROBE 85c: Safe getsockopt scan - only try known-working options

print("=== PROBE 85c ===")
print("pid=" .. tostring(syscall.getpid()))

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local fd = to_num(syscall.socket(uint64(28), uint64(2), uint64(17)))
print("fd=" .. fd)

-- Set recvpktinfo
local optbuf = memory.alloc(4)
memory.write_dword(optbuf, 1)
local r = syscall.setsockopt(uint64(fd), uint64(41), uint64(19), uint64(optbuf), uint64(4))
print("set19=" .. tostring(r))

-- Also set NEXTHOP, HOPOPTS
r = syscall.setsockopt(uint64(fd), uint64(41), uint64(27), uint64(optbuf), uint64(4))
print("set27=" .. tostring(r))

-- getsockopt - read back the options that worked in setsockopt
print("")
print("--- GET ---")
local outbuf = memory.alloc(0x100)
local lenp = memory.alloc(4)

-- Only try options that returned OK in setsockopt (from 84l)
local safe_opts = {
    {41, 4}, {41, 9}, {41, 10}, {41, 11}, {41, 14},
    {41, 19}, {41, 20}, {41, 42}, {41, 43},
    {41, 59}, {41, 61}, {41, 62}, {41, 63},
    {0xFFFF, 4}, {0xFFFF, 8}, {0xFFFF, 16}, {0xFFFF, 32},
    {0xFFFF, 256}, {0xFFFF, 512}, {0xFFFF, 1024},
    {0xFFFF, 4097}, {0xFFFF, 4098},
}

for _, opt in ipairs(safe_opts) do
    memory.write_dword(lenp, 0x100)
    for i = 0, 0x3C, 4 do memory.write_dword(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(opt[1]), uint64(opt[2]),
            uint64(outbuf), uint64(lenp))
    end)
    if ok and to_num(ret) == 0 then
        local rlen = to_num(memory.read_dword(lenp))
        -- Check all qwords for kernel pointers
        local found = false
        for off = 0, math.min(rlen - 1, 0x3F), 8 do
            local q = memory.read_qword(outbuf + off)
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then
                print(string.format("KPTR! level=%d opt=%d +0x%02X %s", opt[1], opt[2], off, tostring(q)))
                found = true
            end
        end
        if not found and rlen > 4 then
            -- Print first qword if non-zero
            local q = memory.read_qword(outbuf)
            local h, l = get_hi_lo(q)
            if h ~= 0 or l ~= 0 then
                print(string.format("lvl=%d opt=%d len=%d val=%s", opt[1], opt[2], rlen, tostring(q)))
            end
        end
    end
end

syscall.close(uint64(fd))
print("=== PROBE 85c COMPLETE ===")
