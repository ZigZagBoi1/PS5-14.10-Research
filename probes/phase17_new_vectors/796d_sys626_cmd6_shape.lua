-- CRASH_CLASS: LOW
-- PROBE 796d: shape of the 626 cmd 6 two-pointer reply
--
-- 796c: 626(6, 0, 0, p4, p5) -> ret 0, p4[0]=0x405E7113 then 0x405ED0DA,
-- p5[0]=0x962EA225 then 0x962ED70C. Both grow. Every other cmd needs arg2=0 as well.
--
-- Questions: how many bytes are written per pointer, does the value pair share one
-- 64-bit source (p4 = low half, p5 = high half), is either pointer optional, and does an
-- unmapped pointer give EFAULT (proving a copyout) rather than a silent success.

print("=== PROBE 796d: 626 cmd 6 reply shape ===")
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
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function addrnum(v)
    if type(v) == "table" then return uint64(to_num(v)) end
    return uint64(to_num(v))
end

local sc626 = make_syscall(626)
local p4 = memory.alloc(0x400)
local p5 = memory.alloc(0x400)

local function zero(p)
    for i = 0, 0x3FC, 4 do safe_wd(p + i, 0) end
end
local function dump(p, tag)
    local line = "  " .. tag
    for i = 0, 7 do
        line = line .. string.format(" %08X", safe_rd(p + i*4) or 0)
    end
    print(line)
end
local function spin(ms)
    local t0 = os.clock()
    while os.clock() - t0 < ms / 1000 do end
end
local function call(a2, a3, a4, a5)
    local ok, rv = pcall(function()
        return sc626(uint64(6), uint64(a2), uint64(a3), addrnum(a4), addrnum(a5))
    end)
    return ok and to_num(rv) or -999
end

print("[A] three calls, 8 dwords of each page")
for k = 1, 3 do
    zero(p4)
    zero(p5)
    local r = call(0, 0, p4, p5)
    print("  call " .. k .. " ret=" .. r)
    dump(p4, "p4:")
    dump(p5, "p5:")
    spin(20)
end

print("")
print("[B] p4 == p5 (one page)")
zero(p4)
local r = call(0, 0, p4, p4)
print("  ret=" .. r)
dump(p4, "same:")

print("")
print("[C] one pointer NULL")
local r1 = call(0, 0, p4, 0)
print("  p5=0 ret=" .. r1)
local r2 = call(0, 0, 0, p5)
print("  p4=0 ret=" .. r2)
local r3 = call(0, 0, 0, 0)
print("  both 0 ret=" .. r3)

print("")
print("[D] unmapped pointers")
local r4 = call(0, 0, 0xDEAD0000, p5)
print("  p4 unmapped ret=" .. r4)
local r5 = call(0, 0, p4, 0xDEAD0000)
print("  p5 unmapped ret=" .. r5)

print("")
print("[E] idx with both pointers")
for idx = 0, 2 do
    zero(p4)
    zero(p5)
    local r = call(0, idx, p4, p5)
    print(string.format("  idx=%d ret=%d p4=%08X p5=%08X", idx, r, safe_rd(p4) or 0, safe_rd(p5) or 0))
end

print("")
print("[F] alive")
