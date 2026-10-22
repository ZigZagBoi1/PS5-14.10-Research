-- CRASH_CLASS: LOW
-- PROBE 352e: the AIO descriptor fields the request trusts, with the result read back
--
-- 352a/352c prove the batch entry works: one read from /dev/urandom landed 16
-- real bytes in our buffer and 664 reported state 3. The descriptor carries
-- four values the kernel must validate - offset, byte count, data pointer,
-- result pointer - and a descriptor number.
--
-- This probe asks what happens at the edges: a full-width offset, an offset
-- past the device size, a byte count larger than the buffer, a zero count, and
-- an invalid descriptor number. A canary allocation sits directly after the
-- read buffer so a write beyond the buffer is visible as a changed canary.

print("=== PROBE 352e: AIO DESCRIPTOR EDGES AND RESULTS ===")
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

local function fill_req(off, len, buf, res, fd)
    wq(reqs + 0x00, off)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(uint64(buf))
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(uint64(res))
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
end

local function canary_intact()
    for i = 0, 0xFF do
        if rd(canary + i * 4) ~= 0xA5A5A5A5 then return false, i * 4 end
    end
    return true, -1
end

local function run(off, len, label)
    fill_req(off, len, data, result, fd)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    local sub = ok1 and sgn(r1) or nil
    local ok2, r2 = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    local pol = ok2 and sgn(r2) or nil
    local good, where = canary_intact()
    print(string.format("  %-26s submit=%-3s poll=%-3s state=0x%X canary=%s",
        label, tostring(sub), tostring(pol), rd(states),
        good and "intact" or ("CHANGED at +0x" .. string.format("%X", where))))
    print(string.format("      result = %08X %08X %08X %08X %08X %08X",
        rd(result), rd(result + 4), rd(result + 8), rd(result + 12),
        rd(result + 16), rd(result + 20)))
    print(string.format("      data   = %08X %08X %08X %08X",
        rd(data), rd(data + 4), rd(data + 8), rd(data + 12)))
    local ok3 = pcall(function()
        return sc(662)(uint64(ids), uint64(1), uint64(states))
    end)
    return sub, pol
end

local fd = open_path("/dev/zero", 0)
print(string.format("[A] /dev/zero fd=%d", fd))
if fd >= 0 then
    run(0, 16, "offset 0 len 16")
    run(0xFFFFFFFF, 16, "offset 0xFFFFFFFF")
    run(0x7FFFFFFFFFFFFFFF, 0, "offset huge len 0")
    run(0, 0, "len 0")
    run(0, 0x100000, "len 1 MiB, 4 KiB buffer")
    run(0x1000, 16, "offset 0x1000")
end

print("[B] descriptor numbers that are not open")
local fd2 = open_path("/dev/zero", 0)
print(string.format("  fresh fd = %d", fd2))
if fd2 >= 0 then
    fill_req(0, 16, data, result, fd2 + 100)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    print(string.format("  669 fd+100 = %s", ok1 and tostring(sgn(r1)) or "EXC"))
    fill_req(0, 16, data, result, -1)
    local ok2, r2 = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    print(string.format("  669 fd=-1  = %s", ok2 and tostring(sgn(r2)) or "EXC"))
end

print("")
print("=== 352e DONE ===")
