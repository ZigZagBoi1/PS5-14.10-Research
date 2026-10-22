-- CRASH_CLASS: MODERATE
-- PROBE 352f: three urandom reads in this process, with the result field
--
-- 352a completed a /dev/zero read through 669/664/662 and printed every step.
-- 352b did the same against /dev/urandom and died between the submit line and
-- the poll line, leaving the loader's fault dump on the wire (the first bytes
-- are 0x13371337, so the process took a fatal signal in userland).
--
-- This probe repeats the working sequence first, then the urandom one, with a
-- print between every single call, so the first missing line is the exact call
-- that dies. Buffers are identical to 352a's.

print("=== PROBE 352f: AIO REPEAT ===")
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
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x3FF do wd(data + i * 4, 0) end

local function fill_req(base, off, len, buf, res, fd)
    wq(base + 0x00, off)
    wq(base + 0x08, len)
    local bh, bl = hi_lo(uint64(buf))
    wd(base + 0x10, bl) wd(base + 0x14, bh)
    local rh, rl = hi_lo(uint64(res))
    wd(base + 0x18, rl) wd(base + 0x1C, rh)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function round(path, flags, label)
    print("[" .. label .. "] " .. path)
    local fd = open_path(path, flags)
    print(string.format("  open = %d", fd))
    if fd < 0 then return end
    fill_req(reqs, 0, 16, data, result, fd)
    print("  descriptor written")
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    print(string.format("  669 = %s  id[0]=0x%X", ok1 and tostring(sgn(r1)) or "EXC", rd(ids)))
    local ok2, r2 = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    print(string.format("  664 = %s  state=0x%X", ok2 and tostring(sgn(r2)) or "EXC", rd(states)))
    print(string.format("  data = %08X %08X %08X %08X", rd(data), rd(data + 4), rd(data + 8), rd(data + 12)))
    print(string.format("  result = %08X %08X %08X", rd(result), rd(result + 4), rd(result + 8)))
    local ok3, r3 = pcall(function()
        return sc(662)(uint64(ids), uint64(1), uint64(states))
    end)
    print(string.format("  662 = %s", ok3 and tostring(sgn(r3)) or "EXC"))
end

round("/dev/urandom", 0, "A")
round("/dev/urandom", 0, "B")
round("/dev/urandom", 0, "C")

print("")
print("=== 352f DONE ===")
