-- CRASH_CLASS: MODERATE
-- PROBE 566b: the working aio read, with the state visible
--
-- Context: 352c's descriptor layout is offset@0, len@8, buf@0x10, result@0x18,
-- fd@0x20. My 566a used a different layout, so the kernel had no valid buffer
-- and the request hung in 0x10003. This probe re-runs the working layout and
-- prints the state machine, then repeats with 0x1000 bytes.

print("=== PROBE 566b: AIO READ BASELINE ===")

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
local function wq(addr, value) pcall(function() memory.write_qword(addr, value) end) end
local function wd(addr, value) pcall(function() memory.write_dword(addr, value) end) end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function open_path(path, flags)
    local ok, rv = pcall(function() return sc(5)(put_str(path), uint64(flags), Z) end)
    if not ok then return -1 end
    return sgn(rv)
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x2000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x7FF do wd(data + i * 4, 0xA5A5A5A5) end

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

local function round(path, len, label)
    print(string.format("[%s] %s len=%d", label, path, len))
    local fd = open_path(path, 0)
    print(string.format("  open=%d", fd))
    if fd < 0 then return end
    for i = 0, 0x7FF do wd(data + i * 4, 0xA5A5A5A5) end
    wd(result, 0)
    fill_req(reqs, 0, len, data, result, fd)
    print(string.format("  669 ret=%s id=0x%X", tostring(sgn(sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids)))), rd(ids)))
    for k = 1, 3 do
        print(string.format("  664[%d] ret=%s state=0x%X res=0x%X data=%08X %08X %08X %08X",
            k, tostring(sgn(sc(664)(uint64(ids), uint64(1), uint64(states)))), rd(states), rd(result),
            rd(data), rd(data + 4), rd(data + 8), rd(data + 12)))
    end
    print(string.format("  662 ret=%s status=0x%X", tostring(sgn(sc(662)(uint64(ids), uint64(1), uint64(states)))), rd(states)))
end

round("/dev/zero", 16, "A")
round("/dev/urandom", 16, "B")
round("/dev/urandom", 0x1000, "C")

print("=== 566b DONE ===")
