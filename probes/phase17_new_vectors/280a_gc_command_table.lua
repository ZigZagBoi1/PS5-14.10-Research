-- CRASH_CLASS: HIGH
-- PROBE 280a: enumerate the /dev/gc command table in group 0x81
--
-- Context: 279a swept the IOC-encoded space on ten nodes. /dev/gc answered in
-- group 0x81 across three directions and three lengths - nineteen commands
-- returned 0 - and then a command in the 0xC010 block killed the process: the
-- capture ends at the last hit 0xC0108120 with the sweep inside
-- dir=0xC0000000 len=0x10.
--
-- That block is the driver's own table, not the file layer's: 276a showed the
-- generic commands answer on every node and none of these do.
--
-- This probe walks the whole 0x81 group with a line printed BEFORE every call,
-- so the process dying names the exact command instead of the block. It also
-- records whether an accepted command writes into the argument, which is what
-- an information leak would look like.
--
-- A command here may hang or panic the console. That is the point of the probe.

print("=== PROBE 280a: gc group 0x81 ===")
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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/gc")), uint64(0), uint64(0))) end
print("[0] open(/dev/gc)=" .. fd)
if fd < 0 then return end

local page = memory.alloc(0x1000)
local function fill(v)
    for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, v) end) end
end

local dirs = { 0x40000000, 0x80000000, 0xC0000000, 0x20000000 }
local lens = { 0, 4, 8, 0x10, 0x20, 0x40, 0x100 }
local arg = uint64(page)

print("")
print("[A] every command in group 0x81, printed before the call")
for _, d in ipairs(dirs) do
    for _, len in ipairs(lens) do
        local base = d + len * 0x10000 + 0x8100
        for num = 0, 0xFF do
            local cmd = base + num
            fill(0xAAAAAAAA)
            print(string.format("    TRY 0x%08X", cmd))
            local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
            if r ~= -1 then
                print(string.format("    RET 0x%08X -> %d  [0]=0x%08X [4]=0x%08X",
                    cmd, r, rd(page), rd(page + 4)))
            end
        end
    end
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 280a COMPLETE ===")
