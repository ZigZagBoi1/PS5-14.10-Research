-- CRASH_CLASS: LOW
-- PROBE 276a: are the four accepted commands dce's, or the file layer's?
--
-- Context: 275a swept the full 32-bit encoding space on /dev/dce (2 949 120
-- calls) and exactly four returned 0:
--
--   0x20006601  FIOCLEX        (IOC_VOID, group 'f', 1)
--   0x20006602  FIONCLEX       (IOC_VOID, group 'f', 2)
--   0x4004667A  _IOR('f',122)  four bytes out
--   0x80088209  _IOW(0x82, 9)  eight bytes in
--
-- The first three belong to the generic file layer, which would make them
-- meaningless as a dce finding. The fourth does not look generic at all.
--
-- This probe runs all four against dce, zero, null, random, a socket and gic,
-- with a page filled with 0xAA so any write is visible, and prints the buffer
-- before and after. A command that returns 0 on every node is the file layer's;
-- a command that only answers on dce is the driver's.

print("=== PROBE 276a: whose commands are they ===")
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
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_socket = make_syscall(97)

local nodes = { "dce", "zero", "null", "random", "gic", "dmem0" }
local fds = {}
for _, n in ipairs(nodes) do
    local fd = sgn(sc_open(uint64(put_str("/dev/" .. n)), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/" .. n)), uint64(0), uint64(0))) end
    fds[#fds + 1] = { name = n, fd = fd }
    print(string.format("[0] %-8s fd=%d", n, fd))
end
local sfd = sgn(sc_socket(uint64(2), uint64(1), uint64(0)))
fds[#fds + 1] = { name = "socket", fd = sfd }
print(string.format("[0] %-8s fd=%d", "socket", sfd))

local cmds = { 0x20006601, 0x20006602, 0x4004667A, 0x80088209 }

local page = memory.alloc(0x1000)
local function fill(v)
    for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, v) end) end
end

print("")
print("[A] each command against each fd, page filled with 0xAAAAAAAA")
for _, c in ipairs(cmds) do
    print(string.format("  cmd=0x%08X", c))
    for _, f in ipairs(fds) do
        if f.fd >= 0 then
            fill(0xAAAAAAAA)
            local before = rd(page)
            local r = sc_ioctl(uint64(f.fd), uint64(c), uint64(page))
            local after = rd(page)
            print(string.format("    %-8s ret=%-3d  [0]=0x%08X -> 0x%08X", f.name, sgn(r), before, after))
        end
    end
end

print("")
print("[B] the same, with a zero page")
for _, c in ipairs(cmds) do
    print(string.format("  cmd=0x%08X", c))
    for _, f in ipairs(fds) do
        if f.fd >= 0 then
            fill(0)
            local r = sc_ioctl(uint64(f.fd), uint64(c), uint64(page))
            print(string.format("    %-8s ret=%-3d  [0]=0x%08X", f.name, sgn(r), rd(page)))
        end
    end
end

print("")
print("[C] group 0x82 neighbours on dce only: dirs x lens x nums")
local dirs = { 0x00000000, 0x20000000, 0x40000000, 0x80000000, 0xC0000000 }
local lens = { 0, 4, 8, 0x10, 0x18, 0x20, 0x40 }
local dce_fd = nil
for _, f in ipairs(fds) do if f.name == "dce" and f.fd >= 0 then dce_fd = f.fd end end
if dce_fd then
    local hits = 0
    for _, d in ipairs(dirs) do
        for _, len in ipairs(lens) do
            for n = 0, 0xFF do
                local cmd = d + len * 0x10000 + 0x82 * 0x100 + n
                local r = sc_ioctl(uint64(dce_fd), uint64(cmd), uint64(page))
                if sgn(r) ~= -1 then
                    hits = hits + 1
                    print(string.format("    HIT cmd=0x%08X ret=%d", cmd, sgn(r)))
                end
            end
        end
    end
    print("    group 0x82 hits: " .. hits)
end

for _, f in ipairs(fds) do
    if f.fd >= 0 then pcall(function() sc_close(uint64(f.fd)) end) end
end
print("")
print("=== PROBE 276a COMPLETE ===")
