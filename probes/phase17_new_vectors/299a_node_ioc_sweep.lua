-- CRASH_CLASS: MODERATE
-- PROBE 299a: sweep the four nodes a game process can open read-only
--
-- Context: 298a established which nodes the earlier round never reached.
-- dbggc, sbl_srv, encdec, uvd_dec and mp3 all refuse both O_RDONLY and O_RDWR,
-- so the debug GC device is not reachable from a game process. sce_zlib, ajm,
-- ajmi and rng open read-only (fds 22-25), and camera opens both ways.
--
-- 298a then re-zeroed the whole 0x1000 page before every single ioctl, which
-- is 1024 interpreted writes per call. The sweep did not hang; it was still
-- running when the loader stopped answering. This probe zeroes the page once
-- per block instead and prints a marker before each block, so the run is
-- bounded and its progress is visible.
--
-- Hits are verified twice: once in the sweep, then again on a fresh page.

print("=== PROBE 299a: node ioctl sweep ===")
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

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x1000)
local function zero_page()
    for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + i, 0) end) end
end
zero_page()

local nodes = { "sce_zlib", "ajm", "ajmi", "rng", "camera" }
local opened = {}
for _, n in ipairs(nodes) do
    local rw = sgn(sc_open(uint64(put_str("/dev/" .. n)), uint64(2), uint64(0)))
    if rw >= 0 then
        opened[#opened + 1] = { name = n, fd = rw }
    else
        local ro = sgn(sc_open(uint64(put_str("/dev/" .. n)), uint64(0), uint64(0)))
        if ro >= 0 then opened[#opened + 1] = { name = n, fd = ro } end
    end
end

local DIRS = { 0x00000000, 0x40000000, 0x80000000, 0xC0000000 }
local LENS = { 4, 0x100 }

for _, node in ipairs(opened) do
    print(string.format("[%s] fd=%d", node.name, node.fd))
    local hits = {}
    for _, dir in ipairs(DIRS) do
        for _, len in ipairs(LENS) do
            local base = dir + len * 0x10000
            print(string.format("  block 0x%08X", base))
            for num = 0, 0xFFFF do
                local cmd = base + num
                local r = sgn(sc_ioctl(uint64(node.fd), uint64(cmd), uint64(page)))
                if r ~= -1 then hits[#hits + 1] = { cmd = cmd, r = r } end
            end
        end
    end
    print(string.format("  %d hits", #hits))
    for i = 1, math.min(#hits, 60) do
        local h = hits[i]
        zero_page()
        local r2 = sgn(sc_ioctl(uint64(node.fd), uint64(h.cmd), uint64(page)))
        print(string.format("    0x%08X -> %d (again %d)", h.cmd, h.r, r2))
    end
    pcall(function() sc_close(uint64(node.fd)) end)
end

print("")
print("=== PROBE 299a COMPLETE ===")
