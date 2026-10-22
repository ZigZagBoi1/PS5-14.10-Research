-- CRASH_CLASS: MODERATE
-- PROBE 298a: the debug GC node, and which remaining nodes open at all
--
-- Context: 297a showed GnmCompositorRestricted and AgcCompositorSppSocket
-- accept connections and never answer zeros, and VrTracker2DomainSock stopped
-- accepting after two connections. Nothing observable there yet.
--
-- /dev also lists nodes that the earlier sweeps either could not open or never
-- reached: dbggc, sbl_srv, encdec, uvd_dec, mp3, sce_zlib, ajm, ajmi, rng.
-- dbggc is a debug interface to the same driver as gc, which makes it the most
-- likely to expose commands the retail node does not.
--
-- This probe first records which of them open read-only and read-write, then
-- sweeps the 16-bit command space of every node that opens, four directions and
-- two lengths, and prints every command that does not return -1.
--
-- Every call is on a zeroed page; nothing is freed and nothing is unmapped.

print("=== PROBE 298a: debug gc and the remaining nodes ===")
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

local O_RDONLY = 0
local O_RDWR = 2

local nodes = { "dbggc", "sbl_srv", "encdec", "uvd_dec", "mp3", "sce_zlib", "ajm", "ajmi", "rng", "camera" }
local page = memory.alloc(0x1000)

local opened = {}
for _, n in ipairs(nodes) do
    local path = "/dev/" .. n
    local ro = sgn(sc_open(uint64(put_str(path)), uint64(O_RDONLY), uint64(0)))
    local rw = sgn(sc_open(uint64(put_str(path)), uint64(O_RDWR), uint64(0)))
    print(string.format("%-10s O_RDONLY=%d O_RDWR=%d", n, ro, rw))
    if ro >= 0 then opened[#opened + 1] = { name = n, fd = ro } end
    if rw >= 0 then opened[#opened + 1] = { name = n .. "/rw", fd = rw } end
end

print("")

local DIRS = { 0x00000000, 0x40000000, 0x80000000, 0xC0000000 }
local LENS = { 4, 0x100 }

for _, node in ipairs(opened) do
    local hits = {}
    local total = 0
    for _, dir in ipairs(DIRS) do
        for _, len in ipairs(LENS) do
            local base = dir + len * 0x10000
            for num = 0, 0xFFFF do
                for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + i, 0) end) end
                local cmd = base + num
                local r = sgn(sc_ioctl(uint64(node.fd), uint64(cmd), uint64(page)))
                total = total + 1
                if r ~= -1 then
                    hits[#hits + 1] = string.format("0x%08X->%d", cmd, r)
                    if #hits >= 40 then break end
                end
            end
            if #hits >= 40 then break end
        end
        if #hits >= 40 then break end
    end
    print(string.format("[%s] %d calls, %d hits", node.name, total, #hits))
    for i = 1, #hits, 4 do
        print("  " .. table.concat(hits, " ", i, math.min(i + 3, #hits)))
    end
    pcall(function() sc_close(uint64(node.fd)) end)
end

print("")
print("=== PROBE 298a COMPLETE ===")
