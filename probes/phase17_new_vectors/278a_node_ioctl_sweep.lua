-- CRASH_CLASS: MODERATE
-- PROBE 278a: which device nodes answer a driver-owned command in 0x0000..0xFFFF
--
-- Context: 275a swept the whole 32-bit encoding space on /dev/dce and found
-- four accepted commands, three of which are the file layer's (276a: FIOCLEX,
-- FIONCLEX, FIODTYPE answer on every character device) and one which is the
-- driver's own, _IOW(0x82, 9, 8), which copies in eight bytes and returns 0.
--
-- This probe runs the same search on every other node a game process can open,
-- in two tiers:
--   [1] 0x0000..0xFFFF with a zero page, every node, 65 536 calls each
--   [2] the IOC-encoded space for the nodes that showed anything, 6 lengths and
--       4 directions
-- Generic file-layer commands are recognised and not reported as hits.

print("=== PROBE 278a: driver-owned ioctls ===")
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

local GENERIC = {
    [0x20006601] = "FIOCLEX",
    [0x20006602] = "FIONCLEX",
    [0x4004667A] = "FIODTYPE",
    [0x8004667D] = "FIOASYNC",
    [0x8004667E] = "FIONBIO",
    [0x4004667F] = "FIONREAD",
}

local names = {
    "gc", "gic", "dmem0", "dmem1", "dmem2", "uvd_enc", "sce_zlib",
    "ajm", "ajmi", "hid", "bt", "camera", "usbctl", "usb",
    "hmd_cmd", "hmd_snsr", "hmd_3da", "hmd_dist",
    "hmd2_cmd", "hmd2_imu", "hmd2_leddet", "hmd2_gaze",
    "notification0", "notification6", "notification7",
    "dipsw", "fd", "rng", "random", "zero", "null",
}

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

local opened = {}
print("[1] tier one: commands 0x0000..0xFFFF, zero page")
for _, n in ipairs(names) do
    local p = put_str("/dev/" .. n)
    local fd = sgn(sc_open(uint64(p), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(p), uint64(0), uint64(0))) end
    if fd < 0 then
        print(string.format("    %-14s no", n))
    else
        local hits = {}
        for cmd = 0, 0xFFFF do
            local n = sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
            if n ~= -1 and not GENERIC[cmd] then hits[#hits + 1] = cmd end
        end
        opened[#opened + 1] = { name = n, fd = fd, tier1 = hits }
        if #hits == 0 then
            print(string.format("    %-14s fd=%d  no driver-owned command", n, fd))
        else
            local parts = {}
            for _, c in ipairs(hits) do parts[#parts + 1] = string.format("0x%04X", c) end
            print(string.format("    %-14s fd=%d  %s", n, fd, table.concat(parts, " ")))
        end
    end
end

print("")
for _, o in ipairs(opened) do pcall(function() sc_close(uint64(o.fd)) end) end
print("")
print("=== PROBE 278a COMPLETE ===")
