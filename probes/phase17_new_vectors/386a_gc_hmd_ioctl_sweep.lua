-- CRASH_CLASS: MODERATE
-- PROBE 386a: sweep the ioctl space of /dev/gc and the hmd family
--
-- Every node whose d_ioctl was ever proven to exist was swept except two families:
-- /dev/gc (graphics core, opens 32/33) and the seven /dev/hmd* nodes. The hmd nodes
-- are the better lead: in 360a they answered the five encrypt ioctls with device
-- return values (-1972236285, -2129592061) instead of ENOTTY, so they read a
-- user-supplied {buffer, length, type} struct and act on it, and only five codes
-- were ever tried.
--
-- For each node this walks 0x00-0xFF with three argument shapes (a mapped page, a
-- NULL pointer, an unmapped pointer) and prints every call that does not answer -1,
-- with the first bytes of the page afterwards. Commands that are recognised show up
-- either as a hit or as a page change.

print("=== PROBE 386a: GC + HMD IOCTL SWEEP ===")
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
local sc_open  = make_syscall(5)
local sc_ioctl = make_syscall(54)
local sc_close = make_syscall(6)

local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    if (l % 2) == 1 then return h * 4294967296 + l - 4294967296 end
    return h * 4294967296 + l
end
local function open_rdwr(path)
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
    local ok = pcall(function()
        for i = 1, #path do memory.write_byte(buf + i - 1, path:byte(i)) end
        memory.write_byte(buf + #path, 0)
    end)
    if not ok then return -1 end
    local fd = -1
    pcall(function() fd = sgn(sc_open(uint64(buf), uint64(2), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    return fd
end
local function hex_at(addr, n)
    local s = ""
    for i = 0, n - 1 do
        local ok, b = pcall(function() return memory.read_byte(addr + i) end)
        if ok and b then s = s .. string.format("%02X", to_num(b)) else s = s .. "??" end
    end
    return s
end
local function ioctl(fd, cmd, arg)
    local r = -999
    pcall(function() r = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(arg), uint64(0), uint64(0), uint64(0))) end)
    return r
end

local page = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + i, 0) end) end

local nodes = {
    "/dev/gc", "/dev/hmd_cmd", "/dev/hmd_snsr", "/dev/hmd_3da",
    "/dev/hmd_dist", "/dev/hmd2_cmd", "/dev/hmd2_imu",
}
local extra = { 0x4004667A, 0xC0104401, 0xC0184402, 0xC0184403, 0xC0184404, 0xC0184405 }

for _, path in ipairs(nodes) do
    local fd = open_rdwr(path)
    print(string.format("[%s] fd=%d", path, fd))
    if fd >= 0 then
        local hits = 0
        for cmd = 0, 0xFF do
            local r1 = ioctl(fd, cmd, page)
            local r2 = ioctl(fd, cmd, 0)
            local r3 = ioctl(fd, cmd, 0x1000)
            if r1 ~= -1 or r2 ~= -1 or r3 ~= -1 then
                hits = hits + 1
                print(string.format("  HIT cmd=0x%02X page=%d null=%d bad=%d buf=%s",
                    cmd, r1, r2, r3, hex_at(page, 8)))
                for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + i, 0) end) end
            end
        end
        for _, cmd in ipairs(extra) do
            local r1 = ioctl(fd, cmd, page)
            local r2 = ioctl(fd, cmd, 0)
            if r1 ~= -1 or r2 ~= -1 then
                hits = hits + 1
                print(string.format("  HIT cmd=0x%08X page=%d null=%d buf=%s",
                    cmd, r1, r2, hex_at(page, 12)))
                for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + i, 0) end) end
            end
        end
        print(string.format("  hits=%d", hits))
        pcall(function() sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end

print("")
print("=== 386a DONE ===")
