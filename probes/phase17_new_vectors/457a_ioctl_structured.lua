-- CRASH_CLASS: MODERATE
-- PROBE 457a: give the device-driver ioctl space its real encoding
--
-- 288a swept bare command values 0x00-0xFF; 299a swept 0..0xFFFF on the
-- nodes that answer, and only FIODTYPE (0x4004667A) ever returned 0.
-- 288a also recorded /dev/camera answering 0x40040000-0x40040013 with the
-- value 22, which is the fd it was opened on, so that reading is suspect.
--
-- FreeBSD encodes ioctl requests as
--   _IOC(dir, group, num, len) = dir<<30 | len<<16 | group<<8 | num,
-- so group and number land in the low 16 bits and a sweep there covers
-- every (group, num) with dir=0 and len=0.  This probe sweeps that space
-- on the nodes a game process can open, then re-calls every hit with a
-- page so a command that moves data has somewhere to put it.

print("=== PROBE 457a: STRUCTURED IOCTL SWEEP ===")
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
    local h, l = 0, 0
    if type(v) == "table" and v.h then h, l = v.h, v.l else l = tonumber(v) or 0 end
    if h then h = tonumber(h) or 0 end
    l = tonumber(l) or 0
    if h == 0xFFFFFFFF and (l % 0x100000000) == 0xFFFFFFFF then return -1 end
    return l
end
local sc_open = make_syscall(5)
local sc_ioctl = make_syscall(54)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)

local function put_path(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(b + i - 1, s:byte(i)) end
    memory.write_byte(b + #s, 0)
    return b
end

local PAGE = 0x1000
local page = to_num(sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if page <= 0 or page >= 0x800000000000 then
    print("mmap failed, cannot continue")
    return
end
for i = 0, PAGE - 1, 8 do memory.write_qword(uint64(page + i), uint64(0)) end
print(string.format("page=0x%X", page))
print("")

local function open_node(path, flags)
    local fd = sgn(sc_open(uint64(to_num(put_path(path))), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0)))
    if fd < 0 then return nil end
    return fd
end

local function dump_page(label)
    local t = {}
    for i = 0, 3 do
        t[#t + 1] = string.format("%08X", to_num(memory.read_dword(uint64(page + i * 4))))
    end
    print(string.format("    %s page: %s", label, table.concat(t, " ")))
end

-- [A] camera: the one node with a visible multi-command block
print("[A] /dev/camera commands 0x40040000-0x40040013")
local cam = open_node("/dev/camera", 2)
print(string.format("    open=%s", tostring(cam)))
if cam then
    for cmd = 0x40040000, 0x40040013 do
        for i = 0, PAGE - 1, 8 do memory.write_qword(uint64(page + i), uint64(0)) end
        local r_file = sgn(sc_ioctl(uint64(cam), uint64(cmd), uint64(page), uint64(0), uint64(0), uint64(0)))
        local r_null = sgn(sc_ioctl(uint64(cam), uint64(cmd), uint64(0), uint64(0), uint64(0), uint64(0)))
        print(string.format("    0x%08X  page=%d  null=%d", cmd, r_file, r_null))
        if r_file ~= -1 then dump_page("   ") end
    end
    sc_close(uint64(cam), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end
print("")

-- [B] the group/num sweep with dir=0 len=0
local nodes = { "/dev/gc", "/dev/dce", "/dev/gic", "/dev/ajm", "/dev/rng", "/dev/camera", "/dev/hid", "/dev/bt" }
for _, path in ipairs(nodes) do
    local fd = open_node(path, 2)
    if not fd then fd = open_node(path, 0) end
    print(string.format("[B] %s fd=%s  sweep 0x0000-0xFFFF", path, tostring(fd)))
    if fd then
        local hits = {}
        for cmd = 0x0000, 0xFFFF do
            local rv = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(0), uint64(0), uint64(0), uint64(0)))
            if rv ~= -1 then hits[#hits + 1] = cmd end
            if cmd % 0x4000 == 0 then print(string.format("    at 0x%04X hits=%d", cmd, #hits)) end
        end
        print(string.format("    done hits=%d", #hits))
        for i = 1, math.min(#hits, 40) do
            local cmd = hits[i]
            for j = 0, PAGE - 1, 8 do memory.write_qword(uint64(page + j), uint64(0)) end
            local rv = sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(page), uint64(0), uint64(0), uint64(0)))
            print(string.format("    HIT 0x%08X rv=%d", cmd, rv))
            dump_page("   ")
        end
        sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end
    print("")
end

print("=== 457a DONE ===")
