-- CRASH_CLASS: MODERATE
-- PROBE 458a: is the camera return ours, and a sweep that can tell -1 apart
--
-- 457a's sweep counted every command as a hit because the loader hands -1
-- back as (h=0, l=0xFFFFFFFF) and the helper only recognised the pair form.
-- 457a also showed /dev/camera answering 0x40040000-0x40040013 with 22 for
-- a mapped page and -1 for NULL, never writing the page.
--
-- [A] asks whether 22 is the descriptor or a value the command echoes: the
--     same command is called on two different descriptors with three
--     different page contents.
-- [B] is the sweep again with a return classifier that treats every -1
--     shape as -1, so only a genuine answer is printed.

print("=== PROBE 458a: IOCTL ECHO AND SWEEP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
-- the loader returns -1 as (0, 0xFFFFFFFF) or as the pair; both mean -1
local function sgn(v)
    local n
    if type(v) == "table" and v.h then
        local h = tonumber(v.h) or 0
        local l = tonumber(v.l) or 0
        if h == 0xFFFFFFFF and (l % 4294967296) == 0xFFFFFFFF then return -1 end
        if h == 0 and (l % 4294967296) == 0xFFFFFFFF then return -1 end
        if h == 0 then return l end
        return nil -- a large value: report as nil so it stands out
    end
    n = tonumber(v) or 0
    if n < 0 then return -1 end
    return n
end
local function fmt(v)
    if v == nil then return "BIG" end
    return tostring(v)
end

local sc_open  = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_mmap  = make_syscall(477)

local function put_path(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(b + i - 1, s:byte(i)) end
    memory.write_byte(b + #s, 0)
    return b
end
local function open_node(path, flags)
    return sgn(sc_open(uint64(to_num(put_path(path))), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0)))
end

local PAGE = 0x1000
local page = to_num(sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if page <= 0 or page >= 0x800000000000 then print("mmap failed"); return end
print(string.format("page=0x%X", page))
print("")

local function zero_page()
    for i = 0, PAGE - 1, 8 do memory.write_qword(uint64(page + i), uint64(0)) end
end
local function pattern(v)
    zero_page()
    memory.write_dword(uint64(page), uint64(v))
end
local function ioctl(fd, cmd, arg)
    return sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(arg), uint64(0), uint64(0), uint64(0)))
end

print("[A] does the camera answer depend on the descriptor or the buffer")
local cam1 = open_node("/dev/camera", 2)
local cam2 = open_node("/dev/camera", 2)
print(string.format("    cam1=%s cam2=%s", tostring(cam1), tostring(cam2)))
if cam1 and cam1 > 0 then
    local cases = {
        { "zeros",    0x00000000 },
        { "deadbeef", 0xDEADBEEF },
        { "11223344", 0x11223344 },
        { "00000016", 0x00000016 },
    }
    for _, c in ipairs(cases) do
        pattern(c[2])
        local r1 = ioctl(cam1, 0x40040000, page)
        local r2 = cam2 and cam2 > 0 and ioctl(cam2, 0x40040000, page) or nil
        local after = to_num(memory.read_dword(uint64(page)))
        print(string.format("    %-9s cam1=%s cam2=%s page0=%08X", c[1], fmt(r1), fmt(r2), after))
    end
    -- every command in the block, on cam1, with the deadbeef page
    pattern(0xDEADBEEF)
    local row = {}
    for cmd = 0x40040000, 0x40040013 do
        row[#row + 1] = string.format("%s", fmt(ioctl(cam1, cmd, page)))
    end
    print("    block: " .. table.concat(row, " "))
end
if cam2 and cam2 > 0 then sc_close(uint64(cam2), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end
print("")

print("[B] group/num sweep, only real answers")
for _, path in ipairs({ "/dev/gc", "/dev/dce", "/dev/gic", "/dev/camera" }) do
    local fd = open_node(path, 2)
    if fd < 0 then fd = open_node(path, 0) end
    print(string.format("  %s fd=%s", path, tostring(fd)))
    if fd and fd > 0 then
        local hits = {}
        for cmd = 0x0000, 0xFFFF do
            local rv = ioctl(fd, cmd, 0)
            if rv ~= -1 then hits[#hits + 1] = { cmd, rv } end
        end
        print(string.format("    done hits=%d", #hits))
        for i = 1, math.min(#hits, 30) do
            local cmd, rv = hits[i][1], hits[i][2]
            pattern(0xDEADBEEF)
            local rp = ioctl(fd, cmd, page)
            local p0 = to_num(memory.read_dword(uint64(page)))
            print(string.format("    HIT 0x%08X null=%s page=%s page0=%08X", cmd, fmt(rv), fmt(rp), p0))
        end
        sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end
end
if cam1 and cam1 > 0 then sc_close(uint64(cam1), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end

print("")
print("=== 458a DONE ===")
