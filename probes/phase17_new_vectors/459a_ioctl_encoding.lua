-- CRASH_CLASS: MODERATE
-- PROBE 459a: sweep the ioctl encoding, not just the value
--
-- 458a measured that /dev/camera answers 22 for the whole block
-- 0x40040000-0x40040013 when the argument is a mapped page, and -1 for
-- NULL, whichever descriptor is used and whatever the page holds.  22 is
-- EINVAL, and the NULL/-1 split means the copyin happens before the
-- refusal.  So the command is recognised and the argument is what fails.
--
-- The encoding is _IOC(dir, group, num, len) = dir<<30 | len<<16 | group<<8
-- | num, so 0x40040000 is dir=1 len=4 group=4 num=0.  This probe holds the
-- group and number fixed and walks dir and len.

print("=== PROBE 459a: IOCTL ENCODING SWEEP ===")
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
    if type(v) ~= "table" or not v.h then
        local n = tonumber(v) or 0
        if n < 0 then return -1 end
        return n
    end
    local h = tonumber(v.h) or 0
    local l = tonumber(v.l) or 0
    if h == -1 or h == 0xFFFFFFFF then
        if l == -1 or (l % 4294967296) == 0xFFFFFFFF then return -1 end
    end
    if h ~= 0 then return nil end
    return l
end
local function fmt(v) if v == nil then return "BIG" end return tostring(v) end

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

local PAGE = 0x2000
local page = to_num(sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if page <= 0 or page >= 0x800000000000 then print("mmap failed"); return end
for i = 0, PAGE - 1, 8 do memory.write_qword(uint64(page + i), uint64(0)) end
print(string.format("page=0x%X", page))
print("")

local DIRS = { 0, 1, 2, 3 }
local LENS = { 0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x100, 0x200, 0x400, 0x1000 }
local function enc(dir, len, group, num)
    return dir * 1073741824 + len * 65536 + group * 256 + num
end
local function ioctl(fd, cmd, arg)
    return sgn(sc_ioctl(uint64(fd), uint64(cmd), uint64(arg), uint64(0), uint64(0), uint64(0)))
end

for _, path in ipairs({ "/dev/camera", "/dev/gc", "/dev/dce", "/dev/gic" }) do
    local fd = open_node(path, 2)
    if fd < 0 then fd = open_node(path, 0) end
    print(string.format("[%s] fd=%s", path, tostring(fd)))
    if fd and fd > 0 then
        for _, dir in ipairs(DIRS) do
            for _, len in ipairs(LENS) do
                local hits = {}
                for num = 0, 0x3F do
                    local cmd = enc(dir, len, 4, num)
                    local rv = ioctl(fd, cmd, page)
                    if rv ~= -1 then hits[#hits + 1] = { num, rv } end
                end
                if #hits > 0 then
                    local t = {}
                    for i = 1, math.min(#hits, 12) do
                        t[#t + 1] = string.format("%02X=%s", hits[i][1], fmt(hits[i][2]))
                    end
                    print(string.format("  dir=%d len=0x%03X hits=%d  %s",
                        dir, len, #hits, table.concat(t, " ")))
                end
            end
        end
        sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end
    print("")
end

print("=== 459a DONE ===")
