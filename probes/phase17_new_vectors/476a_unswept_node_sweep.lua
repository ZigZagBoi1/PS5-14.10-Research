-- CRASH_CLASS: MODERATE
-- PROBE 476a: the full ioctl encoding space on the nodes never swept
--
-- Context: 275a swept /dev/dce, 471a /dev/dmem0 and 471b /dev/gic - the last
-- found the one driver command 0xC0104701. 279a swept ten nodes with the flat
-- 0x0000..0xFFFF space only, which cannot see a command that checks direction
-- bits 30-31 or the length bits 16-28. The nodes below are the ones that were
-- openable but never given the full space:
--
--   /dev/camera  /dev/ajm  /dev/encdec  /dev/uvd_dec  /dev/physhm0  /dev/dmem1
--
-- Same grid as 471b: five directions, nine lengths, group/number 0x0000..0xFFFF
-- with a zeroed 0x1000 page as the argument, so a copyin of any tested length
-- can succeed. 2 949 120 calls per node. A node that will not open is reported
-- and skipped; the sweep continues from the next node, so one run maps all six.

print("=== PROBE 476a: unswept node encoding space ===")
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
    if h ~= 0 or l >= 0x80000000 then
        return -1
    end
    return l
end
local function split(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    return h, l
end
local function all_ones(x)
    return x == -1 or x == 0xFFFFFFFF or x == 0xFFFFFFFFFFFFFFFF
end
local function is_minus_one(h, l)
    return all_ones(h) and all_ones(l)
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

local dirs = { 0x00000000, 0x20000000, 0x40000000, 0x80000000, 0xC0000000 }
local lens = { 0, 4, 8, 0x10, 0x18, 0x20, 0x40, 0x100, 0x1000 }
local TOP = 0x10000

local nodes = { "/dev/ajm", "/dev/encdec", "/dev/uvd_dec", "/dev/physhm0", "/dev/dmem1", "/dev/camera" }
local summary = {}

for _, node in ipairs(nodes) do
    print("")
    print("[" .. node .. "]")
    local fd = sgn(sc_open(uint64(put_str(node)), uint64(2), uint64(0)))
    if fd < 0 then
        fd = sgn(sc_open(uint64(put_str(node)), uint64(0), uint64(0)))
    end
    print(string.format("    open=%d", fd))
    if fd >= 0 then
        local hits = {}
        local total = 0
        for _, d in ipairs(dirs) do
            for _, len in ipairs(lens) do
                local base = d + (len * 0x10000)
                for g = 0, TOP - 1 do
                    local cmd = base + g
                    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), arg) end)
                    total = total + 1
                    local shown = nil
                    if not ok then
                        shown = "PCALL-FAIL"
                    else
                        local h, l = split(r)
                        if not is_minus_one(h, l) then
                            shown = string.format("0x%X%08X", h, l)
                        end
                    end
                    if shown then
                        if #hits < 400 then
                            hits[#hits + 1] = cmd
                            if #hits <= 40 then
                                print(string.format("    HIT cmd=0x%08X ret=%s", cmd, shown))
                            end
                        end
                    end
                    if total % 0x4000 == 0 then
                        print(string.format("    .. %d calls dir=0x%08X len=0x%X cmd=0x%08X", total, d, len, cmd))
                    end
                end
            end
        end
        print(string.format("    total=%d hits=%d", total, #hits))
        summary[#summary + 1] = string.format("%s open=%d hits=%d", node, fd, #hits)
        pcall(function() sc_close(uint64(fd)) end)
    else
        summary[#summary + 1] = string.format("%s not openable", node)
    end
end

print("")
for _, s in ipairs(summary) do print("[SUM] " .. s) end
print("=== PROBE 476a COMPLETE ===")
