-- CRASH_CLASS: HIGH
-- PROBE 478e: replay 477a then 477b's fatal call
--
-- 477b died at 0x80108013 with a zeroed argument after 0x80108000..0x80108012,
-- printing "[13] ret=-" mid-line. 478b/d now refuse the same call in the same
-- argument shape and the same prefix state, on a boot where 477a's reads were
-- NOT run first.
--
-- 477a ran before 477b in that session: nine reads of 0x4008800A on
-- /dev/dmem1, /dev/dmem0 and /dev/dmem2, each with three page fills.
--
-- This probe replays 477a's sequence exactly, then opens /dev/dmem1 and makes
-- the 0x80108013 call with the zeroed page. If the console dies, the reads own
-- the state that makes the write command lethal; if it survives, the 477b
-- death was not reproducible from this path.

print("=== PROBE 478e: replay 477a then 0x80108013 ===")
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
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function rd32(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function fill(page, v)
    for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, v) end) end
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x100)
fill(page, 0)

-- 477a: nine reads per node with three fills
for _, node in ipairs({ "/dev/dmem1", "/dev/dmem0", "/dev/dmem2" }) do
    local fd = sgn(sc_open(uint64(put_str(node)), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(put_str(node)), uint64(0), uint64(0))) end
    print(string.format("[R] open(%s)=%d", node, fd))
    if fd >= 0 then
        for _, fv in ipairs({ 0x00000000, 0xAAAAAAAA, 0x5A5A5A5A }) do
            fill(page, fv)
            for i = 1, 3 do
                local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x4008800A), uint64(page)) end)
                print(string.format("[R] %s fill=%08X #%d ret=%d out=%08X %08X", node, fv, i,
                    ok and sgn(r) or -999, rd32(page), rd32(page + 4)))
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print("[W] open(/dev/dmem1)=" .. fd)
if fd < 0 then print("[W] refused"); return end

fill(page, 0)
print("[W] call 0x80108013 q0=0 q1=0 q2=0")
local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(page)) end)
print(string.format("[W] ret=%s out=%08X %08X %08X %08X", tostring(ok and sgn(r) or -999),
    rd32(page), rd32(page + 4), rd32(page + 8), rd32(page + 12)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478e COMPLETE ===")
