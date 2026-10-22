-- CRASH_CLASS: MODERATE
-- PROBE 279a: the IOC-encoded command space on ten device nodes
--
-- Context: 278a swept 0x0000..0xFFFF on 31 nodes with no hit. That range has no
-- direction or length bits, so a driver that matches a full 32-bit constant -
-- the encrypt service uses 0xC0104401 - is invisible to it. 275a showed the
-- encoding matters: /dev/dce answers only the exact 0x80088209.
--
-- This probe crosses four directions with five lengths over the 16-bit
-- group/number space on the nodes where a real command would be worth finding.
-- 1 310 720 calls per node; the progress line names the node, direction and
-- length, so a panic points at the command block that caused it.

print("=== PROBE 279a: IOC-encoded sweep ===")
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
    [0x20006601] = true, [0x20006602] = true, [0x4004667A] = true,
    [0x8004667D] = true, [0x8004667E] = true, [0x4004667F] = true,
}

local names = { "gc", "gic", "dmem0", "uvd_enc", "sce_zlib", "ajm", "hid", "camera", "usbctl", "notification0" }
local dirs = { 0x40000000, 0x80000000, 0xC0000000, 0x20000000 }
local lens = { 4, 8, 0x10, 0x20, 0x100 }

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

for _, n in ipairs(names) do
    local p = put_str("/dev/" .. n)
    local fd = sgn(sc_open(uint64(p), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(p), uint64(0), uint64(0))) end
    if fd < 0 then
        print(string.format("[A] %-14s no", n))
    else
        local hits = {}
        local calls = 0
        for _, d in ipairs(dirs) do
            for _, len in ipairs(lens) do
                local base = d + len * 0x10000
                print(string.format("[A] %-14s dir=0x%08X len=0x%X", n, d, len))
                for g = 0, 0xFFFF do
                    local cmd = base + g
                    if not GENERIC[cmd] then
                        local r = sgn(sc_ioctl(uint64(fd), uint64(cmd), arg))
                        calls = calls + 1
                        if r ~= -1 then
                            hits[#hits + 1] = cmd
                            print(string.format("    HIT %-14s cmd=0x%08X ret=%d", n, cmd, r))
                        end
                    end
                end
            end
        end
        print(string.format("[B] %-14s calls=%d hits=%d", n, calls, #hits))
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== PROBE 279a COMPLETE ===")
