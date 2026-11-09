-- CRASH_CLASS: MODERATE
-- PROBE 482d: address the window commands with a real mapping inside the window
--
-- 482c proved mmap honours a hint at 0x2500000000. 481a showed 0x80108002,
-- 0x80108015 and 0xC010801A accept only q0 in [0x2500000000, 0x2558000001),
-- 16 KB aligned, q1 16 KB aligned non-zero. This is the first call with a
-- legal argument. Each call is followed by a dump of the target page so any
-- change is visible even if the return is 0.
print("=== PROBE 482d: dmem window command with a legal address ===")
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
local function cast64(n)
    return uint64(string.format("0x%08X%08X", math.floor(n / 4294967296) % 4294967296, n % 4294967296))
end
local function parts(r)
    if type(r) == "table" and r.h then return to_num(r.h), to_num(r.l) end
    local x = to_num(r)
    return math.floor(x / 4294967296), x % 4294967296
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wr(a, v)
    return pcall(function() memory.write_dword(a, v) end)
end
local function dump(tag, addr, n)
    local t = {}
    for i = 0, n - 1 do
        local v = rd(addr + i * 4)
        t[#t + 1] = v and string.format("%08X", v) or "????"
    end
    print("    " .. tag .. " " .. table.concat(t, " "))
end

local BASE = 0x2500000000
local SIZE = 0x40000

local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(str)
    local buf = memory.alloc(#str + 1)
    for i = 1, #str do pcall(function() memory.write_byte(buf + i - 1, string.byte(str, i)) end) end
    pcall(function() memory.write_byte(buf + #str, 0) end)
    return buf
end
local sc_mmap = make_syscall(477)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local ok, r = pcall(function()
    return sc_mmap(cast64(BASE), cast64(SIZE), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local hi, lo = 0, 0
if ok and r ~= nil then hi, lo = parts(r) end
print(string.format("    mmap(0x2500000000, 0x40000) ok=%s -> %08X%08X", tostring(ok), hi, lo))

-- fill the page with a pattern
for i = 0, 63 do wr(BASE + i * 4, 0xA5A50000 + i) end
dump("fill ", BASE, 8)

local function args(q0, q1, tail)
    wr(BASE + 0x100, q0 % 4294967296)
    wr(BASE + 0x104, math.floor(q0 / 4294967296))
    wr(BASE + 0x108, q1 % 4294967296)
    wr(BASE + 0x10C, math.floor(q1 / 4294967296))
    wr(BASE + 0x110, tail or 0)
    return BASE + 0x100
end

local nodes = { {"/dev/dmem1", "/dev/dmem1"}, {"/dev/dmem2", "/dev/dmem2"} }
local cmds = { 0x80108002, 0x80108015, 0xC010801A }
local shapes = {
    { "window+16K", BASE, 0x4000, 0 },
    { "window+64K", BASE, 0x10000, 0 },
    { "misaligned", BASE + 1, 0x4000, 0 },
    { "unaligned len", BASE, 0x10, 0 },
}

for _, node in ipairs(nodes) do
    local fd = -1
    local ook = pcall(function() fd = sgn(sc_open(uint64(put_str(node[1])), uint64(2), uint64(0))) end)
    local fdn = to_num(fd)
    print(string.format("[%s] open ok=%s fd=%s", node[1], tostring(ook), tostring(fdn)))
    if ook and fdn >= 0 and fdn < 1024 then
        for _, cmd in ipairs(cmds) do
            for _, sh in ipairs(shapes) do
                local p = args(sh[2], sh[3], sh[4])
                local cok, ret = pcall(function() return sc_ioctl(uint64(fdn), uint64(cmd), uint64(p)) end)
                local rv = "-"
                if cok then rv = tostring(to_num(ret)) end
                print(string.format("    cmd=%08X %-13s ret=%s", cmd, sh[1], rv))
                dump("page", BASE, 4)
            end
        end
        pcall(function() sc_close(uint64(fdn)) end)
    end
end

print("")
dump("final", BASE, 8)
print("=== PROBE 482d DONE ===")
