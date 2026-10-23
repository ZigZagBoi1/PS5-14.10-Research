-- CRASH_CLASS: MODERATE (a process death confirms the finding)
-- PROBE 473f: is 0xf0000000 (eboot.bin) the killer, alone?
--
-- Context: 473e walked the first sixteen region starts through the gic ioctl
-- 0xC0104701 and died immediately after printing index 4, the eboot mapping
-- at 0xf0000000, prot=0x3. Everything below it survived and classified
-- cleanly, and 473c/473d proved neither the game's text page nor a system
-- library's RX page kills. This probe makes that one call by itself, with the
-- address printed first, so the death is attributable to 0xf0000000 and
-- nothing else.
--
-- The classification seen so far (word1 = class, word3 = status):
--   0x1f830000 prot=0x5 executable   -> class 0, status 0x816800FF
--   0x1fe30000 prot=0x1 executable   -> class 0, status 0x816800FF
--   0x20030000 prot=0x3 executable   -> class 0, status 0
--   0x20174000 prot=0x3 executable   -> class 0, status 0

print("=== PROBE 473f: the eboot address, one call ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return 0
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end
    return 0
end

local sc674 = make_syscall(674)
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
for i = 0, 12, 4 do wd(countp + i, 0) end
sgn(sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000)))
local count = rd(countp)
if count < 0 or count > MAX then count = 0 end

-- find the eboot record by name, so the address is the map's own
local target, tidx
for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    local nm = {}
    for k = 0, 31 do
        local c = rb(rec + 0x20 + k)
        if c == 0 then break end
        if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
    end
    if table.concat(nm):find("eboot") then
        local ok_s, s = pcall(function() return memory.read_qword(rec) end)
        target = ok_s and s or nil
        tidx = i
        print(string.format("[1] eboot record %d %s prot=0x%X", i, tostring(target), rd(rec + 0x18)))
        break
    end
end
if not target then
    print("[1] no eboot record; aborting")
    return
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("[1] fd=" .. fd)
if fd < 0 then
    print("=== PROBE 473f ABORTED ===")
    return
end

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do wd(page + off, 0) end
local ok_t, h, l = pcall(function() return target.h, target.l end)
if ok_t and h then
    wq(page, uint64(string.format("0x%X%08X", h % 0x100000000, l % 0x100000000)))
else
    wq(page, uint64(string.format("0x%X", to_num(target))))
end
wq(page + 8, uint64(0))

print("[2] >>> calling 0xC0104701 with q0 = " .. tostring(target))
local r = sc_ioctl(uint64(fd), uint64(0xC0104701), uint64(page))
print(string.format("[3] survived: ret=%d -> %08X %08X %08X %08X", sgn(r),
    rd(page), rd(page + 4), rd(page + 8), rd(page + 12)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 473f COMPLETE ===")
