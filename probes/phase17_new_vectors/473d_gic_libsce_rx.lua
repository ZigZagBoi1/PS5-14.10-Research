-- CRASH_CLASS: MODERATE (the expected outcome is a process death)
-- PROBE 473d: the libSceFios2 RX page into the gic ioctl, alone
--
-- Context: 473a died at walk index 4 in two different ASLR layouts, and 473b
-- named that record: libSceFios2.prx, prot=0x5 (RX). 473c fed the game's own
-- prot=0x5 executable page (a different mapping) and the call survived with
-- the constant tag, so "prot=0x5" alone is not the trigger - the system
-- library's page is. This probe selects by name and print-before-call, so a
-- death attributes to that one mapping.

print("=== PROBE 473d: the libSceFios2 RX page, one call ===")
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
print(string.format("regions: %d", count))

local target, tidx, tname
for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    local nm = {}
    for k = 0, 31 do
        local c = rb(rec + 0x20 + k)
        if c == 0 then break end
        if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
    end
    local name = table.concat(nm)
    if name:find("libSceFios2") and rd(rec + 0x18) == 0x5 then
        local ok_s, s = pcall(function() return memory.read_qword(rec) end)
        target = ok_s and s or nil
        tidx = i
        tname = name
        break
    end
end
if not target then
    print("[1] no libSceFios2 prot=0x5 region; aborting")
    return
end
print(string.format("[1] target: record %d %s %s", tidx, tostring(target), tname))
print(string.format("[1] neighbours:"))
for i = math.max(0, tidx - 1), math.min(count - 1, tidx + 1) do
    local rec = buf + i * STRIDE
    local ok_s, s = pcall(function() return memory.read_qword(rec) end)
    local nm = {}
    for k = 0, 31 do
        local c = rb(rec + 0x20 + k)
        if c == 0 then break end
        if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
    end
    print(string.format("    [%3d] %s prot=0x%X %s", i, tostring(ok_s and s or "?"),
        rd(rec + 0x18), table.concat(nm)))
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("[1] fd=" .. fd)
if fd < 0 then
    print("=== PROBE 473d ABORTED ===")
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
print(string.format("[3] survived: ret=%d words=%08X %08X %08X %08X",
    sgn(r), rd(page), rd(page + 4), rd(page + 8), rd(page + 12)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 473d COMPLETE ===")
