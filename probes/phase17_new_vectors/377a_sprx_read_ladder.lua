-- CRASH_CLASS: MODERATE
-- PROBE 377a: which module data can be read at all
--
-- 376a died twice inside its first library reads, with no way to tell which one
-- faulted. This probe prints the region before it touches it, reads 256 bytes, and
-- stops at the first six readable .sprx data regions, so the last line printed
-- names the region that kills the process. A control read at the eboot text base
-- proves the read path works before any library is touched.

print("=== PROBE 377a: SPRX READ LADDER ===")
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
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return 0 end
local function rb(a) local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end return 0 end
local function hi(a) return math.floor(a / 4294967296) end
local function lo(a) return a % 4294967296 end

local info = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do pcall(function() memory.write_dword(info + i, 0) end) end
pcall(function() memory.write_dword(info, 0x160) end)
make_syscall(593)(uint64(0), uint64(to_num(info)))
local tl = rd(info + 0x108)
local eboot = hi(tl) * 4294967296 + lo(tl)

print(string.format("[A] control read at eboot 0x%X", eboot))
local ok, v = pcall(function() return memory.read_buffer(eboot, 0x100) end)
print(string.format("    read ok=%s len=%s first=%02X%02X%02X%02X", tostring(ok),
    ok and tostring(#v) or "-", ok and v:byte(1) or 0, ok and v:byte(2) or 0,
    ok and v:byte(3) or 0, ok and v:byte(4) or 0))

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX)
local countp = memory.alloc(16)
for i = 0, STRIDE * 4 - 1, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
for i = 0, 12, 4 do pcall(function() memory.write_dword(countp + i, 0) end) end
make_syscall(674)(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
local count = rd(countp)
if count > MAX then count = MAX end
print(string.format("[B] regions: %d", count))

local tried = 0
for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    local s = hi(rd(rec)) * 4294967296 + lo(rd(rec))
    local e = hi(rd(rec + 8)) * 4294967296 + lo(rd(rec + 8))
    local prot = rd(rec + 0x18)
    local name = {}
    for k = 0, 31 do
        local c = rb(rec + 0x20 + k)
        if c == 0 then break end
        if c >= 32 and c < 127 then name[#name + 1] = string.char(c) end
    end
    local nm = table.concat(name)
    if string.find(nm, ".sprx", 1, true) and prot == 1 and s >= 0x10000 and tried < 6 then
        tried = tried + 1
        print(string.format("    [%d] %-26s 0x%X-0x%X prot=0x%X", tried, nm, s, e, prot))
        local ok2, v2 = pcall(function() return memory.read_buffer(s, 0x100) end)
        if ok2 and v2 then
            print(string.format("        read ok, first bytes %02X %02X %02X %02X",
                v2:byte(1), v2:byte(2), v2:byte(3), v2:byte(4)))
        else
            print("        read FAILED")
        end
    end
end

print("")
print("=== 377a DONE ===")
