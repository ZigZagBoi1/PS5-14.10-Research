-- CRASH_CLASS: LOW
-- PROBE 473b: name the first twelve regions
--
-- Context: 473a died twice around walk index 4-5 while feeding region starts
-- to the gic ioctl. This probe only reads sys 674 and prints records 0-11
-- (start, end, prot, name). No ioctl, no writes to anyone's memory: pure map
-- read, so the killer's kind is on the record before anything touches it.

print("=== PROBE 473b: the first twelve regions ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
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

for i = 0, math.min(count - 1, 11) do
    local rec = buf + i * STRIDE
    local ok_s, s = pcall(function() return memory.read_qword(rec) end)
    local ok_e, e = pcall(function() return memory.read_qword(rec + 8) end)
    local prot = rd(rec + 0x18)
    local nm = {}
    for k = 0, 31 do
        local c = rb(rec + 0x20 + k)
        if c == 0 then break end
        if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
    end
    print(string.format("  [%2d] %s - %s prot=0x%X %s",
        i, tostring(ok_s and s or "?"), tostring(ok_e and e or "?"), prot, table.concat(nm)))
end

print("")
print("=== PROBE 473b COMPLETE ===")
