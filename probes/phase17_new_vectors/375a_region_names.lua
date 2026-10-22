-- CRASH_CLASS: LOW
-- PROBE 375a: what the VM map calls these regions
--
-- 374a scanned the eboot text region (0x494000 bytes) and found no reference to
-- any of the compositor socket names, so the game itself is not the client. The
-- 674 records carry a name at +0x20; this probe prints the name, range and
-- protection of every region the map reports so the next scan can be aimed at a
-- library instead of guessed at.

print("=== PROBE 375a: VM REGION NAMES ===")
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

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX)
local countp = memory.alloc(16)
for i = 0, STRIDE * 4 - 1, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
for i = 0, 12, 4 do pcall(function() memory.write_dword(countp + i, 0) end) end
make_syscall(674)(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
local count = rd(countp)
if count > MAX then count = MAX end
print(string.format("regions: %d", count))
print("")

local named = 0
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
    if #nm > 0 then
        named = named + 1
        print(string.format("  0x%X-0x%X p=0x%X %s", s, e, prot, nm))
    end
end
print("")
print(string.format("named regions: %d of %d", named, count))

print("")
print("=== 375a DONE ===")
