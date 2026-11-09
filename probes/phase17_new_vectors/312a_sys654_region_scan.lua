-- CRASH_CLASS: LOW
-- PROBE 312a: which of the process's own regions does sys 654 accept?
--
-- 311a supplied 654's documented five slots on a GPU mapping and every
-- operation returned -1. The contract in sys_654.md rejects an entry whose
-- object type byte at +0x9d is not 11, and the earlier 673 result is the same
-- wall: the GPU mapping's backing object is not type 11.
--
-- Zero length is the cheapest discriminator - the contract says zero length
-- succeeds once the entry checks pass - so this walks every region the process
-- map reports (674) and calls 654(region_start, 0, 0, 0, 0). A non -1 answer
-- names a region whose object type the handler accepts.

print("=== PROBE 312a: SYS 654 REGION SCAN ===")

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
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return 0
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end

local sc674 = make_syscall(674)
local sc654 = make_syscall(654)

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
local ok, ret = pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
if not ok then print("674 failed") return end
local count = rd(countp)
print(string.format("regions: %d", count))

local hits, aligned = 0, 0
for i = 0, count - 1 do
    local r = buf + i * STRIDE
    local start = to_num(rq(r))
    local stop = to_num(rq(r + 8))
    local prot = rd(r + 0x18)
    if start ~= 0 and stop > start then
        local isaligned = (start % 0x10000) == 0
        if isaligned then aligned = aligned + 1 end
        local okc, rv = pcall(function()
            return sc654(uint64(string.format("0x%X", start)), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        if okc then
            local v = sgn(rv)
            if v ~= -1 then
                hits = hits + 1
                print(string.format("  HIT region %d start=0x%X end=0x%X prot=0x%X aligned=%s -> ret=%d",
                    i, start, stop, prot, tostring(isaligned), v))
            end
        else
            print(string.format("  DEAD at region %d start=0x%X", i, start))
            break
        end
    end
end

print(string.format("scanned=%d aligned=%d hits=%d", count, aligned, hits))
print("=== DONE ===")
