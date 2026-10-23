-- CRASH_CLASS: LOW
-- PROBE 482c: does mmap honour a hint inside [0x2500000000, 0x2558000001)?
--
-- 482b: no existing region intersects that window (0 of 316). The dmem
-- commands 0x80108002/0x80108015/0xC010801A accept only a q0 in it, 16 KB
-- aligned, with q1 16 KB aligned non-zero. So the question is whether a
-- game can create such a mapping at all.
print("=== PROBE 482c: mmap hint in the device window ===")
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
    local hi = math.floor(n / 4294967296) % 4294967296
    local lo = n % 4294967296
    return uint64(string.format("0x%08X%08X", hi, lo))
end
local function parts(r)
    if type(r) == "table" and r.h then return to_num(r.h), to_num(r.l) end
    local x = to_num(r)
    return math.floor(x / 4294967296), x % 4294967296
end

local sc_mmap = make_syscall(477)
local hints = { 0x2500000000, 0x2520000000, 0x2550000000, 0x2500400000 }
local flags = { 0x33, 0x1002 }
for _, hint in ipairs(hints) do
    for _, fl in ipairs(flags) do
        local ok, r = pcall(function()
            return sc_mmap(cast64(hint), uint64(0x40000), uint64(fl),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok and r ~= nil then
            local hi, lo = parts(r)
            print(string.format("    hint=%08X%08X flags=%X -> %08X%08X",
                math.floor(hint / 4294967296), hint % 4294967296, fl, hi, lo))
        else
            print(string.format("    hint=%08X%08X flags=%X -> pcall failed",
                math.floor(hint / 4294967296), hint % 4294967296, fl))
        end
    end
end

print("")
print("[B] plain mmap, confirm the normal landing address")
local ok0, r0 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok0 and r0 ~= nil then
    local hi, lo = parts(r0)
    print(string.format("    no hint -> %08X%08X", hi, lo))
end
print("=== PROBE 482c DONE ===")
