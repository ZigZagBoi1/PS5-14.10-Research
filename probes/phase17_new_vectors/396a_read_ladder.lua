-- CRASH_CLASS: LOW
-- PROBE 396a: which step of the setup the last two runs died in
--
-- 394a ran 593 and a 16-byte read of eboot text and finished in 0.047 s. 393a and
-- 395a printed their banner and then nothing, on the same two operations, and the
-- console powered off. The only functional difference before the missing print in
-- 395a is that it reads 0x40000 bytes for the gadget scan instead of 16, and that it
-- touches syscall.syscall_address at the top.
--
-- This walks the steps one at a time, printing after each, with no mmap, no thread
-- and no device:
--   [A] banner                      [E] read 4,096 bytes
--   [B] syscall.syscall_address     [F] read 65,536 bytes
--   [C] syscall 593 -> base         [G] read 262,144 bytes
--   [D] read 16 bytes               [H] scan that buffer for EB FE
-- A death at any step names the step.

print("=== PROBE 396a: READ LADDER ===")

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
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end

print("[A] banner")
print(string.format("[B] syscall_address type=%s", type(syscall.syscall_address)))
local ga = 0
pcall(function() ga = to_num(syscall.syscall_address) end)
print(string.format("[B] syscall_address=0x%X", ga))

local sc_info = make_syscall(593)
print("[C] calling 593")
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
print(string.format("[C] 593 rv=%d base=0x%X", rv, base))
if base <= 0 then print("no base") print("=== 396a DONE ===") return end

local function read_and_report(n, tag)
    print(string.format("[%s] reading %d bytes", tag, n))
    local ok, s = pcall(function() return memory.read_buffer(base, n) end)
    if ok and type(s) == "string" then
        local h = ""
        for i = 1, math.min(8, #s) do h = h .. string.format("%02X", string.byte(s, i)) end
        print(string.format("[%s] ok len=%d first=%s", tag, #s, h))
        return s
    end
    print(string.format("[%s] failed ok=%s", tag, tostring(ok)))
    return nil
end

read_and_report(16, "D")
read_and_report(4096, "E")
read_and_report(65536, "F")
local big = read_and_report(262144, "G")

print("[H] scanning for EB FE")
if big then
    local found = {}
    local i = 1
    while i < #big - 1 do
        local a, b = big:byte(i, i + 1)
        if a == 0xEB and b == 0xFE then found[#found + 1] = base + i - 1; if #found >= 4 then break end end
        i = i + 1
    end
    print(string.format("[H] matches=%d", #found))
    for _, a in ipairs(found) do print(string.format("    0x%X", a)) end
end

print("")
print("=== 396a DONE ===")
