-- CRASH_CLASS: MEDIUM
-- PROBE 307a: which argument does sys 532 call null?
--
-- 87a (first execution, 2026-10-22) showed sys 532 IS implemented on 14.10:
--   commands 0x18-0x1E, 0x20, 0x2F return 0 and write 0x800D0202 (NULL_PTR)
--   commands 0x00, 0x03, 0x05, 0x10 return -1 (privilege check failed)
-- so 532 is not a dead entry, and the unprivileged commands are failing on a
-- pointer we did not supply. This probe varies arg1 (sub-command / handle) and
-- the size, and maps which command codes give a Sony error versus a raw -1.

print("=== PROBE 307a: SYS 532 ARGUMENT MAP ===")

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

local sc = make_syscall(532)
local out = memory.alloc(0x1000)
local inp = memory.alloc(0x1000)
local function fill(addr, v)
    for i = 0, 0xFFF, 4 do memory.write_dword(addr + i, v) end
end

local function call(cmd, sub, size)
    fill(out, 0x41414141)
    fill(inp, 0x42424242)
    local okc, r = pcall(function()
        return sc(uint64(cmd), uint64(sub), uint64(out), uint64(inp), uint64(size), uint64(0))
    end)
    if not okc then return nil, "PCALL-FAIL" end
    return sgn(r), rd(out)
end

print("--- A: command codes, sub=0, size=0x40 ---")
local cmds = { 0x00, 0x01, 0x02, 0x03, 0x05, 0x07, 0x08, 0x0A, 0x0B, 0x0D,
               0x0E, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20, 0x2C,
               0x2F, 0x31, 0x36, 0x41, 0x45 }
for _, cmd in ipairs(cmds) do
    local ret, first = call(cmd, 0, 0x40)
    if ret == nil then
        print(string.format("  cmd 0x%02X: DEAD (%s)", cmd, first))
        break
    end
    print(string.format("  cmd 0x%02X: ret=%d out0=0x%08X", cmd, ret, first))
end

print("")
print("--- B: sub-command sweep on 0x18, size=0x40 ---")
for _, sub in ipairs({ 0, 1, 2, 4, 8, 0x10, 0x40, 0x100, 0x10000, 0xFFFFFFFF }) do
    local ret, first = call(0x18, sub, 0x40)
    if ret == nil then print(string.format("  sub 0x%X: DEAD", sub)) break end
    print(string.format("  sub 0x%X: ret=%d out0=0x%08X", sub, ret, first))
end

print("")
print("--- C: size sweep on 0x18, sub=0 ---")
for _, size in ipairs({ 0, 4, 8, 0x18, 0x30, 0x40, 0x800, 0x801, 0x818, 0x819, 0x1000, 0xFFFFFFFF }) do
    local ret, first = call(0x18, 0, size)
    if ret == nil then print(string.format("  size 0x%X: DEAD", size)) break end
    print(string.format("  size 0x%X: ret=%d out0=0x%08X", size, ret, first))
end

print("=== DONE ===")
