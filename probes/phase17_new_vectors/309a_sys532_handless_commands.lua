-- CRASH_CLASS: LOW
-- PROBE 309a: the sys 532 commands that need no handle
--
-- 307a/308a: 0x18-0x1D want a packed handle (checksum confirmed: forging one
-- replaced 0x800D0204 with 0x800D0203). Two commands answered without one:
--   0x1E wrote 3, and 0x2F wrote 0.
-- 0x20 answered 0x800D0208 (INVALID_SIZE) at size 0x40 and 0x800D0202
-- (NULL_PTR) at size 4, so it has its own size rule - the dossier says a fixed
-- 0x30 config query.
-- This probe maps 0x20's size window and watches what 0x1E and 0x2F write.

print("=== PROBE 309a: SYS 532 HANDLELESS COMMANDS ===")

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
local function wd(addr, v)
    pcall(function() memory.write_dword(addr, v) end)
end

local sc = make_syscall(532)
local out = memory.alloc(0x1000)
local inp = memory.alloc(0x1000)
local function fill(addr, v)
    for i = 0, 0xFFF, 4 do wd(addr + i, v) end
end

local function call(cmd, sub, size)
    fill(out, 0x41414141)
    fill(inp, 0x42424242)
    local okc, r = pcall(function()
        return sc(uint64(cmd), uint64(sub), uint64(out), uint64(inp), uint64(size), uint64(0))
    end)
    if not okc then return nil end
    return sgn(r)
end

print("--- A: cmd 0x20 size window ---")
for _, size in ipairs({ 0, 4, 0x10, 0x20, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x40 }) do
    local ret = call(0x20, 0, size)
    if ret == nil then print(string.format("  size 0x%X: DEAD", size)) break end
    print(string.format("  size 0x%X: ret=%d out0=0x%08X out4=0x%08X", size, ret, rd(out), rd(out + 4)))
end

print("")
print("--- B: cmd 0x1E across subs ---")
for _, sub in ipairs({ 0, 1, 2, 3, 4, 8, 0x10 }) do
    local ret = call(0x1E, sub, 0x40)
    if ret == nil then print(string.format("  sub 0x%X: DEAD", sub)) break end
    print(string.format("  sub 0x%X: ret=%d out0=0x%08X out4=0x%08X", sub, ret, rd(out), rd(out + 4)))
end

print("")
print("--- C: cmd 0x2F across sizes ---")
for _, size in ipairs({ 0, 4, 0x10, 0x40, 0x800 }) do
    local ret = call(0x2F, 0, size)
    if ret == nil then print(string.format("  size 0x%X: DEAD", size)) break end
    print(string.format("  size 0x%X: ret=%d out0=0x%08X", size, ret, rd(out)))
end

print("=== DONE ===")
