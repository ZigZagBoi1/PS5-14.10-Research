-- CRASH_CLASS: MODERATE
-- PROBE 475g: does the 0xf0000000 window store what is written?
--
-- Context: 475f read zeros from the map's eboot record and 0xf0000000+0x1000/
-- +0x2000, then "wrote" the zeros back with ok=true. Zeros read back either
-- because the window is a real zeroed mapping or because the Lua binding
-- silently stubs bad addresses. A distinctive value tells the two apart. A
-- control write to a page this probe owns proves the read/write path itself.

print("=== PROBE 475g: is 0xf0000000 real memory? ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) % 0x100000000 end
    return -1
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end

print("[A] control: our own page")
local mine = memory.alloc(0x100)
wd(mine, 0xCAFEBABE)
print(string.format("    wrote CAFEBABE at 0x%X, read %08X", to_num(mine), rd(mine)))

print("")
print("[B] distinctive writes into the eboot window, read straight back")
local BASE = 0xF0000000
for i, off in ipairs({0x0, 0x1000, 0x2000, 0x4000}) do
    local a = BASE + off
    local before = rd(a)
    local ok = wd(a, 0xCAFEBABE + i)
    local after = rd(a)
    print(string.format("    0x%08X  before=%08X write ok=%s after=%08X  %s", a, before,
        tostring(ok), after, after == (0xCAFEBABE + i) % 0x100000000 and "STORED" or "not stored"))
end

print("")
print("[C] read back from a fresh address one page higher")
print(string.format("    0xF0008000 = %08X", rd(0xF0008000)))

print("")
print("=== PROBE 475g COMPLETE ===")
