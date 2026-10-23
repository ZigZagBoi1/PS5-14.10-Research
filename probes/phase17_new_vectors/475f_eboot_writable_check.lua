-- CRASH_CLASS: HIGH
-- PROBE 475f: is the 0xf0000000 eboot mapping actually writable from userland?
--
-- Context: the gic handler (13.60 text 0xab80e0) copies 0x470 bytes in from q0,
-- runs a device request, and copies 0x470 bytes back to q0 through the kernel's
-- fault-handled copyout. Aiming q0 at the map's eboot record (0xf0000000, prot
-- 0x3) killed the game and stalled console TCP for about a minute. Two readings
-- fit that: (a) the copyout faulted in kernel mode in a way recovery missed, or
-- (b) the mapping really is writable user memory holding the running image, so
-- the 0x470-byte write corrupted eboot and the process died of its own damage.
--
-- This probe separates them without the ioctl: read the eboot base, write the
-- same values straight back, and re-read. A self-write that survives says the
-- page is ordinary writable user memory - the gic case is then self-corruption.
-- A self-write that kills says the mapping faults on write, and the gic crash
-- is a kernel-side fault. Either answer is one run.

print("=== PROBE 475f: is the eboot mapping writable? ===")
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
local BASE = 0xF0000000

print(string.format("[A] read 8 dwords at 0x%X", BASE))
local vals = {}
for i = 0, 7 do
    vals[i] = rd(BASE + i * 4)
    print(string.format("    +0x%02X = %08X", i * 4, vals[i]))
end

print("")
print("[B] write the same values back (read-modify-write, identical content)")
for i = 0, 7 do
    local ok = wd(BASE + i * 4, vals[i])
    print(string.format("    +0x%02X write ok=%s readback=%08X", i * 4, tostring(ok), rd(BASE + i * 4)))
end

print("")
print("[C] same at +0x1000 and +0x2000")
for _, off in ipairs({0x1000, 0x2000}) do
    local a = BASE + off
    local v = rd(a)
    local ok = wd(a, v)
    print(string.format("    0x%X  was=%08X write ok=%s now=%08X", a, v, tostring(ok), rd(a)))
end

print("")
print("=== PROBE 475f COMPLETE ===")
