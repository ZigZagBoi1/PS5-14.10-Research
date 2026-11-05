-- CRASH_CLASS: HIGH
-- PROBE 988a: the loader's own signal handler reports faults to the client
--
-- savedata/signal.lua registers a SIGILL/SIGBUS/SIGSEGV handler that pivots the stack
-- and writes 0x18 bytes (magic 0x13371337, signal code, faulting address) plus 0x100
-- bytes of mcontext to the client fd. If that report reaches the PC, a fault is a
-- measurement instead of a death — and the signal code separates "not mapped" from
-- "mapped but not accessible".

print("=== PROBE 988a: FAULT CHANNEL ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a)
    local ok, v = pcall(function() return to_num(memory.read_dword(a)) end)
    if ok then return string.format("ok 0x%X", v) end
    return "PCALL-FAIL"
end

print(string.format("[A] pid=%u", to_num(mk(20)())))
print("[B] control: a mapped heap page")
local p = memory.alloc(0x1000)
local ba = tonumber(tostring(p):match("0x(%x+)"), 16) or to_num(p)
print(string.format("    page=0x%X -> %s", ba, rd(ba)))

print("[C] unmapped user address 0x10")
print("    MARKER-C-BEFORE")
print("    0x10 -> " .. rd(0x10))
print("    MARKER-C-AFTER")

print("[D] kernel text candidate 0xFFFFFFFF8A9C0000")
print("    MARKER-D-BEFORE")
print("    0xFFFFFFFF8A9C0000 -> " .. rd(0xFFFFFFFF8A9C0000))
print("    MARKER-D-AFTER")

print("[E] kernel direct map 0xFFFF800000000000")
print("    MARKER-E-BEFORE")
print("    0xFFFF800000000000 -> " .. rd(0xFFFF800000000000))
print("    MARKER-E-AFTER")

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
