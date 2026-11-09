-- CRASH_CLASS: LOW
-- PROBE 125f: Read native.lua and kernel.lua source
-- Need to understand how native.fcall dispatches before calling it

print("=== PROBE 125f: READ SOURCES ===")
print("pid=" .. tostring(syscall.getpid()))

-- Read native.lua
local f1 = io.open("/savedata0/native.lua", "r")
if f1 then
    print("--- NATIVE.LUA ---")
    print(f1:read("*a"))
    f1:close()
end

-- Read kernel.lua (lines 76-220 — the ipv6_kernel_rw parts)
local f2 = io.open("/savedata0/kernel.lua", "r")
if f2 then
    print("--- KERNEL.LUA ---")
    print(f2:read("*a"))
    f2:close()
end

print("=== PROBE 125f COMPLETE ===")
