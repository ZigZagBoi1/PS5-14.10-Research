-- CRASH_CLASS: MODERATE
-- PROBE 381a: does a store to the GPU mappings really land
--
-- 380a wrote 0xE0300000 and reported success, then died on the read back, so
-- "write ok" is only worth something if a store to a bad address is reported as a
-- failure. This probe writes the dump area, then TrapData, and finishes with a
-- store to an address that is certainly not mapped: if that last one takes the
-- process, every earlier "ok" was a real store. It never reads device memory.

print("=== PROBE 381a: GPU WRITE CONTROL ===")
print("")

local function try_write(tag, addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    print(string.format("[%s] 0x%X <- 0x%X  ok=%s", tag, addr, val, tostring(ok)))
end

try_write("A dump-area", 0xE0300000, 0x11111111)
try_write("B trap-data", 0x4000 + 0x100, 0x22222222)
try_write("C trap-data2", 0x4000 + 0x104, 0x33333333)
print("[D] control: an address that is not mapped")
try_write("D unmapped", 0x7F0000000000, 0x44444444)
print("    still alive after the control")

print("")
print("=== 381a DONE ===")
