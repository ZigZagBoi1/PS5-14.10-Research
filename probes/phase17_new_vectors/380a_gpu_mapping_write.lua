-- CRASH_CLASS: MODERATE
-- PROBE 380a: can a game process write the GPU's memory at all
--
-- 375a showed the graphics driver's mappings sit in the process at low addresses:
-- SceGnmTrapCode 0x0-0x4000, SceGnmTrapData 0x4000-0x8000, SceAgcDdid 0x8000,
-- SceGnmAcqRb 0x1148000-0x1328000, all with protection 0x33, and the driver's own
-- aperture at 0xE0000000 with 0x10. Reading a 0x33 region killed the process in
-- 376a. Writing is a different question: if these mappings accept stores from the
-- game, the command ring is reachable from userland, which is the start of every
-- GPU-driven memory primitive there is.
--
-- The order is least to most dangerous: the dump area (0xE0300000, plain RW, is a
-- diagnostic buffer), then TrapData (0x33, data the trap code reads), and nothing
-- touches TrapCode or the rings. Each step writes one marker dword and reads it
-- back; a fault takes the process and the last printed line names the step.

print("=== PROBE 380a: GPU MAPPING WRITE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local U = function(h, l) return uint64(string.format("0x%X%08X", h, l)) end

local function step(tag, addr)
    print(string.format("[%s] addr=0x%X", tag, addr))
    local okw = pcall(function() memory.write_dword(addr, 0xDEADBEEF) end)
    print(string.format("    write ok=%s", tostring(okw)))
    local okr, v = pcall(function() return memory.read_dword(addr) end)
    if okr then
        print(string.format("    read  ok=true value=0x%X", to_num(v)))
    else
        print("    read  ok=false")
    end
end

step("A dump-area", 0xE0300000)
step("B trap-data", 0x4000 + 0x100)
step("C acq-rb-tail", 0x1148000 + 0x1E0000 - 0x1000)

print("")
print("=== 380a DONE ===")
