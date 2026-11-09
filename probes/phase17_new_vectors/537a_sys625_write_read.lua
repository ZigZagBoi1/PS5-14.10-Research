-- CRASH_CLASS: HIGH
-- PROBE 537a: does sys 625 write an MSR that sys 626 can read back
--
-- Context: 536a called 625(command,0,0,0) for commands 1..22 and saw ret=-1
-- for 1..16 and ret=0 for 17..22 (and for 23, which the dossier's unsigned
-- range test also admits). The dossier's blocks split into guards that demand
-- value==0 (return 0 without touching hardware) and blocks that write a
-- caller-controlled 64-bit value to 0xc0010241+2*index / 0xc0010189+2*index.
--
-- This probe:
--   [1] writes the safe pass-through value 1 through every admitted command
--       with domain=0, index=0;
--   [2] reads back the matching MSR through 626 with its real five-argument
--       shape (command, domain, index, out, out2=0), which earlier probes
--       never used.
-- A read-back of 1 is proof that the write reached the register.

print("=== PROBE 537a: SYS 625 WRITE / 626 READ ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rdq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if not ok then return nil end
    if type(v) == "table" and v.h then return 0 end
    return tonumber(v) or 0
end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local sc625, sc626 = mk(625), mk(626)
local OUT = memory.alloc(0x40)

local function rdmsr(tag, cmd, dom, idx)
    wq(N(OUT), 0)
    local ret = -999
    pcall(function()
        ret = N(sc626(uint64(cmd), uint64(dom), uint64(idx), uint64(N(OUT)), uint64(0)))
    end)
    print(string.format("%s 626 cmd=%d dom=%d idx=%d ret=%d val=%s",
        tag, cmd, dom, idx, ret, tostring(rdq(N(OUT)))))
end

print("[baseline]")
for c = 1, 6 do rdmsr(" ", c, 0, 0) end

print("[write 1]")
for c = 17, 23 do
    local ret = -999
    pcall(function()
        ret = N(sc625(uint64(c), uint64(0), uint64(0), uint64(1)))
    end)
    print(string.format("  625 cmd=%d dom=0 idx=0 val=1 ret=%d", c, ret))
end
for c = 1, 6 do
    local ret = -999
    pcall(function()
        ret = N(sc625(uint64(c), uint64(0), uint64(0), uint64(1)))
    end)
    print(string.format("  625 cmd=%d dom=0 idx=0 val=1 ret=%d", c, ret))
end

print("[read back]")
for c = 1, 6 do rdmsr(" ", c, 0, 0) end
print("=== DONE ===")
