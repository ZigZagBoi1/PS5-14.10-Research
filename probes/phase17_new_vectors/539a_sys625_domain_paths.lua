-- CRASH_CLASS: HIGH
-- PROBE 539a: sys 625 with domain 1 and 2
--
-- Context: with domain 0 only commands 17..20 accept a nonzero value, and none
-- of them changes the register that 626 reads (0xc0010241+2*index, all zero).
-- The dossier's remaining write blocks all require domain 1..3: they clear or
-- reconfigure the six even MSRs 0xc0010230..0xc001023a, set bit 22 in them,
-- or write the indexed odd counters 0xc0010231+2*index. 626's domain 1/2 read
-- path (helper 0x8afc5000, low32 sign-extended) is the matching observer.
--
-- This probe takes a baseline, then writes value 1 through domain 1 and 2 for
-- each admitted command, then reads the counters back.

print("=== PROBE 539a: SYS 625 DOMAIN PATHS ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function out(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if not ok then return "ERR" end
    if type(v) == "table" and v.h then return 0 end
    return tonumber(v) or 0
end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local sc625, sc626 = mk(625), mk(626)
local OUT = memory.alloc(0x40)

local function read(tag, cmd, dom, idx)
    wq(N(OUT), 0)
    local ret = -999
    pcall(function()
        ret = N(sc626(uint64(cmd), uint64(dom), uint64(idx), uint64(N(OUT)), uint64(0)))
    end)
    print(string.format("%s 626 cmd=%d dom=%d idx=%d ret=%d val=%s",
        tag, cmd, dom, idx, ret, tostring(out(N(OUT)))))
end

print("[baseline]")
for idx = 0, 5 do read(" ", 4, 1, idx) end
for idx = 0, 5 do read(" ", 1, 2, idx) end

print("[write dom=1]")
for c = 17, 23 do
    local ret = -999
    pcall(function() ret = N(sc625(uint64(c), uint64(1), uint64(0), uint64(1))) end)
    print(string.format("  625 cmd=%d dom=1 idx=0 val=1 ret=%d", c, ret))
end
print("[write dom=2]")
for c = 17, 23 do
    local ret = -999
    pcall(function() ret = N(sc625(uint64(c), uint64(2), uint64(0), uint64(1))) end)
    print(string.format("  625 cmd=%d dom=2 idx=0 val=1 ret=%d", c, ret))
end

print("[after]")
for idx = 0, 5 do read(" ", 4, 1, idx) end
for idx = 0, 5 do read(" ", 1, 2, idx) end
print("=== DONE ===")
