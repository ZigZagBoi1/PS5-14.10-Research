-- CRASH_CLASS: HIGH
-- PROBE 538a: which admitted command writes which MSR
--
-- Context: 625 with value 1 returns 0 for commands 17..20 and -1 for 21..23;
-- with value 0 the 21..23 set returns 0, so those three are the zero-guard
-- blocks that touch no hardware. 626 answers only command 5 with domain 0
-- (ret=0, value 0), and its dossier says that block reads
-- 0xc0010241+2*index (index<=3) or 0xc0010189+2*index and copies 8 bytes out.
--
-- So: write a distinct value through each of 17..20, then read index 0..7
-- back through 626 and look for the values.

print("=== PROBE 538a: SYS 625 MSR MAP ===")
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
        tag, cmd, dom, idx, ret, tostring(rdq(N(OUT)))))
end

for c = 1, 6 do read("[pre]", c, 0, 0) end

local vals = {17, 18, 19, 20}
for i = 1, 4 do
    local cmd = vals[i]
    local v = i * 0x11
    local ret = -999
    pcall(function()
        ret = N(sc625(uint64(cmd), uint64(0), uint64(0), uint64(v)))
    end)
    print(string.format("[write] 625 cmd=%d dom=0 idx=0 val=%X ret=%d", cmd, v, ret))
end

for idx = 0, 7 do read("[post]", 5, 0, idx) end
for c = 1, 6 do read("[post-d1]", c, 1, 0) end
print("=== DONE ===")
