-- CRASH_CLASS: HIGH
-- PROBE 983a: the opmc store/read pair (566/567) — is the slot index bounded?
--
-- 327a established that 566(tid, idx, value) returns 0 and 567(tid, idx, out)
-- returns the same value at idx 0 and 1, while idx 6 returns -1. If the index is
-- checked against six slots we have a fixed six-qword window; if it is not, the
-- same call writes outside the array and the readback tells us what it hit.

print("=== PROBE 983a: OPMC INDEX BOUNDS ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function show(tag, ok, rv) if not ok then print("  ["..tag.."] PCALL-FAIL") return -1 end local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X",tag,h,l)) return l end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local tb = memory.alloc(8) wq(tb,0)
show("thr_self", pcall(function() return mk(432)(uint64(tb)) end))
local tid = rq(tb)
print(string.format("    tid=0x%X", tid))

-- [B] in-range slots, value written then read back
print("[B] slots 0..7 through 566/567")
local out = memory.alloc(0x40) 
for i=0,7 do
    local v = 0x1111000000000000 + i*0x1111
    local okw = pcall(function() return mk(566)(uint64(tid),uint64(i),uint64(v)) end)
    wq(out+i*8, 0xEEEEEEEEEEEEEEEE)
    local okr, rv = pcall(function() return mk(567)(uint64(tid),uint64(i),uint64(out+i*8)) end)
    local got = rq(out+i*8)
    print(string.format("    idx=%d w_ok=%s r_ok=%s got=0x%X", i, tostring(okw), tostring(okr), got))
end

-- [C] out of range indices: does the store happen and where does the read land
print("[C] out of range indices")
local probes = {8, 9, 16, 64, 0x100, 0x1000, 0x7FFFFFFF, 0xFFFFFFFF}
for _,idx in ipairs(probes) do
    local okw = pcall(function() return mk(566)(uint64(tid),uint64(idx),uint64(0xA5A5A5A500000000 + idx)) end)
    wq(out, 0xEEEEEEEEEEEEEEEE)
    local okr = pcall(function() return mk(567)(uint64(tid),uint64(idx),uint64(out)) end)
    local got = rq(out)
    print(string.format("    idx=0x%X w_ok=%s r_ok=%s got=0x%X", idx, tostring(okw), tostring(okr), got))
end

-- [D] selector forms: does 563/564/565 take a tid or a selector, and does a bad
-- selector change the 566 target
print("[D] 563/564/565 selectors")
for _,sel in ipairs({0, 1, 0x18EF9}) do
    local a = show(string.format("563(sel=0x%X)", sel), pcall(function() return mk(563)(uint64(sel)) end))
    local b = show(string.format("564(sel=0x%X)", sel), pcall(function() return mk(564)(uint64(sel)) end))
    local c = show(string.format("565(sel=0x%X)", sel), pcall(function() return mk(565)(uint64(sel)) end))
end
print("[D] 565(tid, idx, val) then 567 readback")
for _,idx in ipairs({0,1,2}) do
    local okw = pcall(function() return mk(565)(uint64(tid),uint64(idx),uint64(0x7777000000000000+idx)) end)
    wq(out, 0xEEEEEEEEEEEEEEEE)
    local okr = pcall(function() return mk(567)(uint64(tid),uint64(idx),uint64(out)) end)
    print(string.format("    idx=%d 565_ok=%s got=0x%X", idx, tostring(okw), rq(out)))
end

-- [E] the same calls with a foreign tid and with tid 0
print("[E] foreign tid and tid 0")
for _,t in ipairs({0, 1, 0x7FFFFFFF}) do
    local okw = pcall(function() return mk(566)(uint64(t),uint64(0),uint64(0xB0B00000B0B00000)) end)
    wq(out, 0xEEEEEEEEEEEEEEEE)
    local okr = pcall(function() return mk(567)(uint64(t),uint64(0),uint64(out)) end)
    print(string.format("    tid=0x%X w_ok=%s r_ok=%s got=0x%X", t, tostring(okw), tostring(okr), rq(out)))
end

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
