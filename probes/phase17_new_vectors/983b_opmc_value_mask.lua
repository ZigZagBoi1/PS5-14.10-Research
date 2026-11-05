-- CRASH_CLASS: MODERATE
-- PROBE 983b: what does 566 actually store — value mask, slot width, readback form
--
-- 983a showed slots 0..5 accept 566(tid,idx,val) and return the value through
-- 567, but with the low byte dropped (0x...1111 came back 0x...1100), and idx>=6
-- answers with a 16-bit status instead. This measures the mask precisely.

print("=== PROBE 983b: OPMC VALUE MASK ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end return -999 end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rv(ok,v) if not ok then return "PCALL-FAIL" end local h,l=hi_lo(v) return string.format("0x%08X_%08X",h,l) end

local pid = to_num(mk(20)())
local tb = memory.alloc(8) wq(tb,0)
pcall(function() return mk(432)(uint64(tb)) end)
local tid = rq(tb)
print(string.format("[A] pid=%u tid=0x%X", pid, tid))

local out = memory.alloc(0x40)
local function roundtrip(idx, val)
    local okw, w = pcall(function() return mk(566)(uint64(tid),uint64(idx),uint64(val)) end)
    wq(out, 0xEEEEEEEEEEEEEEEE)
    local okr, r = pcall(function() return mk(567)(uint64(tid),uint64(idx),uint64(out)) end)
    return rq(out), rv(okw,w), rv(okr,r)
end

print("[B] masks on slot 0")
local vals = {
    {0xFFFFFFFFFFFFFFFF, "all ones"},
    {0x00000000FFFFFFFF, "low dword"},
    {0x000000000000FFFF, "low word"},
    {0x00000000000000FF, "low byte"},
    {0x0000000000000100, "bit 8"},
    {0x0000000000FF0000, "byte 2"},
    {0x000000FF00000000, "byte 4"},
    {0xDEADBEEFCAFEBABE, "pattern"},
    {0x0000000000000001, "one"},
    {0x0000000000000000, "zero"},
}
for _,p in ipairs(vals) do
    local got, w, r = roundtrip(0, p[1])
    print(string.format("    w=0x%016X -> 0x%016X  (%s)  wr=%s rr=%s", p[1], got, p[2], w, r))
end

print("[C] the same pattern on every slot 0..5")
for idx=0,5 do
    local got = roundtrip(idx, 0xDEADBEEFCAFEBABE)
    print(string.format("    idx=%d -> 0x%016X", idx, got))
end

print("[D] does a later read of slot 0 change when another slot is written")
roundtrip(0, 0x1111222233334444)
local a = roundtrip(3, 0xAAAABBBBCCCCDDDD)
local got0 = roundtrip(0, 0x1111222233334444)
print(string.format("    slot3 wrote -> slot0 now 0x%016X", got0))

print("[E] 567 with a null out pointer and with a kernel out pointer")
print(string.format("    567(tid,0,NULL)      -> %s", rv(pcall(function() return mk(567)(uint64(tid),uint64(0),uint64(0)) end))))
print(string.format("    567(tid,0,0xFFFFFFFF80000000) -> %s", rv(pcall(function() return mk(567)(uint64(tid),uint64(0),uint64(0xFFFFFFFF80000000)) end))))
print(string.format("    566(tid,0,0) again   -> %s", rv(pcall(function() return mk(566)(uint64(tid),uint64(0),uint64(0)) end))))

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
