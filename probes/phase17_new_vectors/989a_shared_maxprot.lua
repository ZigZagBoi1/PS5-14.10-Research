-- CRASH_CLASS: HIGH
-- PROBE 989a: does a MAP_SHARED mapping keep a wider max_protection than an anon one?
--
-- Finding 99 measured that mmap strips PROT_EXEC and that 548 op2 cannot add it back,
-- but every sample was a MAP_PRIVATE anonymous page. Stock FreeBSD derives
-- max_protection from the mapping kind, so a file-backed MAP_SHARED mapping is the
-- untested case. sys 547 is the protection oracle (it answers for GPU and heap
-- mappings) and is used here before and after the protect call.

print("=== PROBE 989a: MAP_SHARED MAX_PROT ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function fmt(v) local h,l=hi_lo(v) if h==0 then return string.format("0x%X", l) end return string.format("0x%X%08X", h,l) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return to_num(v) else return -1 end end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local out = memory.alloc(0x40)
local function prot_of(a)
    wq(out,0) wq(out+8,0) wq(out+0x10,0)
    local ok, rv = pcall(function() return mk(547)(uint64(a), uint64(a+0x4000), uint64(out)) end)
    if not ok then return "PCALL-FAIL" end
    local h,l = hi_lo(rv)
    return string.format("ret=0x%X q0=0x%X q1=0x%X q2=0x%X", l, to_num(memory.read_qword(out)), to_num(memory.read_qword(out+8)), to_num(memory.read_qword(out+0x10)))
end
local entry = memory.alloc(0x40)
local function call548(addr, prot, op)
    wq(entry,0) wq(entry+8,0) wq(entry+0x10,0) wq(entry+0x18,0) wq(entry+0x20,0)
    wq(entry, addr)
    wq(entry+8, 0)
    wq(entry+0x10, 0x4000)
    wb(entry+0x18, prot)
    wd(entry+0x1C, op)
    local ok, rv = pcall(function() return mk(548)(uint64(0),uint64(0),uint64(addr_of(entry)),uint64(1),uint64(0)) end)
    if not ok then return "PCALL-FAIL" end
    return fmt(rv)
end

-- [B] control: anonymous private mapping
print("[B] control: anon MAP_PRIVATE prot=3")
local anon = to_num(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    mmap -> 0x%X  %s", anon, prot_of(anon)))
if anon > 0 then
    print(string.format("    548 op2 prot=7 -> %s  now %s", call548(anon,7,2), prot_of(anon)))
end

-- [C] file-backed MAP_SHARED
print("[C] file-backed MAP_SHARED (writable path from the loader)")
local path = "/av_contents/content_tmp/mx989.bin"
local fd = to_num(mk(5)(uint64(0),uint64(0)))
-- open(5) needs a string argument; the pipe marshaller accepts Lua strings
local okf, rvf = pcall(function() return mk(5)(path, uint64(0x602), uint64(0x1B6)) end)
if not okf then print("    open PCALL-FAIL") else print(string.format("    open -> %s", fmt(rvf))) end
local fdn = to_num(okf and rvf or -1)
print(string.format("    fd=%d", fdn))
if fdn > 0 then
    print(string.format("    ftruncate -> %s", fmt(mk(480)(uint64(fdn), uint64(0x4000)))))
    local sh = to_num(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(1),uint64(fdn),uint64(0)))
    print(string.format("    mmap MAP_SHARED prot=3 -> 0x%X  %s", sh, prot_of(sh)))
    if sh > 0 then
        wb(sh, 0xC3)
        print(string.format("    write 0xC3 readback=0x%X", rb(sh)))
        print(string.format("    548 op2 prot=7 -> %s", call548(sh,7,2)))
        print(string.format("    after: %s", prot_of(sh)))
        print(string.format("    548 op1 prot=7 -> %s", call548(sh,7,1)))
        print(string.format("    after op1: %s", prot_of(sh)))
    end
end

-- [D] GPU page through 588
print("[D] GPU page: 588 attribute call, protection read before/after")
local gpu = to_num(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    mmap -> 0x%X  %s", gpu, prot_of(gpu)))
if gpu > 0 then
    local rec = memory.alloc(0x20)
    wq(rec,0) wq(rec+8,0) wq(rec+0x10,0) wq(rec+0x18,0)
    wd(rec, 7)
    local ok, rv = pcall(function() return mk(588)(uint64(gpu), uint64(0x4000), uint64(addr_of(rec))) end)
    print(string.format("    588(prot@0=7) -> %s", ok and fmt(rv) or "PCALL-FAIL"))
    print(string.format("    after: %s", prot_of(gpu)))
    wd(rec, 0) wb(rec+0x18, 7)
    local ok2, rv2 = pcall(function() return mk(588)(uint64(gpu), uint64(0x4000), uint64(addr_of(rec))) end)
    print(string.format("    588(prot@0x18=7) -> %s", ok2 and fmt(rv2) or "PCALL-FAIL"))
    print(string.format("    after: %s", prot_of(gpu)))
end

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
