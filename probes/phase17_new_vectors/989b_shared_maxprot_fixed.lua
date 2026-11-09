-- CRASH_CLASS: HIGH
-- PROBE 989b: MAP_SHARED max_protection, with the 547 record read correctly
--
-- 989a called 547 with three arguments and got -1; the working shape from 98a is
-- 547(address, out), which fills three qwords. 989a also called 548 op1 on the shared
-- mapping, and op1 is unmap — that region disappeared. This run uses op2 only.

print("=== PROBE 989b: MAP_SHARED MAX_PROT (fixed) ===")
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
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) else return -1 end end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return to_num(v) else return -1 end end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local out = memory.alloc(0x40)
local function reg(a)
    wq(out,0) wq(out+8,0) wq(out+0x10,0)
    local ok, rv = pcall(function() return mk(547)(uint64(a), uint64(addr_of(out))) end)
    if not ok then return "PCALL-FAIL" end
    local h,l = hi_lo(rv)
    if l ~= 0 then return string.format("ret=%d", l) end
    return string.format("start=0x%X end=0x%X packed=0x%X", rq(out), rq(out+8), rq(out+0x10))
end
local entry = memory.alloc(0x40)
local function call548(addr, prot, op)
    wq(entry,0) wq(entry+8,0) wq(entry+0x10,0) wq(entry+0x18,0) wq(entry+0x20,0)
    wq(entry, addr) wq(entry+0x10, 0x4000) wb(entry+0x18, prot) wd(entry+0x1C, op)
    local ok, rv = pcall(function() return mk(548)(uint64(0),uint64(0),uint64(addr_of(entry)),uint64(1),uint64(0)) end)
    if not ok then return "PCALL-FAIL" end
    return fmt(rv)
end

print("[B] anon MAP_PRIVATE control")
local anon = to_num(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    mmap -> 0x%X  547: %s", anon, reg(anon)))
print(string.format("    548 op2 prot=7 -> %s", call548(anon,7,2)))
print(string.format("    547 now: %s", reg(anon)))

print("[C] file-backed MAP_SHARED")
local okf, rvf = pcall(function() return mk(5)("/av_contents/content_tmp/mx989b.bin", uint64(0x602), uint64(0x1B6)) end)
local fdn = to_num(okf and rvf or -1)
print(string.format("    open fd=%d", fdn))
if fdn > 0 then
    print(string.format("    ftruncate -> %s", fmt(mk(480)(uint64(fdn), uint64(0x4000)))))
    local sh = to_num(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(1),uint64(fdn),uint64(0)))
    print(string.format("    mmap MAP_SHARED prot=3 -> 0x%X  547: %s", sh, reg(sh)))
    if sh > 0 then
        wb(sh, 0xC3)
        print(string.format("    write 0xC3 -> readback=0x%X", rb(sh)))
        print(string.format("    548 op2 prot=7 -> %s", call548(sh,7,2)))
        print(string.format("    547 now: %s", reg(sh)))
        print(string.format("    548 op2 prot=5 -> %s", call548(sh,5,2)))
        print(string.format("    547 now: %s", reg(sh)))
    end
end

print("[D] GPU page through 588")
local gpu = to_num(mk(477)(uint64(0),uint64(0x10000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    mmap -> 0x%X  547: %s", gpu, reg(gpu)))
if gpu > 0 then
    local rec = memory.alloc(0x20)
    wq(rec,0) wq(rec+8,0) wq(rec+0x10,0) wq(rec+0x18,0)
    wd(rec, 7)
    local ok, rv = pcall(function() return mk(588)(uint64(gpu), uint64(0x4000), uint64(addr_of(rec))) end)
    print(string.format("    588(7@0) -> %s", ok and fmt(rv) or "PCALL-FAIL"))
    print(string.format("    547 now: %s", reg(gpu)))
end

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
