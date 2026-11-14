-- CRASH_CLASS: MODERATE
-- PROBE 972a: the three handlers whose 13.60 bodies cannot return -1
--
-- 641 get_cpu_usage_proc   args { int32 id, uint32 pad, uintptr out }
-- 642 get_map_statistics   args { int32 id, uint32 pad0, int32 cap, uint32 pad1,
--                                 uintptr records, uintptr count_out }
-- 646 get_kernel_mem_stat / stats   args { uintptr out }   (0x3f8 record)
-- Each is called with a zeroed buffer and every qword is scanned for kernel VA.

print("=== PROBE 972a: SYS 641 / 642 / 646 ===")
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
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function zero(p,n) for i=0,n-4,4 do wd(p+i,0) end end

local function scan(tag, buf, n)
    local found=0
    for off=0,n-8,8 do
        local oa,lo=pcall(function() return to_num(memory.read_dword(buf+off)) end)
        local ob,hi=pcall(function() return to_num(memory.read_dword(buf+off+4)) end)
        if oa and ob then
            if hi>=0xFFFF8000 then
                found=found+1
                if found<=6 then print(string.format("  [%s] +0x%03X = 0x%08X%08X  <== kernel VA", tag, off, hi, lo)) end
            end
        end
    end
    print(string.format("  [%s] kernel-va-count=%d", tag, found))
end

local pid=to_num(mk(20)())
print("[0] pid=" .. tostring(pid))

-- 641
local out641=memory.alloc(0x100) zero(out641,0x100)
local a641=memory.alloc(0x10) zero(a641,0x10)
wd(a641,pid) wd(a641+4,0)
wd(a641+8, addr_of(out641)%4294967296) wd(a641+12, math.floor(addr_of(out641)/4294967296))
local ok,rv=pcall(function() return mk(641)(uint64(a641)) end)
local h,l=hi_lo(ok and rv or 0)
print(string.format("  [641 pid=%d] ret=0x%08X_%08X", pid, h, l))
if ok then
    for i=0,0x30,8 do print(string.format("   641 +0x%02X: %08X %08X", i, rd(out641+i+4), rd(out641+i))) end
    scan("641", out641, 0x38)
end

-- 642
local rec=memory.alloc(0x68*8) zero(rec,0x68*8)
local cnt=memory.alloc(0x10) zero(cnt,0x10)
local a642=memory.alloc(0x20) zero(a642,0x20)
wd(a642,pid) wd(a642+8,8)
wd(a642+16, addr_of(rec)%4294967296) wd(a642+20, math.floor(addr_of(rec)/4294967296))
wd(a642+24, addr_of(cnt)%4294967296) wd(a642+28, math.floor(addr_of(cnt)/4294967296))
ok,rv=pcall(function() return mk(642)(uint64(a642)) end)
h,l=hi_lo(ok and rv or 0)
print(string.format("  [642 pid=%d] ret=0x%08X_%08X count=%d", pid, h, l, rd(cnt)))
if ok then scan("642", rec, 0x68*8) end

-- 646
local out646=memory.alloc(0x400) zero(out646,0x400)
local a646=memory.alloc(0x10) zero(a646,0x10)
wd(a646, addr_of(out646)%4294967296) wd(a646+4, math.floor(addr_of(out646)/4294967296))
ok,rv=pcall(function() return mk(646)(uint64(a646)) end)
h,l=hi_lo(ok and rv or 0)
print(string.format("  [646] ret=0x%08X_%08X", h, l))
if ok then
    local nz=0
    for i=0,0x3F0,8 do
        local lo2=rd(out646+i) local hi2=rd(out646+i+4)
        if lo2~=0 or hi2~=0 then nz=nz+1 end
    end
    print(string.format("  [646] non-zero qwords=%d", nz))
    scan("646", out646, 0x3f8)
end

print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
