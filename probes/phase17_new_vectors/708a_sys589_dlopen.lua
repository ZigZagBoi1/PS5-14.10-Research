-- CRASH_CLASS: MODERATE
-- PROBE 708a: syscall 589 (listed as dynlib_dlopen in the 13.60 capture as a stub)
-- with real path strings, under a SIGSYS shield.
--
-- Context: 561/562 are nosys stubs in the 13.60 image but behave like real
-- handlers on 14.10, so the 13.60 "stub" label no longer rules a number out.
-- 589/590/597 are the dlopen-style triple that 591/594 needed and could not get.
-- A dlopen that works would hand us a module base or a handle, which is the one
-- thing dynlib_get_info (593) does not give us: a resolved entry point.
--
-- The shield (sigaction 12 SIG_IGN) turns a SIGSYS death into a -1, so an
-- invalid shape costs nothing. Every section prints before it runs.

print("=== PROBE 708a: syscall 589 dlopen shapes under SIGSYS shield ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a=N(a)
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wr(addr,str)
    for i=1,#str do
        pcall(function() memory.write_byte(addr+i-1,string.byte(str,i)) end)
    end
    pcall(function() memory.write_byte(addr+#str,0) end)
end
local function rd(a)
    local o,v=pcall(function() return memory.read_dword(a) end)
    if o then return N(v) end
    return nil
end

local sc416=mk(416)
pcall(function() sc416(uint64(12),uint64(1),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[0] shield set")

local out=memory.alloc(0x100)
local paths={
    "/system/common/lib/libkernel.sprx",
    "/system/common/lib/libSceLibc.prx",
    "/app0/sce_module/libc.prx",
    "/app0/eboot.bin",
}
local sc589=mk(589)
local names={"589"}
for pi,p in ipairs(paths) do
    local buf=memory.alloc(0x200)
    wr(N(buf),p)
    for shape=1,4 do
        for i=0,0xFC,4 do wd(N(out)+i,0xDEADBEEF) end
        local ok,rv
        if shape==1 then
            ok,rv=pcall(function() return sc589(U(N(buf)),uint64(0),U(N(out)),uint64(0),uint64(0),uint64(0)) end)
        elseif shape==2 then
            ok,rv=pcall(function() return sc589(U(N(buf)),U(N(out)),uint64(0),uint64(0),uint64(0),uint64(0)) end)
        elseif shape==3 then
            ok,rv=pcall(function() return sc589(U(N(buf)),uint64(1),U(N(out)),uint64(0),uint64(0),uint64(0)) end)
        else
            ok,rv=pcall(function() return sc589(U(N(buf)),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
        end
        local d0=rd(N(out)) or 0
        local d1=rd(N(out)+4) or 0
        print(string.format("[P%d s%d] %s ok=%s rv=%s out=%08X/%08X",
            pi,shape,p,tostring(ok),tostring(rv),d0,d1))
    end
end

-- 590 dlclose and 597 prepare_dlclose with the same handle shapes
local sc590=mk(590)
for h=1,4 do
    local ok,rv=pcall(function() return sc590(uint64(h),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("[590 h%d] ok=%s rv=%s",h,tostring(ok),tostring(rv)))
end
local sc597=mk(597)
for h=1,3 do
    local ok,rv=pcall(function() return sc597(uint64(h),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("[597 h%d] ok=%s rv=%s",h,tostring(ok),tostring(rv)))
end

print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
