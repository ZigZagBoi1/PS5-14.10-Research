-- CRASH_CLASS: LOW
-- PROBE 119g: Scan other modules data + eboot data rest
--
-- Skip pipe (kills process). Focus on:
-- A: All modules 3-39 data segments for kernel pointers
-- B: Eboot data 0x80000-0x180000 (119c only did first 0x80000)
-- C: Check libSceLibcInternal "kptr" stability (NID vs real kptr)

print("=== PROBE 119g: MODULES + EBOOT REST ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val)=="table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val==nil then return "nil" end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    return string.format("0x%X%08X",h,l)
end
local function is_kptr(val)
    if val==nil then return false end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    return h>=0xFFFF8000 and h<0xFFFFF000 and h~=0xFFFFFFFF
end
local function read_base(inf_addr, off)
    local lo=rd(inf_addr+off) or 0; local hi=rd(inf_addr+off+4) or 0
    if hi<0 then hi=hi+0x100000000 end
    if lo<0 then lo=lo+0x100000000 end
    if hi==0 and lo==0 then return nil end
    return N(uint64(string.format("0x%X%08X", hi, lo)))
end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)
local sc_info=mk(593)

-- ============================================================
print("--- A: ALL MODULES DATA ---")
for handle=3,39 do
    local inf=memory.alloc(0x200)
    wd(inf,0x160)
    local ok2=pcall(function() sc_info(uint64(handle),inf) end)
    if not ok2 then break end
    local I2=N(inf)
    local tb2=read_base(I2,0x108)
    if not tb2 then
        if handle>10 then break end
    else
        local db2=read_base(I2,0x118)
        local name=""
        for i=0,23 do
            local b=rd(I2+8+i); if not b then break end
            local ch=b%256; if ch==0 then break end
            if ch>=32 and ch<127 then name=name..string.char(ch) end
        end
        if db2 then
            local dsz2_raw=rq(I2+0x120)
            local dsz2=0
            if dsz2_raw then
                local _,dl=get_hi_lo(dsz2_raw)
                if dl<0 then dl=dl+0x100000000 end
                dsz2=dl
            end
            local mkp=0
            local first_off=nil
            local limit=math.min(dsz2,0x40000)
            for off=0,limit-8,8 do
                local val=rq(db2+off)
                if val==nil then break end
                if is_kptr(val) then
                    mkp=mkp+1
                    if not first_off then first_off=off end
                    if mkp<=3 then
                        print(string.format("  [%d]+0x%X:%s", handle, off, fmt(val)))
                    end
                end
            end
            if mkp>0 then
                print(string.format("[%d]'%s' kp=%d first=0x%X sz=0x%X", handle, name, mkp, first_off, dsz2))
            else
                print(string.format("[%d]'%s' kp=0 sz=0x%X", handle, name, dsz2))
            end
        else
            print(string.format("[%d]'%s' NO_DATA", handle, name))
        end
    end
end

local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: EBOOT DATA REST ---")
local inf0=memory.alloc(0x200)
wd(inf0,0x160)
pcall(function() sc_info(uint64(0),inf0) end)
local I0=N(inf0)
local EB_DB=read_base(I0,0x118)
if EB_DB then
    print(string.format("eboot_data=0x%X", EB_DB))
    local ekp=0
    for off=0x80000,0x180000-8,8 do
        local val=rq(EB_DB+off)
        if val==nil then
            print(string.format("unreadable +0x%X", off))
            break
        end
        if is_kptr(val) then
            ekp=ekp+1
            print(string.format("  +0x%05X:%s", off, fmt(val)))
            if ekp>=10 then break end
        end
    end
    print("eboot_rest_kp="..ekp)
end

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: NID CHECK ---")
-- Read first 3 "kptr" values from libSceLibcInternal data+0xA428
-- If these are NID entries, the low 32 bits are function offsets
-- and they should be within libSceLibcInternal text_size
local inf2=memory.alloc(0x200)
wd(inf2,0x160)
pcall(function() sc_info(uint64(2),inf2) end)
local I2=N(inf2)
local lci_tb=read_base(I2,0x108)
local lci_db=read_base(I2,0x118)
local lci_tsz_raw=rq(I2+0x110)
local lci_tsz=0
if lci_tsz_raw then
    local _,tl=get_hi_lo(lci_tsz_raw)
    if tl<0 then tl=tl+0x100000000 end
    lci_tsz=tl
end
print(string.format("lci text=0x%X tsz=0x%X data=0x%X", lci_tb or 0, lci_tsz, lci_db or 0))

if lci_db then
    for _,off in ipairs({0xA428,0xA438,0xA498}) do
        local val=rq(lci_db+off)
        if val then
            local h,l=get_hi_lo(val)
            if h<0 then h=h+0x100000000 end
            if l<0 then l=l+0x100000000 end
            local in_text = (l < lci_tsz) and "YES" or "NO"
            print(string.format("  +0x%X: hi=0x%X lo=0x%X in_text=%s", off, h, l, in_text))
        end
    end
end

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 119g COMPLETE ===")
