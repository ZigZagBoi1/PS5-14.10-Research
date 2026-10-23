-- CRASH_CLASS: LOW
-- PROBE 91m: Scan for mov r10,rcx patterns in eboot
--
-- 91l found pop_rcx at +0xE64. If we find mov r10,rcx (49 89 CA)
-- followed by ret (C3), we can set R10 in ROP chains.
-- Also search for the 3-byte prefix (49 89 CA) alone to find
-- syscall wrappers.

print("=== PROBE 91m: MOV R10,RCX SCAN ===")
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

-- Search targets:
-- A: 49 89 CA C3 = mov r10,rcx; ret (ideal gadget)
-- B: 49 89 CA followed by anything (find syscall wrappers)
-- C: 49 89 CA 0F 05 C3 = mov r10,rcx; syscall; ret (raw wrapper)
-- D: 49 89 CA B8 XX 00 00 00 0F 05 = mov r10,rcx; mov eax,XX; syscall

local gadget_hits={} -- {off, type, next_bytes}
local max_hits=100
local p2=nil; local p3=nil

local scan_lim=math.min(text_sz,0x500000)
local chunk=0x40000

print("")
print("--- SCANNING for 49 89 CA ---")

for base_off=0,scan_lim-1,chunk do
    local end_off=math.min(base_off+chunk-1,scan_lim-4)

    for soff=base_off,end_off,4 do
        local v=rd(ebase+soff)
        if not v then break end
        local b0=v%256
        local b1=math.floor(v/256)%256
        local b2=math.floor(v/65536)%256
        local b3=math.floor(v/16777216)%256

        -- Check 49 89 CA at each position

        -- Cross-boundary: prev b2=49, prev b3=89, this b0=CA
        if p2 and p3 and p2==0x49 and p3==0x89 and b0==0xCA then
            if #gadget_hits<max_hits then
                table.insert(gadget_hits,{off=soff-2,nb0=b0,nb1=b1,nb2=b2,nb3=b3})
            end
        end
        -- Cross-boundary: prev b3=49, this b0=89, b1=CA
        if p3 and p3==0x49 and b0==0x89 and b1==0xCA then
            if #gadget_hits<max_hits then
                table.insert(gadget_hits,{off=soff-1,nb0=b1,nb1=b2,nb2=b3})
            end
        end
        -- Within dword: b0=49, b1=89, b2=CA
        if b0==0x49 and b1==0x89 and b2==0xCA then
            if #gadget_hits<max_hits then
                table.insert(gadget_hits,{off=soff,nb0=b2,nb1=b3})
            end
        end
        -- Within dword: b1=49, b2=89, b3=CA
        if b1==0x49 and b2==0x89 and b3==0xCA then
            if #gadget_hits<max_hits then
                table.insert(gadget_hits,{off=soff+1})
            end
        end

        p2=b2; p3=b3
    end

    print("  +"..string.format("0x%X",base_off).." "..#gadget_hits.." hits")
    if #gadget_hits>=max_hits then break end
end

-- ============================================================
-- Print results with 32 bytes context + scan for first C3 (ret)
-- ============================================================
print("")
print("--- RESULTS (32B context) ---")
print("Found "..#gadget_hits.." hits")
print("")

for i,hit in ipairs(gadget_hits) do
    local off=hit.off
    -- Read 32 bytes from match+3 (after the 49 89 CA)
    local bytes="49 89 CA "
    local first_ret=nil
    local r10_clobbered=false
    for j=3,34 do
        local b=read_byte_at(off+j)
        if b then
            bytes=bytes..string.format("%02X ",b)
            if b==0xC3 and not first_ret then first_ret=j end
        else
            bytes=bytes.."?? "
        end
    end

    -- Check for R10 clobber before first ret
    -- Look for 49 89 XX (mov r10,<reg>) or 41 5A (pop r10)
    -- or 49 FF (inc/dec r10) or 49 F7 DA (neg r10) etc.
    local clobber_note=""
    if first_ret then
        for j=3,first_ret-1 do
            local b=read_byte_at(off+j)
            local bn=read_byte_at(off+j+1)
            if b and bn then
                -- 49 89 XX where XX mod/rm r/m=r10 (XX & 0xC7 == 0xC2)
                if b==0x49 and bn==0x89 then
                    local modrm=read_byte_at(off+j+2)
                    if modrm and (modrm%8)==2 and modrm>=0xC0 then
                        clobber_note=" R10_CLOBBER@+"..j
                    end
                end
                -- 49 F7 DA = neg r10
                if b==0x49 and bn==0xF7 then
                    local m3=read_byte_at(off+j+2)
                    if m3==0xDA then clobber_note=" R10_NEG@+"..j end
                end
                -- 49 29 F2 = sub r10,rsi etc
                if b==0x49 and (bn==0x29 or bn==0x01 or bn==0x31 or bn==0x21 or bn==0x09) then
                    local m3=read_byte_at(off+j+2)
                    if m3 and (m3%8)==2 and m3>=0xC0 then
                        clobber_note=" R10_ALU@+"..j
                    end
                end
                -- 4C 8B DX = mov r10,[...]
                if b==0x4C and bn==0x8B then
                    local m3=read_byte_at(off+j+2)
                    if m3 and m3>=0xD0 and m3<=0xD7 then
                        clobber_note=" R10_LOAD@+"..j
                    end
                end
                -- 41 5A = pop r10
                if b==0x41 and bn==0x5A then
                    clobber_note=" POP_R10@+"..j
                end
            end
        end
    end

    local ret_tag=""
    if first_ret then
        ret_tag=" RET@+"..first_ret..clobber_note
        if clobber_note=="" then ret_tag=ret_tag.." *** USABLE ***" end
    else
        ret_tag=" NO_RET_IN_32B"
    end

    print(string.format("  #%d +0x%06X: %s%s",i,off,bytes,ret_tag))
end

-- ============================================================
-- Also scan for mov r10,[rsp]; ret (4C 8B 14 24 C3)
-- and pop r10; ret (41 5A C3) — double check 91c
-- and mov r10,rax; ret (49 89 C2 C3 or 4C 8B D0 C3)
-- and mov r10,rdi; ret (49 89 FA C3 or 4C 8B D7 C3)
-- ============================================================
print("")
print("--- EXTRA PATTERNS ---")

local extra={} -- name → offset list
local ep2=nil; local ep3=nil; local ep4=nil

for base_off=0,scan_lim-1,chunk do
    local end_off=math.min(base_off+chunk-1,scan_lim-4)
    for soff=base_off,end_off,4 do
        local v=rd(ebase+soff)
        if not v then break end
        local b0=v%256
        local b1=math.floor(v/256)%256
        local b2=math.floor(v/65536)%256
        local b3=math.floor(v/16777216)%256

        -- 3-byte: 41 5A C3 = pop r10; ret
        if ep2 and ep3 and ep2==0x41 and ep3==0x5A and b0==0xC3 then
            if not extra["pop_r10"] then extra["pop_r10"]={} end
            if #extra["pop_r10"]<3 then table.insert(extra["pop_r10"],soff-2) end
        end
        if ep3 and ep3==0x41 and b0==0x5A and b1==0xC3 then
            if not extra["pop_r10"] then extra["pop_r10"]={} end
            if #extra["pop_r10"]<3 then table.insert(extra["pop_r10"],soff-1) end
        end
        if b0==0x41 and b1==0x5A and b2==0xC3 then
            if not extra["pop_r10"] then extra["pop_r10"]={} end
            if #extra["pop_r10"]<3 then table.insert(extra["pop_r10"],soff) end
        end
        if b1==0x41 and b2==0x5A and b3==0xC3 then
            if not extra["pop_r10"] then extra["pop_r10"]={} end
            if #extra["pop_r10"]<3 then table.insert(extra["pop_r10"],soff+1) end
        end

        -- 4-byte: 49 89 C2 C3 = mov r10,rax; ret
        if ep3 and ep3==0x49 and b0==0x89 and b1==0xC2 and b2==0xC3 then
            if not extra["mov_r10_rax"] then extra["mov_r10_rax"]={} end
            table.insert(extra["mov_r10_rax"],soff-1)
        end
        if b0==0x49 and b1==0x89 and b2==0xC2 and b3==0xC3 then
            if not extra["mov_r10_rax"] then extra["mov_r10_rax"]={} end
            table.insert(extra["mov_r10_rax"],soff)
        end

        -- 4-byte: 49 89 FA C3 = mov r10,rdi; ret
        if ep3 and ep3==0x49 and b0==0x89 and b1==0xFA and b2==0xC3 then
            if not extra["mov_r10_rdi"] then extra["mov_r10_rdi"]={} end
            table.insert(extra["mov_r10_rdi"],soff-1)
        end
        if b0==0x49 and b1==0x89 and b2==0xFA and b3==0xC3 then
            if not extra["mov_r10_rdi"] then extra["mov_r10_rdi"]={} end
            table.insert(extra["mov_r10_rdi"],soff)
        end

        -- 4-byte: 49 89 D2 C3 = mov r10,rdx; ret
        if ep3 and ep3==0x49 and b0==0x89 and b1==0xD2 and b2==0xC3 then
            if not extra["mov_r10_rdx"] then extra["mov_r10_rdx"]={} end
            table.insert(extra["mov_r10_rdx"],soff-1)
        end
        if b0==0x49 and b1==0x89 and b2==0xD2 and b3==0xC3 then
            if not extra["mov_r10_rdx"] then extra["mov_r10_rdx"]={} end
            table.insert(extra["mov_r10_rdx"],soff)
        end

        -- 4-byte: 49 89 F2 C3 = mov r10,rsi; ret
        if ep3 and ep3==0x49 and b0==0x89 and b1==0xF2 and b2==0xC3 then
            if not extra["mov_r10_rsi"] then extra["mov_r10_rsi"]={} end
            table.insert(extra["mov_r10_rsi"],soff-1)
        end
        if b0==0x49 and b1==0x89 and b2==0xF2 and b3==0xC3 then
            if not extra["mov_r10_rsi"] then extra["mov_r10_rsi"]={} end
            table.insert(extra["mov_r10_rsi"],soff)
        end

        -- 5-byte: 4C 8B 14 24 C3 = mov r10,[rsp]; ret
        if ep4 and ep3 and ep4==0x4C and ep3==0x8B and b0==0x14 and b1==0x24 and b2==0xC3 then
            if not extra["mov_r10_rsp"] then extra["mov_r10_rsp"]={} end
            table.insert(extra["mov_r10_rsp"],soff-2)
        end
        -- within dword boundaries
        if ep3 and ep3==0x4C and b0==0x8B and b1==0x14 and b2==0x24 and b3==0xC3 then
            if not extra["mov_r10_rsp"] then extra["mov_r10_rsp"]={} end
            table.insert(extra["mov_r10_rsp"],soff-1)
        end

        ep4=ep3; ep3=b3; ep2=b2
    end
end

local enames={"pop_r10","mov_r10_rax","mov_r10_rdi","mov_r10_rdx","mov_r10_rsi","mov_r10_rsp"}
for _,nm in ipairs(enames) do
    local r=extra[nm]
    if r and #r>0 then
        local s=""
        for _,o in ipairs(r) do s=s..string.format("+0x%X ",o) end
        print("  "..nm..": "..s.." *** FOUND ***")
    else
        print("  "..nm..": NOT FOUND")
    end
end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91m DONE ===")
