-- CRASH_CLASS: MODERATE
-- PROBE 873a: which reachable aio call can move a pending object to state 3?
--
-- The delete gate requires [S+8] in {3,4} (0x8ad6fe... -> 0x80020010 otherwise).
-- A pending object (state 2, read never completes) is refused, which is what
-- kept 866a's blocked waiter away from the free path.  If any reachable call
-- flips a pending object to 3 without the object actually finishing, the
-- wait/delete overlap becomes reachable.
print("=== PROBE 873a: aio state writers ===")
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
local SOCKETPAIR=135
local fn_ud=syscall.pipe.fn_addr
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local page=0x4000
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page); local bufp=mmap(page); local res=mmap(page)
local ts=memory.alloc(16)
local function H(v) if type(v)=="table" then v=to_num(v) end return string.format("%08X", (tonumber(v) or 0) % 4294967296) end
local function S(v) return tostring(v) end
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
local fds=memory.alloc(8)
local function fresh_pending()
    wd(D,0); wd(D+0x20,0xFFFFFFFF) wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
    local ok,rv=pcall(function() return mk(SOCKETPAIR)(uint64(1),uint64(1),uint64(0),uint64(fds)) end)
    if not (ok and to_num(rv)==0) then return nil end
    local a=rd(fds)
    wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(res)); wd(D+0x20,a); wd(D+0x24,0)
    local okc,rvc=pcall(function() return mk(669)(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
    local id=rd(out) or 0
    if id==0 then return nil, tostring(rvc) end
    wd(ids,id)
    pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
    return id, rd(st) or 0
end
local function state(id)
    wd(ids,id)
    pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
    return rd(st) or 0
end
local function del(id)
    wd(ids,id)
    pcall(function() mk(662)(uint64(ids),uint64(1),uint64(st)) end)
    return rd(st) or 0
end
local tmo=memory.alloc(8); wd(tmo,2000)  -- 2 ms
local CASES={
    {"none control", function(id) return "skip" end},
    {"666 cancel",   function(id) wd(ids,id); pcall(function() mk(666)(uint64(ids),uint64(1),uint64(st)) end); return rd(st) or 0 end},
    {"663 wait 2ms",  function(id) wd(ids,id); wd(tmo,2000); pcall(function() mk(663)(uint64(ids),uint64(1),uint64(st),uint64(tmo)) end); return rd(st) or 0 end},
    {"663 wait 0",    function(id) wd(ids,id); pcall(function() mk(663)(uint64(ids),uint64(0),uint64(st),uint64(0)) end); return rd(st) or 0 end},
    {"670 cmd0",      function(id) wd(ids,id); pcall(function() mk(670)(uint64(0),uint64(ids),uint64(1),uint64(st)) end); return rd(st) or 0 end},
    {"670 cmd1",      function(id) wd(ids,id); pcall(function() mk(670)(uint64(1),uint64(ids),uint64(1),uint64(st)) end); return rd(st) or 0 end},
    {"665 get_data",  function(id) wd(ids,id); pcall(function() mk(665)(uint64(ids),uint64(1),uint64(st)) end); return rd(st) or 0 end},
    {"661 submit",    function(id) wd(ids,id); pcall(function() mk(661)(uint64(ids),uint64(1),uint64(st)) end); return rd(st) or 0 end},
}
for i=1,#CASES do
    local name,fnc=CASES[i]
    local id,s0=fresh_pending()
    if not id then print("["..tostring(name).."] create failed "..S(s0))
    else
        local rv=fnc(id)
        sleep_ms(2)
        local s1=state(id)
        local sd=del(id)
        print(string.format("[%-14s] id=%s before=%s call=%s after=%s delete=%s", tostring(name), H(id), H(s0), S(rv), H(s1), H(sd)))
        local hs,rvc=fresh_pending()
        print(string.format("[%-14s] health id=%s state=%s", tostring(name), tostring(hs), S(rvc)))
    end
end
print("[Z] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
