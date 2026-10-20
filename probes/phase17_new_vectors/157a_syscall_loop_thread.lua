-- CRASH_CLASS: HIGH (a child thread loops a libkernel syscall wrapper)
-- PROBE 157a: a second thread that keeps entering the kernel
--
-- Why: a race needs one thread INSIDE a kernel handler while another thread
-- perturbs the object it works on. 156c proved thr_create(430) accepts a
-- ring-3 context and 156d proved the child executes; the missing piece is a
-- child that keeps calling a syscall instead of spinning once.
--
-- eboot has no `syscall` instruction (the first version of this probe scanned
-- 1 MB of eboot text for 0F 05 C3 and found none), so the wrapper has to come
-- from libkernel — which is execute-only and cannot be read. The loader
-- already publishes the address it uses:
--   syscall.syscall_address = <gettimeofday wrapper> + 7
-- (syscall.lua: "gettimeofday + 7 -- +7 is to skip 'mov rax, <num>'").
-- The seven bytes before it are `mov rax, 116`, so RIP = syscall_address - 7
-- makes the child execute, every iteration:
--   mov rax, 116 ; mov r10, rcx ; syscall ; ret
-- and with every stack slot holding that same address, `ret` re-enters it.
--
-- Oracle: syscall 116 writes struct timeval into RDI. The child loops with
-- RDI = our page, so tv_sec/tv_usec change while it runs. That is direct
-- evidence the child is entering the kernel, not just executing user bytes.
-- (Sys 624, the VM-operation counter, is also sampled: it moves +5 per mmap
-- and proves the counter is live, but gettimeofday does not touch it.)
--
-- Layout: docs/THR_CREATE_430_CONTEXT.md §5 — gates +0x108=0x480,
-- +0x110=0x10000, +0x0d0=0; CS +0x0c0, RIP +0x0e0, RSP +0x0f8, SS +0x100;
-- rdi..r15 at +0x048..+0x0B8.

print("=== PROBE 157a: SYSCALL-LOOP THREAD VIA LIBKERNEL WRAPPER ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_thr_self = make_syscall(432)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)
local sc624 = make_syscall(624)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX = 0x048, 0x050, 0x058
local C_RAX = 0x078

local function read624()
    local ok, ret = pcall(function() return sc624() end)
    if not ok or ret == nil then return nil end
    local h, l = get_hi_lo(ret)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return h * 4294967296 + l
end

local ok0, pid0 = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid0))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
print("[0] main TID=" .. q(rq(tid_buf)))

-- 624 sanity: one mmap should move the counter by +5.
local c_a = read624()
local ok_p, probe_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x1000), uint64(3), uint64(0x1002),
        uint64(0xFFFFFFFF), uint64(0))
end)
local c_b = read624()
print("[0] 624 sanity: before=" .. tostring(c_a) .. " after=" .. tostring(c_b) ..
    " delta=" .. tostring(c_a and c_b and (c_b - c_a) or "n/a") ..
    " (one mmap, ok=" .. tostring(ok_p) .. ")")

local SW = syscall.syscall_address
if SW == nil then
    print("[0] syscall.syscall_address is nil; the loader did not expose the wrapper")
    print("=== PROBE 157a COMPLETE ===")
    return
end
local sw_hi, sw_lo = get_hi_lo(SW)
if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
if sw_lo < 7 then
    sw_lo = sw_lo + 0x100000000 - 7
    sw_hi = sw_hi - 1
else
    sw_lo = sw_lo - 7
end
local wrapper = uint64(string.format("0x%X%08X", sw_hi, sw_lo))
print("[0] syscall_address=" .. q(SW) .. " wrapper(mov rax,116)=" .. q(wrapper))

-- The page syscall 116 writes into.
local ok_pg, page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
        uint64(0xFFFFFFFF), uint64(0))
end)
local ph, pl = get_hi_lo(page)
if not ok_pg or (ph == 0 and pl == 0) then
    print("[0] page mmap failed; aborting")
    print("=== PROBE 157a COMPLETE ===")
    return
end
zero(page, 0x4000)
print("[0] timeval page=" .. q(page))

-- Cycling stack: every slot is the wrapper address.
local STACK_SIZE = 0x100000
local ok_stack, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3), uint64(0x1002),
        uint64(0xFFFFFFFF), uint64(0))
end)
local sh, sl = get_hi_lo(stack_base)
if not ok_stack or (sh == 0 and sl == 0) then
    print("[0] stack mmap failed; aborting")
    print("=== PROBE 157a COMPLETE ===")
    return
end
local slots = 0
for off = 0, STACK_SIZE - 8, 8 do
    wq(stack_base + off, wrapper)
    slots = slots + 1
end
print("[0] stack=" .. q(stack_base) .. " slots=" .. tostring(slots))

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + C_MAGIC, uint64(0x480))
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, uint64(0x10000))
wq(ctx + C_CS, uint64(0x43))
wq(ctx + C_SS, uint64(0x3B))
wq(ctx + C_RIP, wrapper)
wq(ctx + C_RSP, stack_base)
wq(ctx + C_RAX, uint64(116))   -- gettimeofday; the wrapper reloads it anyway
wq(ctx + C_RDI, page)          -- struct timeval *
wq(ctx + C_RSI, uint64(0))     -- timezone *
wq(ctx + C_RDX, uint64(0))

print("[1] child: RIP=" .. q(rq(ctx + C_RIP)) .. " RSP=" .. q(rq(ctx + C_RSP)) ..
    " RDI=" .. q(rq(ctx + C_RDI)))

zero(tid_buf, 8)
wq(tid_buf, uint64(0xDEADDEAD))
local before = read624()
print("[1] calling thr_create ...")
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local child_tid = rq(tid_buf)
print("[1] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) ..
    " tid=" .. q(child_tid))

if to_num(rv_tc) ~= 0 then
    print("[1] rejected; nothing to observe")
    print("=== PROBE 157a COMPLETE ===")
    return
end

local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 40000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local sec1, usec1 = rd(page), rd(page + 8)
local mid = read624()
local ok_alive, rv_alive = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
print("[2] after 40 ms: timeval sec=" .. tostring(sec1) .. " usec=" .. tostring(usec1) ..
    " 624 delta=" .. tostring(before and mid and (mid - before) or "n/a") ..
    " thr_kill(tid,0) rv=" .. tostring(to_num(rv_alive)))

local ts1 = memory.alloc(16)
wq(ts1, 0); wq(ts1 + 8, 20000000)
pcall(function() sc_nanosleep(uint64(ts1), uint64(0)) end)
local sec2, usec2 = rd(page), rd(page + 8)
print("[2] 20 ms later:  timeval sec=" .. tostring(sec2) .. " usec=" .. tostring(usec2))

-- A fatal signal to a THREAD ends the WHOLE process on this kernel, so the
-- kill is the last action: every result above is already on the wire, and no
-- spinning child outlives the session (a surviving spinner wedged the loader
-- after the 17:17 run, which is why this order matters).
if (usec1 or 0) ~= 0 or (sec1 or 0) ~= 0 then
    if (usec2 or 0) ~= (usec1 or 0) or (sec2 or 0) ~= (sec1 or 0) then
        print("[3] *** CHILD LOOPED IN THE KERNEL: timeval advanced ***")
    else
        print("[3] timeval written once but did not advance")
    end
else
    print("[3] timeval untouched; the child did not reach syscall 116")
end

local ok_c2, pid_c2 = pcall(function() return sc_getpid():tonumber() end)
print("[4] final canary: ok=" .. tostring(ok_c2) .. " pid=" .. tostring(pid_c2))
print("")
print("=== PROBE 157a COMPLETE (session ends with the kill) ===")

pcall(function() return sc_thr_kill(child_tid, uint64(9)) end)
