-- CRASH_CLASS: MODERATE
-- PROBE 555e: barrier read test — why doesn't the main see 0xBEEF?
--
-- 555d showed: child writes READY (0xBEEF) and DONE (0xDEAD) to shared mem,
-- child_done=true (DONE detected), but ready=false (READY never seen in spin).
-- This probe isolates the issue.

print("=== PROBE 555e: BARRIER READ TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", N(v))
end

local Z = uint64(0)
local sc20  = mk(20)
local sc331 = mk(331)
local sc455 = mk(455)
local sc477 = mk(477)

local pid = N(sc20())
print("pid=" .. pid)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax   = eb + uint64(0x992)
local pop_rdi   = eb + uint64(0xC9DFE)
local pop_rsi   = eb + uint64(0xD77D)
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

-- Shared memory
local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))
local shared_n = N(shared)

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Stack for child
local ok_stk, stack_base = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local rsp = N(stack_base) + 0x100000 - 8

-- ============================================================
-- TEST 1: Main writes and reads from shared memory (sanity)
-- ============================================================
print("")
print("=== TEST 1: Main R/W on shared ===")
wd(shared_n, 0)
wd(shared_n + 4, 0)
print("  pre: [+0]=" .. tostring(rd(shared_n)) .. " [+4]=" .. tostring(rd(shared_n + 4)))

wd(shared_n, 0xBEEF)
print("  post-wd: [+0]=" .. tostring(rd(shared_n)))
print("  match=" .. tostring(rd(shared_n) == 0xBEEF))

-- Clear for test 2
wd(shared_n, 0)
wd(shared_n + 4, 0)

-- ============================================================
-- TEST 2: Child writes qword, main reads dword (THE ACTUAL PATTERN)
-- ============================================================
print("")
print("=== TEST 2: Child writes qword, main reads dword ===")

-- Build minimal chain: sysarch → write 0xBEEF to +0 → write 0xDEAD to +8 → exit
local pos = 0
local function emit(v) wq(uint64(rsp + pos), v); pos = pos + 8 end

-- sysarch
emit(pop_rdi); emit(uint64(129))
emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
emit(pop_rax); emit(uint64(165))
emit(fn_addr)

-- write 0xBEEF to shared+0 (qword!)
emit(pop_rax); emit(uint64(0xBEEF))
emit(pop_rdi); emit(uint64(shared_n))
emit(mov_m_rax)

-- write 0xDEAD to shared+16 (far away, no overlap)
emit(pop_rax); emit(uint64(0xDEAD))
emit(pop_rdi); emit(uint64(shared_n + 16))
emit(mov_m_rax)

-- thr_exit
emit(pop_rdi); emit(Z)
emit(pop_rax); emit(uint64(431))
emit(fn_addr)

print("  chain=" .. pos .. "B")

-- thr_param
local tp = memory.alloc(0x40); zero(tp, 0x40)
wq(tp, bare_ret)
wq(tp + 0x10, stack_base)
wq(tp + 0x18, uint64(0x100008))

-- Launch child
pcall(function() sc455(uint64(N(tp)), uint64(0x38)) end)

-- Wait with yield for child to finish
for w = 1, 5000 do
    if (rd(shared_n + 16) or 0) == 0xDEAD then break end
    if w % 100 == 0 then pcall(function() sc331() end) end
end

-- Read shared memory
local v0_dword = rd(shared_n)
local v0_qword = rq(shared_n)
local v16_dword = rd(shared_n + 16)
local v16_qword = rq(shared_n + 16)

print("  [+0] dword=" .. tostring(v0_dword) .. " qword=" .. q(v0_qword or uint64(0)))
print("  [+16] dword=" .. tostring(v16_dword) .. " qword=" .. q(v16_qword or uint64(0)))
print("  dword==0xBEEF: " .. tostring(v0_dword == 0xBEEF))
print("  dword==48879:  " .. tostring(v0_dword == 48879))

-- ============================================================
-- TEST 3: Spin-wait detection test
-- ============================================================
print("")
print("=== TEST 3: Spin-wait detection ===")

-- Clear and rebuild chain (same as above)
wd(shared_n, 0)
wd(shared_n + 16, 0)

-- Rebuild chain at same rsp
pos = 0
-- sysarch
emit(pop_rdi); emit(uint64(129))
emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
emit(pop_rax); emit(uint64(165))
emit(fn_addr)
-- write 0xBEEF (dword this time!)
emit(pop_rax); emit(uint64(0xBEEF))
emit(pop_rdi); emit(uint64(shared_n))
emit(mov_m_rax)
-- done marker
emit(pop_rax); emit(uint64(0xDEAD))
emit(pop_rdi); emit(uint64(shared_n + 16))
emit(mov_m_rax)
-- exit
emit(pop_rdi); emit(Z)
emit(pop_rax); emit(uint64(431))
emit(fn_addr)

-- Launch child
pcall(function() sc455(uint64(N(tp)), uint64(0x38)) end)

-- Spin-wait for 0xBEEF at +0
local found = false
local spin_count = 0
for s = 1, 50000 do
    local v = rd(shared_n)
    if v == 0xBEEF then
        found = true; spin_count = s; break
    end
    if v ~= 0 and s <= 5 then
        print("  spin iter " .. s .. ": val=" .. tostring(v))
    end
end

print("  found=" .. tostring(found) .. " spin=" .. spin_count)

-- Read final state
local final_0 = rd(shared_n)
local final_16 = rd(shared_n + 16)
print("  final [+0]=" .. tostring(final_0) .. " [+16]=" .. tostring(final_16))

-- ============================================================
-- TEST 4: What if we compare with the raw dword value?
-- ============================================================
print("")
print("=== TEST 4: Raw value comparison ===")
wd(shared_n, 0)
wd(shared_n + 16, 0)

-- Rebuild chain
pos = 0
emit(pop_rdi); emit(uint64(129))
emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
emit(pop_rax); emit(uint64(165))
emit(fn_addr)
emit(pop_rax); emit(uint64(0xBEEF))
emit(pop_rdi); emit(uint64(shared_n))
emit(mov_m_rax)
emit(pop_rax); emit(uint64(0xDEAD))
emit(pop_rdi); emit(uint64(shared_n + 16))
emit(mov_m_rax)
emit(pop_rdi); emit(Z)
emit(pop_rax); emit(uint64(431))
emit(fn_addr)

pcall(function() sc455(uint64(N(tp)), uint64(0x38)) end)

-- Wait for done
for w = 1, 5000 do
    if (rd(shared_n + 16) or 0) ~= 0 then break end
    if w % 100 == 0 then pcall(function() sc331() end) end
end

-- Read value and try different comparisons
local raw = rd(shared_n)
print("  raw value: " .. tostring(raw))
print("  type: " .. type(raw))
print("  == 0xBEEF: " .. tostring(raw == 0xBEEF))
print("  == 48879: " .. tostring(raw == 48879))
print("  == tonumber('0xBEEF'): " .. tostring(raw == tonumber("0xBEEF")))

-- Also try reading as raw pcall without N()
local ok_raw, raw2 = pcall(function() return memory.read_dword(shared_n) end)
print("  raw2 type: " .. type(raw2))
print("  raw2 value: " .. tostring(raw2))
if type(raw2) == "number" then
    print("  raw2 == 0xBEEF: " .. tostring(raw2 == 0xBEEF))
elseif type(raw2) == "table" then
    print("  raw2.tonumber: " .. tostring(raw2:tonumber()))
    print("  raw2:tonumber() == 0xBEEF: " .. tostring(raw2:tonumber() == 0xBEEF))
end

print("")
print("pid_final=" .. N(sc20()))
print("=== 555e DONE ===")
