-- CRASH_CLASS: MODERATE
-- PROBE 93d3: kevent untried filters + Sony syscall arg fuzzing
--
-- A) kevent with EVFILT_PROC(-5), EVFILT_SIGNAL(-6), EVFILT_USER(-11),
--    EVFILT_AIO(-3) — some may leak kernel addresses in output
-- B) Sony syscalls 596, 585, 606, 640 with large output buffers
--    and boundary values looking for info leaks
-- C) sys 643 with specific bit patterns — it writes to process+0xa34,
--    test if certain bits change kernel behavior we can observe

print("=== PROBE 93d3: KEVENT FILTERS + SONY FUZZ ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function scan_kptrs(buf, size, label)
    local count = 0
    for off = 0, size - 8, 4 do
        local lo = rd(N(buf) + off) or 0
        local hi = rd(N(buf) + off + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            count = count + 1
            if count <= 3 then
                print(string.format("  [KPTR!] %s +0x%X: 0x%08X%08X", label, off, hi, lo))
            end
        end
    end
    return count
end

-- ========== SECTION A: kevent with untried filters ==========
print("--- A: kevent untried filters ---")

local kq_ok, kq_rv = pcall(function() return mk(362)() end)
local kq = kq_ok and N(kq_rv) or -1
print("kq=" .. kq)

if kq >= 0 then
    local filters = {
        {name="EVFILT_AIO", val=-3, ident=0, fflags=0, data=0},
        {name="EVFILT_PROC", val=-5, ident=pid_val, fflags=0x7F, data=0},  -- NOTE_EXIT|FORK|EXEC|...
        {name="EVFILT_SIGNAL", val=-6, ident=14, fflags=0, data=0},  -- SIGALRM
        {name="EVFILT_USER", val=-11, ident=1, fflags=0x01000001, data=0},  -- NOTE_TRIGGER|NOTE_FFNOP
    }

    for _, f in ipairs(filters) do
        -- Register the filter
        local kev_in = memory.alloc(48)
        -- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8) = 32 bytes
        -- Actually FreeBSD kevent is different sized. Let's use the known 48-byte struct
        wq(N(kev_in), uint64(f.ident))        -- ident
        -- filter is int16 at +8, flags is uint16 at +10
        local filter_val = f.val
        if filter_val < 0 then filter_val = filter_val + 0x10000 end
        wd(N(kev_in) + 8, filter_val + 0x00050000)  -- filter | flags=EV_ADD|EV_ENABLE(5)<<16
        -- Wait, kevent struct packing: filter is at +8 (int16), flags at +10 (uint16)
        wd(N(kev_in) + 8, 0)
        -- Set filter (int16 at +8)
        local filt_u16 = f.val < 0 and (f.val + 0x10000) or f.val
        -- flags = EV_ADD(1) | EV_ENABLE(4) | EV_ONESHOT(0x10) = 0x15
        -- Pack as: filter(lo16) | flags(hi16)
        wd(N(kev_in) + 8, filt_u16 + 0x00050000)  -- filter + (EV_ADD|EV_ENABLE)<<16
        wd(N(kev_in) + 12, f.fflags)              -- fflags
        wq(N(kev_in) + 16, uint64(f.data))        -- data
        wq(N(kev_in) + 24, uint64(0))             -- udata

        -- Output kevent + sentinel fill
        local kev_out = memory.alloc(64)
        for i = 0, 60, 4 do wd(N(kev_out) + i, 0xDEADDEAD) end

        -- Timespec {0, 0} for immediate return
        local ts = memory.alloc(16)
        wq(N(ts), uint64(0))
        wq(N(ts) + 8, uint64(0))

        -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
        local ok_k, rv_k = pcall(function()
            return mk(363)(uint64(kq), kev_in, uint64(1), kev_out, uint64(1), ts)
        end)
        local kret = ok_k and N(rv_k) or -999
        if kret >= 0x80000000 then kret = kret - 0x100000000 end

        -- Check what was written to output
        local out_changed = false
        local kptrs = 0
        for i = 0, 44, 4 do
            local v = rd(N(kev_out) + i) or 0xDEADDEAD
            if v ~= 0xDEADDEAD then out_changed = true end
        end
        if out_changed then
            kptrs = scan_kptrs(kev_out, 48, f.name)
        end

        -- Dump first 32 bytes if anything changed
        local dump = ""
        if out_changed then
            for i = 0, 28, 4 do
                local v = rd(N(kev_out) + i)
                if v then
                    if v < 0 then v = v + 0x100000000 end
                    dump = dump .. string.format("%08X ", v)
                end
            end
        end

        print(string.format("  %s: ret=%d changed=%s kptrs=%d %s",
            f.name, kret, tostring(out_changed), kptrs, dump))

        if not alive() then print("  DEAD!"); break end
    end

    -- Also try EVFILT_USER with NOTE_TRIGGER to fire it
    if alive() then
        local kev_trig = memory.alloc(48)
        wq(N(kev_trig), uint64(1))  -- ident=1
        wd(N(kev_trig) + 8, 0xFFF5 + 0x00010000)  -- EVFILT_USER(-11) + EV_ADD
        wd(N(kev_trig) + 12, 0x01000001)  -- NOTE_TRIGGER | NOTE_FFNOP

        local ok_t, rv_t = pcall(function()
            return mk(363)(uint64(kq), kev_trig, uint64(1), uint64(0), uint64(0), uint64(0))
        end)
        local tret = ok_t and N(rv_t) or -999

        -- Now poll for the triggered event
        local kev_out2 = memory.alloc(64)
        for i = 0, 60, 4 do wd(N(kev_out2) + i, 0xDEADDEAD) end
        local ts2 = memory.alloc(16)
        wq(N(ts2), uint64(0)); wq(N(ts2) + 8, uint64(0))

        local ok_p, rv_p = pcall(function()
            return mk(363)(uint64(kq), uint64(0), uint64(0), kev_out2, uint64(1), ts2)
        end)
        local pret = ok_p and N(rv_p) or -999

        local dump2 = ""
        for i = 0, 28, 4 do
            local v = rd(N(kev_out2) + i) or 0xDEADDEAD
            if v < 0 then v = v + 0x100000000 end
            dump2 = dump2 .. string.format("%08X ", v)
        end
        local kp2 = scan_kptrs(kev_out2, 48, "USER_TRIG")
        print(string.format("  EVFILT_USER triggered: add=%d poll=%d kptrs=%d %s",
            tret, pret, kp2, dump2))
    end

    pcall(function() mk(6)(uint64(kq)) end)
end

if not alive() then print("DEAD!"); return end

-- ========== SECTION B: Sony syscall info leak probing ==========
print("")
print("--- B: Sony syscall output buffer probing ---")

-- Test accessible Sony syscalls with large sentinel-filled output buffers
local sony_tests = {
    -- {sysno, name, {arg patterns to try}}
    {596, "budgets_info", {
        {0, 0, 0, 0, 0, 0},
        {0, 0x1000, 0, 0, 0, 0},  -- maybe (outbuf, size, ...)
    }},
    {585, "get_proc_type_info", {
        {0, 0, 0, 0, 0, 0},
        {pid_val, 0, 0, 0, 0, 0},
    }},
    {606, "get_authinfo", {
        {pid_val, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0},
    }},
    {640, "workaround", {
        {0, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 0, 0},
    }},
}

for _, st in ipairs(sony_tests) do
    print(string.format("  sys %d (%s):", st[1], st[2]))
    local sc = mk(st[1])

    for pi, pattern in ipairs(st[3]) do
        -- Allocate output buffer with sentinels
        local outbuf = memory.alloc(0x200)
        for i = 0, 0x1FC, 4 do wd(N(outbuf) + i, 0xDEADDEAD) end

        -- Build args, substituting outbuf address for zero args
        local args = {}
        for i = 1, 6 do
            if pattern[i] == 0 and i <= 2 then
                args[i] = uint64(N(outbuf))
            else
                args[i] = uint64(pattern[i])
            end
        end

        local ok_s, rv_s = pcall(function()
            return sc(args[1], args[2], args[3], args[4], args[5], args[6])
        end)
        local sret = ok_s and N(rv_s) or -999
        if sret >= 0x80000000 then sret = sret - 0x100000000 end

        -- Count modified bytes
        local modified = 0
        for i = 0, 0x1FC, 4 do
            local v = rd(N(outbuf) + i) or 0xDEADDEAD
            if v ~= 0xDEADDEAD then modified = modified + 4 end
        end

        local kptrs = 0
        if modified > 0 then
            kptrs = scan_kptrs(outbuf, 0x200, string.format("sys%d_p%d", st[1], pi))
        end

        -- First 32 modified bytes
        local dump = ""
        if modified > 0 then
            local shown = 0
            for i = 0, 0x1FC, 4 do
                local v = rd(N(outbuf) + i) or 0xDEADDEAD
                if v ~= 0xDEADDEAD and shown < 8 then
                    if v < 0 then v = v + 0x100000000 end
                    dump = dump .. string.format("+%X=%08X ", i, v)
                    shown = shown + 1
                end
            end
        end

        print(string.format("    p%d: ret=%d mod=%dB kptrs=%d %s",
            pi, sret, modified, kptrs, dump))

        if not alive() then break end
    end
    if not alive() then break end
end

if not alive() then print("DEAD!"); return end

-- ========== SECTION C: sys 643 bit exploration ==========
print("")
print("--- C: sys 643 bit-by-bit effects ---")

-- 643 ORs its argument into process+0xa34
-- Test individual bits to see if any have observable effects
-- beyond what was tested (mprotect, fork, kldstat all unchanged)
-- Try: socket creation, memory allocation behavior, sysctl access

-- First set all bits
local ok_643, rv_643 = pcall(function()
    return mk(643)(uint64(0xFFFFFFFF))
end)
print(string.format("643(0xFFFFFFFF) ret=%d", ok_643 and N(rv_643) or -999))

-- Test effects after setting all bits:
-- 1. Can we now access blocked syscalls?
local blocked_tests = {
    {672, "dynlinker_list"},
    {676, "cpu_mode"},
    {673, "page_remap"},
}

for _, bt in ipairs(blocked_tests) do
    local ok_b, rv_b = pcall(function()
        return mk(bt[1])(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local bret = ok_b and N(rv_b) or -999
    if bret >= 0x80000000 then bret = bret - 0x100000000 end
    print(string.format("  %s(%d): ret=%d", bt[2], bt[1], bret))
end

-- 2. Does mmap behavior change?
local ok_mm, rv_mm = pcall(function()
    return mk(477)(uint64(0), uint64(0x4000), uint64(7),  -- PROT_RWX
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local mm_ret = ok_mm and N(rv_mm) or -999
print(string.format("  mmap(RWX) after 643: ret=0x%X", mm_ret))
if mm_ret ~= 0 and mm_ret < 0x80000000 then
    -- Mapped! Check if we can execute
    print("  [!] RWX mapping succeeded! Testing execute...")
    -- Write ret instruction
    wd(mm_ret, 0x90C3)  -- ret; nop
    -- Try to call it... this would be huge
end

-- 3. Try mprotect to RWX on existing RW page
local test_page = memory.alloc(0x4000)
local ok_mp, rv_mp = pcall(function()
    return mk(74)(uint64(N(test_page)), uint64(0x4000), uint64(7))  -- PROT_RWX
end)
local mp_ret = ok_mp and N(rv_mp) or -999
if mp_ret >= 0x80000000 then mp_ret = mp_ret - 0x100000000 end
print(string.format("  mprotect(RWX) after 643: ret=%d", mp_ret))

if not alive() then print("DEAD!"); return end

-- ========== SECTION D: sys 587 credential deep scan ==========
print("")
print("--- D: sys 587 credential with all PIDs ---")

-- 587 returns credential info. Try reading other processes' credentials
-- if 643 unlocked anything
local cred_buf = memory.alloc(0x200)
local pids_to_try = {0, 1, 2, pid_val}

for _, test_pid in ipairs(pids_to_try) do
    for i = 0, 0x1FC, 4 do wd(N(cred_buf) + i, 0xDEADDEAD) end

    local ok_c, rv_c = pcall(function()
        return mk(587)(uint64(test_pid), cred_buf, uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local cret = ok_c and N(rv_c) or -999
    if cret >= 0x80000000 then cret = cret - 0x100000000 end

    local modified = 0
    for i = 0, 0x1FC, 4 do
        if (rd(N(cred_buf) + i) or 0xDEADDEAD) ~= 0xDEADDEAD then modified = modified + 4 end
    end

    local kptrs = 0
    if modified > 0 then kptrs = scan_kptrs(cred_buf, 0x200, "cred_" .. test_pid) end

    -- Show interesting bytes
    local dump = ""
    if modified > 0 then
        local shown = 0
        for i = 0, math.min(0x8C, 0x1FC), 4 do
            local v = rd(N(cred_buf) + i) or 0xDEADDEAD
            if v ~= 0xDEADDEAD and shown < 6 then
                if v < 0 then v = v + 0x100000000 end
                dump = dump .. string.format("+%X=%08X ", i, v)
                shown = shown + 1
            end
        end
    end

    print(string.format("  pid=%d: ret=%d mod=%dB kptrs=%d %s",
        test_pid, cret, modified, kptrs, dump))
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93d3 COMPLETE ===")
