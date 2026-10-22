-- CRASH_CLASS: LOW
-- PROBE 126a: fstat on device fds + AIO real IDs via 669
--
-- ng643 PR #99 shows: fstat(189) works with SIGSYS ignored.
-- ng643 PR #98 shows: sys 669 is the batch AIO submit.
--
-- This probe:
-- [A] Install SIG_IGN for SIGSYS (signal 12) via sigaction(416)
-- [B] fstat(189) on device fds — look for kernel pointers in stat struct
-- [C] AIO submit via 669 — create real IDs
-- [D] AIO poll via 664 — check if pointer leak is in status struct

print("=== PROBE 126a: FSTAT DEVICES + AIO REAL IDS ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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
local function is_kptr(h)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end
local function put_path(base, s)
    local off = 0
    local dw = 0
    local shift = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        dw = dw + b * (2 ^ shift)
        shift = shift + 8
        if shift == 32 then
            wd(base + off, dw)
            off = off + 4
            dw = 0
            shift = 0
        end
    end
    dw = dw + 0 * (2 ^ shift)
    shift = shift + 8
    if shift <= 32 then
        wd(base + off, dw)
    end
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc_sigaction = mk(416)
local sc_fstat     = mk(189)
local sc_open      = mk(5)
local sc_close     = mk(6)
local sc669        = mk(669)
local sc664        = mk(664)
local sc670        = mk(670)
local sc662        = mk(662)

-- [A] Install SIG_IGN for SIGSYS (signal 12)
print("[A] sigaction(12, SIG_IGN)")
local sa_buf = memory.alloc(0x40)
local SA = N(sa_buf)
for i = 0, 0x3F, 4 do wd(SA + i, 0) end
-- struct sigaction: sa_handler at +0 (8 bytes), sa_flags at +8 (4 bytes), sa_mask at +12
wq(SA, uint64(1))  -- SIG_IGN = 1
wd(SA + 8, 0)      -- no flags
local ok_sa, rv_sa = pcall(function()
    return sc_sigaction(uint64(12), sa_buf, uint64(0))
end)
print("  ret=" .. (ok_sa and tostring(N(rv_sa)) or "PFAIL"))

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [B] fstat on device fds
print("")
print("[B] fstat on device fds")
local pathbuf = memory.alloc(0x100)
local stat_buf = memory.alloc(0x200)
local STAT = N(stat_buf)

local devs = {
    {"/dev/dmem0", 0x0002},
    {"/dev/gc",    0x0002},
    {"/dev/dce",   0x0000},
    {"/dev/rng",   0x0000},
    {"/dev/zero",  0x0000},
}

for _, dev in ipairs(devs) do
    repeat
    local path, flags = dev[1], dev[2]

    put_path(N(pathbuf), path)
    local ok_o, fd = pcall(function()
        return sc_open(pathbuf, uint64(flags), uint64(0))
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then print("  DIED on open " .. path) return end
    if not ok_o or N(fd) < 0 then
        print("  " .. path .. ": open failed")
        break
    end
    local fd_n = N(fd)

    -- Zero stat buffer
    for i = 0, 0x1FF, 4 do wd(STAT + i, 0) end

    local ok_f, rv_f = pcall(function()
        return sc_fstat(uint64(fd_n), stat_buf)
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then print("  DIED on fstat " .. path) return end

    if ok_f and N(rv_f) == 0 then
        print(string.format("  %s fd=%d: fstat=OK", path, fd_n))
        -- Dump key fields of struct stat (FreeBSD)
        -- +0x00: st_dev (8)
        -- +0x08: st_ino (8)
        -- +0x10: st_nlink (8)
        -- +0x18: st_mode (2) + pad
        -- +0x30: st_size (8)
        -- Scan full 256 bytes for kernel pointers
        local kptrs = {}
        for i = 0, 0xFC, 4 do
            local lo = rd(STAT + i) or 0
            local hi = rd(STAT + i + 4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if is_kptr(hi) and lo ~= 0 then
                kptrs[#kptrs + 1] = {i, hi, lo}
            end
        end
        if #kptrs > 0 then
            for _, k in ipairs(kptrs) do
                print(string.format("    +%02X: 0x%08X%08X *** KERNEL PTR ***", k[1], k[2], k[3]))
            end
        end
        -- Print first 128 bytes hex dump
        local line = "    "
        for i = 0, 0x7C, 4 do
            local v = rd(STAT + i) or 0
            if v < 0 then v = v + 0x100000000 end
            line = line .. string.format("%08X ", v)
            if (i + 4) % 32 == 0 then
                print(line)
                line = "    "
            end
        end
        if #line > 4 then print(line) end
    else
        print(string.format("  %s fd=%d: fstat ret=%s", path, fd_n,
            ok_f and tostring(N(rv_f)) or "PFAIL"))
    end

    pcall(function() sc_close(uint64(fd_n)) end)
    until true
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [C] AIO init + submit via 669
print("")
print("[C] AIO init + submit (669)")

-- Init AIO
local ok_670, rv_670 = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("  670 init ret=" .. (ok_670 and tostring(N(rv_670)) or "PFAIL"))

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after 670!") return end

-- Open a file to read via AIO
put_path(N(pathbuf), "/dev/zero")
local ok_zfd, zfd = pcall(function()
    return sc_open(pathbuf, uint64(0), uint64(0))
end)
if not ok_zfd or N(zfd) < 0 then
    print("  /dev/zero open failed")
else
    local zfd_n = N(zfd)
    print("  /dev/zero fd=" .. zfd_n)

    -- Build AIO request descriptor (stride 0x28 = 40 bytes)
    local aio_buf = memory.alloc(0x1000)
    local AIO = N(aio_buf)
    local data_buf = memory.alloc(0x4000)
    local DATA = N(data_buf)
    local ids_buf = memory.alloc(0x100)
    local IDS = N(ids_buf)

    -- Zero everything
    for i = 0, 0xFF, 4 do wd(AIO + i, 0) end
    for i = 0, 0xFF, 4 do wd(IDS + i, 0) end

    -- Descriptor at AIO+0 (stride 0x28):
    -- Layout from ng643's 352a analysis:
    -- +0x00: fd (4 bytes)
    -- +0x04: flags? (4 bytes)
    -- +0x08: buffer ptr (8 bytes)
    -- +0x10: offset (8 bytes)
    -- +0x18: nbytes (8 bytes)
    -- +0x20: priority? (8 bytes)
    wd(AIO + 0x00, zfd_n)        -- fd
    wd(AIO + 0x04, 0)            -- flags
    wq(AIO + 0x08, data_buf)     -- buffer
    wq(AIO + 0x10, uint64(0))    -- offset
    wq(AIO + 0x18, uint64(0x10)) -- nbytes = 16
    wq(AIO + 0x20, uint64(0))    -- priority

    -- 669(cmd=1, reqs, count=1, class=1, ids)
    -- cmd=1 is read
    local ok_669, rv_669 = pcall(function()
        return sc669(uint64(1), aio_buf, uint64(1), uint64(1), ids_buf)
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then print("  DIED on 669!") return end

    local id0 = rd(IDS) or 0
    local id1 = rd(IDS + 4) or 0
    if id0 < 0 then id0 = id0 + 0x100000000 end
    if id1 < 0 then id1 = id1 + 0x100000000 end
    print(string.format("  669 ret=%s id[0]=0x%08X%08X",
        ok_669 and tostring(N(rv_669)) or "PFAIL", id1, id0))

    -- [D] Poll with 664 using the real ID
    if id0 ~= 0 or id1 ~= 0 then
        print("")
        print("[D] AIO poll (664) with real ID")
        local poll_buf = memory.alloc(0x100)
        local POLL = N(poll_buf)
        for i = 0, 0xFF, 4 do wd(POLL + i, 0) end

        -- 664(ids, count, results)
        local ok_664, rv_664 = pcall(function()
            return sc664(ids_buf, uint64(1), poll_buf)
        end)
        c = N(native.fcall_with_rax(stub, 20))
        if c ~= pid then print("  DIED on 664!") return end

        print("  664 ret=" .. (ok_664 and tostring(N(rv_664)) or "PFAIL"))

        -- Dump poll result
        local kptrs_664 = {}
        for i = 0, 0x3C, 4 do
            local v = rd(POLL + i) or 0
            if v < 0 then v = v + 0x100000000 end
            if v ~= 0 then
                print(string.format("    +%02X: 0x%08X", i, v))
            end
            -- Check qword pairs for kernel pointers
            if i % 8 == 0 then
                local hi = rd(POLL + i + 4) or 0
                if hi < 0 then hi = hi + 0x100000000 end
                if is_kptr(hi) and v ~= 0 then
                    kptrs_664[#kptrs_664 + 1] = {i, hi, v}
                end
            end
        end
        for _, k in ipairs(kptrs_664) do
            print(string.format("    +%02X: 0x%08X%08X *** KERNEL PTR ***", k[1], k[2], k[3]))
        end

        -- Also try 662 with the real ID now
        print("")
        print("[E] AIO delete (662) with real ID")
        local del_res = memory.alloc(0x100)
        local DEL = N(del_res)
        for i = 0, 0x3F, 4 do wd(DEL + i, 0) end

        local ok_662, rv_662 = pcall(function()
            return sc662(ids_buf, uint64(1), del_res)
        end)
        c = N(native.fcall_with_rax(stub, 20))
        if c ~= pid then print("  DIED on 662!") return end

        print("  662 ret=" .. (ok_662 and tostring(N(rv_662)) or "PFAIL"))
        -- Dump delete result
        for i = 0, 0x1C, 4 do
            local v = rd(DEL + i) or 0
            if v < 0 then v = v + 0x100000000 end
            if v ~= 0 then
                print(string.format("    +%02X: 0x%08X", i, v))
            end
        end
    end

    pcall(function() sc_close(uint64(zfd_n)) end)
end

print("")
c = N(native.fcall_with_rax(stub, 20))
print("canary=" .. (c == pid and "OK" or "FAIL"))
print("=== 126a COMPLETE ===")
