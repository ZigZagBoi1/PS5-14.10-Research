-- CRASH_CLASS: MODERATE
-- PROBE 392d: BSD data returners (no read_qword — fixes output corruption)
--
-- 392b/392c crashed because memory.read_qword output corrupts stdout.
-- This probe uses ONLY read_dword. Kptr check: two adjacent dwords.

print("=== PROBE 392d: BSD safe ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end
local function fill_sent(buf, len)
    for i = 0, len - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end
end
local function write_str(buf, s)
    zero_buf(buf, (#s + 8) - ((#s + 8) % 4))
    for i = 0, #s - 1, 4 do
        local dw = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #s then dw = dw + string.byte(s, idx) * (256 ^ j) end
        end
        wd(N(buf) + i, dw)
    end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

-- Kptr scan using ONLY read_dword (no read_qword)
-- On x86-64 little-endian: qword at addr = lo dword at addr, hi dword at addr+4
local function scan_safe(base, len, label)
    local baddr = N(base)
    local mod = 0
    local kptrs = 0
    for off = 0, len - 4, 4 do
        local d = rd(baddr + off)
        if d ~= nil and d ~= 0xDEADDEAD then mod = mod + 1 end
    end
    -- Check qwords as two dwords: hi at off+4, lo at off
    for off = 0, len - 8, 8 do
        local lo = rd(baddr + off)
        local hi = rd(baddr + off + 4)
        if hi ~= nil and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            kptrs = kptrs + 1
            if kptrs <= 5 then
                print(string.format("  %s +0x%03X: hi=%08X lo=%08X ***KPTR***",
                    label, off, hi, lo or 0))
            end
        end
    end
    return mod, kptrs
end

-- ===================================================================
-- [A] sc125 quick verify
-- ===================================================================
print("[A] sc125")
local buf = memory.alloc(0x400)
fill_sent(buf, 0x400)
local ok_a, rv_a = pcall(function() return mk(125)(buf, uint64(0x400)) end)
local ret_a = ok_a and N(rv_a) or -999
local m_a, k_a = scan_safe(buf, 0x400, "sc125")
print(string.format("  ret=%d mod=%d kptrs=%d", ret_a, m_a, k_a))
if not alive() then print("DEAD"); return end
print("")

-- ===================================================================
-- [B] fstatfs(397) with real fds
-- ===================================================================
print("[B] fstatfs(397)")

local dev_buf = memory.alloc(32)

write_str(dev_buf, "/dev/null")
local null_fd = -1
local ok_n, rv_n = pcall(function() return mk(5)(dev_buf, uint64(0), uint64(0)) end)
if ok_n then null_fd = N(rv_n) end

write_str(dev_buf, "/dev/dce")
local dce_fd = -1
local ok_d, rv_d = pcall(function() return mk(5)(dev_buf, uint64(2), uint64(0)) end)
if ok_d then dce_fd = N(rv_d) end

local shm_fd = -1
local ok_s, rv_s = pcall(function()
    return mk(482)(uint64(1), uint64(0x202), uint64(0x180))
end)
if ok_s then shm_fd = N(rv_s) end

local sock_fd = -1
local ok_sk, rv_sk = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
if ok_sk then sock_fd = N(rv_sk) end

print(string.format("  fds: null=%d dce=%d shm=%d sock=%d",
    null_fd, dce_fd, shm_fd, sock_fd))

local statfs_buf = memory.alloc(0x300)
local fds = {}
if null_fd >= 0 then fds[#fds+1] = {null_fd, "null"} end
if dce_fd >= 0 then fds[#fds+1] = {dce_fd, "dce"} end
if shm_fd >= 0 then fds[#fds+1] = {shm_fd, "shm"} end
if sock_fd >= 0 then fds[#fds+1] = {sock_fd, "sock"} end

for _, fi in ipairs(fds) do
    if not alive() then break end
    fill_sent(statfs_buf, 0x300)
    local ok_f, rv_f = pcall(function()
        return mk(397)(uint64(fi[1]), statfs_buf)
    end)
    local ret = ok_f and N(rv_f) or -999
    local m, k = scan_safe(statfs_buf, 0x300, fi[2])
    print(string.format("  fstatfs(%s fd=%d): ret=%d mod=%d kptrs=%d",
        fi[2], fi[1], ret, m, k))

    if ret == 0 and m > 0 then
        local fver = rd(N(statfs_buf)) or 0
        local ftype = rd(N(statfs_buf) + 4) or 0
        local flags = rd(N(statfs_buf) + 8) or 0
        print(string.format("    ver=%d type=%d flags=0x%X", fver, ftype, flags))
        -- f_fstypename at +0x24 (16 chars)
        local fsname = ""
        for i = 0, 12, 4 do
            local d = rd(N(statfs_buf) + 0x24 + i)
            if d and d ~= 0 then
                for b = 0, 3 do
                    local c = math.floor(d / (256^b)) % 256
                    if c > 0 and c < 128 then fsname = fsname .. string.char(c) end
                end
            end
        end
        if #fsname > 0 then print("    fstype: " .. fsname) end
        -- f_mntonname at +0x34 (1024 chars) — just first 32
        local mnt = ""
        for i = 0, 28, 4 do
            local d = rd(N(statfs_buf) + 0x34 + i)
            if d and d ~= 0 then
                for b = 0, 3 do
                    local c = math.floor(d / (256^b)) % 256
                    if c > 0 and c < 128 then mnt = mnt .. string.char(c) end
                end
            end
        end
        if #mnt > 0 then print("    mntpoint: " .. mnt) end
    end
end

for _, fi in ipairs(fds) do pcall(function() mk(6)(uint64(fi[1])) end) end
if not alive() then print("DEAD [B]"); return end
print("")

-- ===================================================================
-- [C] getfsstat(395) — filesystem listing
-- ===================================================================
print("[C] getfsstat(395)")

local ok_c1, rv_c1 = pcall(function()
    return mk(395)(uint64(0), uint64(0), uint64(2))
end)
local count = ok_c1 and N(rv_c1) or -1
print(string.format("  count=%d", count))

local ok_c2, rv_c2 = pcall(function()
    return mk(396)(uint64(0), uint64(0), uint64(2))
end)
print(string.format("  getfsstat(396): ret=%d", ok_c2 and N(rv_c2) or -999))

if count > 0 and count < 50 and alive() then
    local fsbuf = memory.alloc(0x4000)
    fill_sent(fsbuf, 0x4000)
    local ok_c3, rv_c3 = pcall(function()
        return mk(395)(fsbuf, uint64(0x4000), uint64(2))
    end)
    local ret_c3 = ok_c3 and N(rv_c3) or -1
    local m, k = scan_safe(fsbuf, 0x4000, "fsstat")
    print(string.format("  getfsstat(buf): ret=%d mod=%d kptrs=%d", ret_c3, m, k))
end

if not alive() then print("DEAD [C]"); return end
print("")

-- ===================================================================
-- [D] Unnamed slot sweep
-- ===================================================================
print("[D] slots")

local test_buf = memory.alloc(0x200)
local hits = 0

local unnamed = {91, 94, 119, 151, 152, 153, 159, 167, 168, 172,
    177, 178, 179, 180, 184, 185, 186, 187,
    364, 365, 366, 367, 368, 369, 370, 375,
    380, 381, 382, 383, 418, 419, 420,
    434, 435, 440, 467, 468, 469, 470}

for _, num in ipairs(unnamed) do
    if not alive() then break end

    fill_sent(test_buf, 0x200)
    local ok1, rv1 = pcall(function()
        return mk(num)(test_buf, uint64(0x200))
    end)
    local ret1 = ok1 and N(rv1) or -999

    if ret1 >= 0 then
        local m, k = scan_safe(test_buf, 0x200, tostring(num))
        print(string.format("  %d(buf,sz): ret=%d mod=%d kptrs=%d", num, ret1, m, k))
        hits = hits + 1
    end

    if ret1 < 0 and alive() then
        fill_sent(test_buf, 0x200)
        local ok2, rv2 = pcall(function()
            return mk(num)(uint64(0), test_buf, uint64(0x200))
        end)
        local ret2 = ok2 and N(rv2) or -999
        if ret2 >= 0 then
            local m, k = scan_safe(test_buf, 0x200, tostring(num))
            print(string.format("  %d(0,buf,sz): ret=%d mod=%d kptrs=%d", num, ret2, m, k))
            hits = hits + 1
        end
    end

    if alive() then
        fill_sent(test_buf, 0x200)
        local ok3, rv3 = pcall(function()
            return mk(num)(uint64(pid_val), test_buf, uint64(0x200))
        end)
        local ret3 = ok3 and N(rv3) or -999
        if ret3 >= 0 and ret1 < 0 then
            local m, k = scan_safe(test_buf, 0x200, tostring(num))
            print(string.format("  %d(pid,buf,sz): ret=%d mod=%d kptrs=%d", num, ret3, m, k))
            hits = hits + 1
        end
    end
end

if hits == 0 then
    print("  40 slots: all -1")
else
    print(string.format("  %d responded", hits))
end

if not alive() then print("DEAD [D]"); return end
print("")

-- ===================================================================
-- [E] Misc BSD
-- ===================================================================
print("[E] misc")

local tname = memory.alloc(32)
write_str(tname, "exploit")
local ok_tn, rv_tn = pcall(function()
    return mk(464)(uint64(0), tname, uint64(7))
end)
print(string.format("  thr_set_name(464): %d", ok_tn and N(rv_tn) or -999))

local ok_ar, rv_ar = pcall(function() return mk(314)(uint64(0)) end)
print(string.format("  aio_return(314): %d", ok_ar and N(rv_ar) or -999))

local clkid = memory.alloc(8)
fill_sent(clkid, 8)
local ok_clk, rv_clk = pcall(function()
    return mk(247)(uint64(pid_val), uint64(0), clkid)
end)
print(string.format("  clock_getcpuid(247): %d", ok_clk and N(rv_clk) or -999))
if (ok_clk and N(rv_clk) or -1) == 0 then
    print(string.format("    clockid=%d", rd(N(clkid)) or -1))
end

local cr = memory.alloc(0x40)
fill_sent(cr, 0x40)
local ok_cap, rv_cap = pcall(function()
    return mk(515)(uint64(0), uint64(0), cr)
end)
print(string.format("  cap_rights_get(515): %d", ok_cap and N(rv_cap) or -999))

local ok_sp, rv_sp = pcall(function() return mk(328)(uint64(0), test_buf) end)
print(string.format("  sched_getparam(328): %d", ok_sp and N(rv_sp) or -999))

local ok_ss, rv_ss = pcall(function() return mk(329)(uint64(0)) end)
print(string.format("  sched_getsched(329): %d", ok_ss and N(rv_ss) or -999))

-- socketex(113) quick test
local ok_se, rv_se = pcall(function()
    return mk(113)(uint64(2), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  socketex(113): %d", ok_se and N(rv_se) or -999))

-- socketclose(114) with a fresh socket
if (ok_se and N(rv_se) or -1) >= 0 then
    local fd113 = N(rv_se)
    local ok_sc, rv_sc = pcall(function() return mk(114)(uint64(fd113)) end)
    print(string.format("  socketclose(114, %d): %d", fd113, ok_sc and N(rv_sc) or -999))
else
    local tfd = -1
    local ok_tf, rv_tf = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(0))
    end)
    if ok_tf then tfd = N(rv_tf) end
    if tfd >= 0 then
        local ok_sc2, rv_sc2 = pcall(function() return mk(114)(uint64(tfd)) end)
        print(string.format("  socketclose(114, sock %d): %d", tfd, ok_sc2 and N(rv_sc2) or -999))
    end
end

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 392d COMPLETE ===")
