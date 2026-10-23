-- CRASH_CLASS: MODERATE
-- PROBE 392e: BSD calls — return values only, no buffer scanning
--
-- 392b-392d crash when scanning certain syscall output buffers.
-- This probe: report ret values only, defer buffer scans.

print("=== PROBE 392e: BSD noscan ===")
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

-- Kptr scan: ONLY check first 8 dwords of the buffer, no full scan
local function quick_kptr(base, label)
    local baddr = N(base)
    local found = 0
    -- Check first 64 bytes (8 qwords)
    for off = 0, 56, 8 do
        local lo = rd(baddr + off)
        local hi = rd(baddr + off + 4)
        if hi ~= nil and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            found = found + 1
        end
    end
    return found
end

-- ===================================================================
-- [A] fstatfs(397) — just ret values
-- ===================================================================
print("[A] fstatfs(397)")

local dev_buf = memory.alloc(32)
local statfs_buf = memory.alloc(0x300)

-- /dev/null
write_str(dev_buf, "/dev/null")
local ok1, rv1 = pcall(function() return mk(5)(dev_buf, uint64(0), uint64(0)) end)
local null_fd = ok1 and N(rv1) or -1

-- shm
local ok2, rv2 = pcall(function()
    return mk(482)(uint64(1), uint64(0x202), uint64(0x180))
end)
local shm_fd = ok2 and N(rv2) or -1

-- socket
local ok3, rv3 = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local sock_fd = ok3 and N(rv3) or -1

print(string.format("  fds: null=%d shm=%d sock=%d", null_fd, shm_fd, sock_fd))

local test_fds = {}
if null_fd >= 0 then test_fds[#test_fds+1] = {null_fd, "null"} end
if shm_fd >= 0 then test_fds[#test_fds+1] = {shm_fd, "shm"} end
if sock_fd >= 0 then test_fds[#test_fds+1] = {sock_fd, "sock"} end

for _, fi in ipairs(test_fds) do
    if not alive() then break end
    zero_buf(statfs_buf, 0x300)
    local ok_f, rv_f = pcall(function()
        return mk(397)(uint64(fi[1]), statfs_buf)
    end)
    local ret = ok_f and N(rv_f) or -999
    -- Only read first dword to check if data was written
    local d0 = rd(N(statfs_buf))
    local wrote = (d0 ~= nil and d0 ~= 0) and "data" or "empty"
    print(string.format("  fstatfs(%s fd=%d): ret=%d %s", fi[2], fi[1], ret, wrote))
end

for _, fi in ipairs(test_fds) do pcall(function() mk(6)(uint64(fi[1])) end) end
if not alive() then print("DEAD [A]"); return end
print("")

-- ===================================================================
-- [B] getfsstat(395)
-- ===================================================================
print("[B] getfsstat(395)")

local ok_c1, rv_c1 = pcall(function()
    return mk(395)(uint64(0), uint64(0), uint64(2))
end)
local count = ok_c1 and N(rv_c1) or -1
print(string.format("  count=%d", count))

local ok_c2, rv_c2 = pcall(function()
    return mk(396)(uint64(0), uint64(0), uint64(2))
end)
print(string.format("  396 count=%d", ok_c2 and N(rv_c2) or -999))

if count > 0 and count < 50 and alive() then
    local fsbuf = memory.alloc(0x4000)
    zero_buf(fsbuf, 0x100)  -- Only zero first 256 bytes
    local ok_c3, rv_c3 = pcall(function()
        return mk(395)(fsbuf, uint64(0x4000), uint64(2))
    end)
    local ret_c3 = ok_c3 and N(rv_c3) or -1
    local d0 = rd(N(fsbuf))
    local wrote = (d0 ~= nil and d0 ~= 0) and "data" or "empty"
    print(string.format("  getfsstat(buf): ret=%d %s", ret_c3, wrote))
end

if not alive() then print("DEAD [B]"); return end
print("")

-- ===================================================================
-- [C] Unnamed slot sweep — ret values only
-- ===================================================================
print("[C] slots")

local test_buf = memory.alloc(0x200)
local hits_pos = {}  -- slots that returned >= 0

local unnamed = {91, 94, 119, 151, 152, 153, 159, 167, 168, 172,
    177, 178, 179, 180, 184, 185, 186, 187,
    364, 365, 366, 367, 368, 369, 370, 375,
    380, 381, 382, 383, 418, 419, 420,
    434, 435, 440, 467, 468, 469, 470}

for _, num in ipairs(unnamed) do
    if not alive() then break end

    zero_buf(test_buf, 0x200)
    local ok1, rv1 = pcall(function()
        return mk(num)(test_buf, uint64(0x200))
    end)
    local ret1 = ok1 and N(rv1) or -999

    if ret1 >= 0 then
        hits_pos[#hits_pos+1] = string.format("%d(buf,sz)=%d", num, ret1)
    end

    if ret1 < 0 and alive() then
        zero_buf(test_buf, 0x200)
        local ok2, rv2 = pcall(function()
            return mk(num)(uint64(0), test_buf, uint64(0x200))
        end)
        local ret2 = ok2 and N(rv2) or -999
        if ret2 >= 0 then
            hits_pos[#hits_pos+1] = string.format("%d(0,buf,sz)=%d", num, ret2)
        end
    end

    if alive() then
        zero_buf(test_buf, 0x200)
        local ok3, rv3 = pcall(function()
            return mk(num)(uint64(pid_val), test_buf, uint64(0x200))
        end)
        local ret3 = ok3 and N(rv3) or -999
        if ret3 >= 0 and ret1 < 0 then
            hits_pos[#hits_pos+1] = string.format("%d(pid,buf,sz)=%d", num, ret3)
        end
    end
end

if #hits_pos == 0 then
    print("  40 slots: all -1")
else
    for _, h in ipairs(hits_pos) do print("  " .. h) end
end

if not alive() then print("DEAD [C]"); return end
print("")

-- ===================================================================
-- [D] Misc BSD — return values
-- ===================================================================
print("[D] misc")

-- thr_set_name(464)
local tname = memory.alloc(32)
write_str(tname, "exploit")
local ok_tn, rv_tn = pcall(function()
    return mk(464)(uint64(0), tname, uint64(7))
end)
print(string.format("  thr_set_name: %d", ok_tn and N(rv_tn) or -999))

-- aio_return(314)
local ok_ar, rv_ar = pcall(function() return mk(314)(uint64(0)) end)
print(string.format("  aio_return: %d", ok_ar and N(rv_ar) or -999))

-- clock_getcpuclockid2(247)
local clkid = memory.alloc(8)
zero_buf(clkid, 8)
local ok_clk, rv_clk = pcall(function()
    return mk(247)(uint64(pid_val), uint64(0), clkid)
end)
print(string.format("  clock_getcpuid: %d", ok_clk and N(rv_clk) or -999))
if (ok_clk and N(rv_clk) or -1) == 0 then
    print(string.format("    val=%d", rd(N(clkid)) or -1))
end

-- __cap_rights_get(515)
local cr = memory.alloc(0x40)
zero_buf(cr, 0x40)
local ok_cap, rv_cap = pcall(function()
    return mk(515)(uint64(0), uint64(0), cr)
end)
print(string.format("  cap_rights_get: %d", ok_cap and N(rv_cap) or -999))

-- sched_getparam(328)
local sp = memory.alloc(16)
zero_buf(sp, 16)
local ok_sp, rv_sp = pcall(function() return mk(328)(uint64(0), sp) end)
print(string.format("  sched_getparam: %d", ok_sp and N(rv_sp) or -999))
if (ok_sp and N(rv_sp) or -1) == 0 then
    print(string.format("    prio=%d", rd(N(sp)) or -1))
end

-- sched_getscheduler(329)
local ok_ss, rv_ss = pcall(function() return mk(329)(uint64(0)) end)
print(string.format("  sched_getsched: %d", ok_ss and N(rv_ss) or -999))

-- socketex(113)
local ok_se, rv_se = pcall(function()
    return mk(113)(uint64(2), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local se_ret = ok_se and N(rv_se) or -999
print(string.format("  socketex: %d", se_ret))

-- socketclose(114)
if se_ret >= 0 then
    local ok_sc, rv_sc = pcall(function() return mk(114)(uint64(se_ret)) end)
    print(string.format("  socketclose(%d): %d", se_ret, ok_sc and N(rv_sc) or -999))
else
    -- Try on a regular socket
    local tfd = -1
    local ok_tf, rv_tf = pcall(function()
        return mk(97)(uint64(2), uint64(1), uint64(0))
    end)
    if ok_tf then tfd = N(rv_tf) end
    if tfd >= 0 then
        local ok_sc2, rv_sc2 = pcall(function() return mk(114)(uint64(tfd)) end)
        print(string.format("  socketclose(sock %d): %d", tfd, ok_sc2 and N(rv_sc2) or -999))
    end
end

-- modfind(300)
local mname = memory.alloc(32)
write_str(mname, "if_lo")
local ok_mf, rv_mf = pcall(function() return mk(300)(mname) end)
print(string.format("  modfind(if_lo): %d", ok_mf and N(rv_mf) or -999))

-- modfnext(302)
local ok_mn, rv_mn = pcall(function() return mk(302)(uint64(0)) end)
print(string.format("  modfnext(0): %d", ok_mn and N(rv_mn) or -999))

-- modnext(301)
local ok_mnx, rv_mnx = pcall(function() return mk(301)(uint64(0)) end)
print(string.format("  modnext(0): %d", ok_mnx and N(rv_mnx) or -999))

-- modstat(303) — might return module info with kernel addresses!
if (ok_mf and N(rv_mf) or -1) > 0 then
    local mod_id = N(rv_mf)
    local mstat = memory.alloc(0x100)
    zero_buf(mstat, 0x100)
    -- struct module_stat has version at +0
    wd(N(mstat), 1)  -- version = 1
    local ok_ms, rv_ms = pcall(function()
        return mk(303)(uint64(mod_id), mstat)
    end)
    local ret_ms = ok_ms and N(rv_ms) or -999
    print(string.format("  modstat(%d): ret=%d", mod_id, ret_ms))
    if ret_ms == 0 then
        -- Check first few dwords for kernel addresses
        for off = 0, 60, 4 do
            local d = rd(N(mstat) + off)
            if d and d ~= 0 then
                print(string.format("    +%02X: %d (0x%X)", off, d, d))
            end
        end
    end
end

-- sigtimedwait(345) with zero-timeout
local sigset = memory.alloc(16)
zero_buf(sigset, 16)
wd(N(sigset), 0xFFFFFFFF)
local ts = memory.alloc(16)
zero_buf(ts, 16)
local ok_st, rv_st = pcall(function() return mk(345)(sigset, uint64(0), ts) end)
print(string.format("  sigtimedwait: %d", ok_st and N(rv_st) or -999))

if not alive() then print("DEAD"); return end
print("")

-- ===================================================================
-- [E] More BSD discovery
-- ===================================================================
print("[E] discovery")

-- getlogin(49) — returns username string
local login_buf = memory.alloc(64)
zero_buf(login_buf, 64)
local ok_gl, rv_gl = pcall(function() return mk(49)(login_buf, uint64(64)) end)
local ret_gl = ok_gl and N(rv_gl) or -999
print(string.format("  getlogin: ret=%d", ret_gl))
if ret_gl == 0 then
    -- Read first 16 bytes as chars
    local name = ""
    for i = 0, 12, 4 do
        local d = rd(N(login_buf) + i)
        if d and d ~= 0 then
            for b = 0, 3 do
                local c = math.floor(d / (256^b)) % 256
                if c > 31 and c < 127 then name = name .. string.char(c) end
            end
        end
    end
    if #name > 0 then print("    name: " .. name) end
end

-- issetugid(253)
local ok_isu, rv_isu = pcall(function() return mk(253)() end)
print(string.format("  issetugid: %d", ok_isu and N(rv_isu) or -999))

-- pathconf(191) on /app0
local path_buf = memory.alloc(32)
write_str(path_buf, "/app0")
local ok_pc, rv_pc = pcall(function()
    return mk(191)(path_buf, uint64(2))  -- _PC_NAME_MAX
end)
print(string.format("  pathconf(/app0,NAME_MAX): %d", ok_pc and N(rv_pc) or -999))

-- access(33) — check file access
write_str(path_buf, "/dev/null")
local ok_ac, rv_ac = pcall(function() return mk(33)(path_buf, uint64(6)) end)
print(string.format("  access(/dev/null,RW): %d", ok_ac and N(rv_ac) or -999))

-- statfs(396) on /app0
write_str(path_buf, "/app0")
local ok_sf, rv_sf = pcall(function() return mk(396)(path_buf, statfs_buf) end)
print(string.format("  statfs(396,/app0): ret=%d", ok_sf and N(rv_sf) or -999))

-- stat(188) on /app0
local stat_buf = memory.alloc(0x100)
zero_buf(stat_buf, 0x100)
write_str(path_buf, "/app0")
local ok_stat, rv_stat = pcall(function() return mk(188)(path_buf, stat_buf) end)
local ret_stat = ok_stat and N(rv_stat) or -999
print(string.format("  stat(/app0): ret=%d", ret_stat))
if ret_stat == 0 then
    local dev = rd(N(stat_buf)) or 0
    local ino = rd(N(stat_buf) + 8) or 0
    local mode = rd(N(stat_buf) + 4) or 0
    print(string.format("    dev=%d ino=%d mode=0x%X", dev, ino, mode))
end

-- adjtime(140)
local ok_adj, rv_adj = pcall(function()
    return mk(140)(uint64(0), uint64(0))
end)
print(string.format("  adjtime: %d", ok_adj and N(rv_adj) or -999))

-- mlock(203) — already known to work, but test range
local mtest = memory.alloc(0x4000)
local ok_ml, rv_ml = pcall(function()
    return mk(203)(uint64(N(mtest)), uint64(0x4000))
end)
print(string.format("  mlock(heap, 16K): %d", ok_ml and N(rv_ml) or -999))

-- munlock(204)
if (ok_ml and N(rv_ml) or -1) == 0 then
    pcall(function() mk(204)(uint64(N(mtest)), uint64(0x4000)) end)
end

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 392e COMPLETE ===")
