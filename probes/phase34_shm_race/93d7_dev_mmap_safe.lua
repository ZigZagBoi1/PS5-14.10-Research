-- CRASH_CLASS: MODERATE
-- PROBE 93d7: device mmap check (safe - no binary reads)
--
-- Just checks which /dev nodes accept mmap, reports addr+readable status
-- Avoids binary output contamination by not dumping raw memory

print("=== PROBE 93d7: DEV MMAP SAFE CHECK ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function open_dev(name)
    local path = memory.alloc(64)
    local full = "/dev/" .. name
    for i = 1, #full do wd(N(path) + i - 1, string.byte(full, i)) end
    wd(N(path) + #full, 0)
    local ok, ret = pcall(function() return mk(5)(path, uint64(2)) end)
    if ok and N(ret) >= 0 and N(ret) < 200 then return N(ret) end
    ok, ret = pcall(function() return mk(5)(path, uint64(0)) end)
    if ok and N(ret) >= 0 and N(ret) < 200 then return N(ret) end
    return nil
end

-- ======== SECTION A: mmap on device nodes ========
print("--- A: mmap accessibility ---")

local devs = {"ajm", "gc", "dce", "dmem0", "dmem1", "camera", "rng",
              "gic", "hid", "bt", "zero", "null", "urandom",
              "notification0", "notification1", "usbctl"}

for _, dname in ipairs(devs) do
    local fd = open_dev(dname)
    if fd then
        -- Try PROT_READ, MAP_SHARED
        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(1),
                uint64(1), uint64(fd), uint64(0))
        end)
        local mapped_r = false
        local readable = false
        local kptrs = 0
        if ok_m then
            local h, l = get_hi_lo(rv_m)
            if h > 0 or l > 0x1000 then
                mapped_r = true
                -- Try reading ONE dword safely
                local rval = rd(l)
                readable = (rval ~= nil)
                -- Scan for kernel pointers WITHOUT printing values
                if readable then
                    for off = 0, 0x3FF0, 8 do
                        local lo2 = rd(l + off) or 0
                        local hi2 = rd(l + off + 4) or 0
                        if lo2 < 0 then lo2 = lo2 + 0x100000000 end
                        if hi2 < 0 then hi2 = hi2 + 0x100000000 end
                        if hi2 >= 0xFFFF8000 and hi2 < 0xFFFFFFFF then
                            kptrs = kptrs + 1
                        end
                    end
                end
                pcall(function() mk(73)(rv_m, uint64(0x4000)) end)
            end
        end

        -- Try PROT_READ|PROT_WRITE, MAP_SHARED
        local ok_m2, rv_m2 = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(fd), uint64(0))
        end)
        local mapped_rw = false
        if ok_m2 then
            local h2, l2 = get_hi_lo(rv_m2)
            if h2 > 0 or l2 > 0x1000 then
                mapped_rw = true
                pcall(function() mk(73)(rv_m2, uint64(0x4000)) end)
            end
        end

        local status = "no_mmap"
        if mapped_r and readable then
            status = string.format("MAPPED_R readable kptrs=%d", kptrs)
        elseif mapped_r then
            status = "MAPPED_R unreadable"
        end
        if mapped_rw then status = status .. " +RW" end

        print(string.format("  /dev/%-16s fd=%2d %s", dname, fd, status))
        pcall(function() mk(6)(uint64(fd)) end)
    else
        print(string.format("  /dev/%-16s OPEN_FAIL", dname))
    end
    if not alive() then print("  DEAD!"); return end
end

-- ======== SECTION B: Full TCP getsockopt scan ========
print("")
print("--- B: TCP getsockopt full scan ---")

local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(6))
end)
local tcp_fd = ok_s and N(rv_s) or -1
print("tcp_fd=" .. tcp_fd)

if tcp_fd >= 0 then
    local buf = memory.alloc(0x200)
    local lenp = memory.alloc(8)

    -- Scan all TCP options 0-0x100
    local found = 0
    for optnum = 0, 0x100 do
        for i = 0, 0x1F8, 4 do wd(N(buf) + i, 0xCCCCCCCC) end
        wd(N(lenp), 0x200)
        local ok_o, rv_o = pcall(function()
            return mk(118)(uint64(tcp_fd), uint64(6), uint64(optnum),
                uint64(N(buf)), uint64(N(lenp)))
        end)
        local oret = ok_o and N(rv_o) or -999
        if oret >= 0x80000000 then oret = oret - 0x100000000 end
        if oret == 0 then
            local olen = rd(N(lenp)) or 0
            found = found + 1
            -- Count kernel pointers
            local kp = 0
            local nonzero = 0
            for off = 0, math.min(olen - 4, 0x1FC), 8 do
                local lo = rd(N(buf) + off) or 0
                local hi = rd(N(buf) + off + 4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi ~= 0 or lo ~= 0 then nonzero = nonzero + 1 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then kp = kp + 1 end
            end
            -- Check for sentinel overwrite past len (overcopy)
            local overcopy = 0
            for off = olen, math.min(olen + 32, 0x1FC), 4 do
                local v = rd(N(buf) + off)
                if v and v ~= 0xCCCCCCCC then overcopy = overcopy + 1 end
            end
            if olen > 4 or kp > 0 or overcopy > 0 then
                local tag = ""
                if kp > 0 then tag = tag .. " KPTR=" .. kp end
                if overcopy > 0 then tag = tag .. " OVERCOPY=" .. overcopy end
                print(string.format("  opt 0x%02X: len=%3d nonzero=%d%s",
                    optnum, olen, nonzero, tag))
            end
        end
        if not alive() then break end
    end
    print("total_working_opts=" .. found)

    pcall(function() mk(6)(uint64(tcp_fd)) end)
end

-- ======== SECTION C: UDP getsockopt scan ========
print("")
print("--- C: UDP getsockopt scan ---")

local ok_u, rv_u = pcall(function()
    return mk(97)(uint64(2), uint64(2), uint64(17)) -- AF_INET, SOCK_DGRAM, UDP
end)
local udp_fd = ok_u and N(rv_u) or -1

if udp_fd >= 0 then
    local buf = memory.alloc(0x200)
    local lenp = memory.alloc(8)

    for optnum = 0, 0x80 do
        for i = 0, 0x1F8, 4 do wd(N(buf) + i, 0xBBBBBBBB) end
        wd(N(lenp), 0x200)
        local ok_o, rv_o = pcall(function()
            return mk(118)(uint64(udp_fd), uint64(17), uint64(optnum),
                uint64(N(buf)), uint64(N(lenp)))
        end)
        local oret = ok_o and N(rv_o) or -999
        if oret >= 0x80000000 then oret = oret - 0x100000000 end
        if oret == 0 then
            local olen = rd(N(lenp)) or 0
            local kp = 0
            local overcopy = 0
            for off = 0, math.min(olen - 4, 0x1FC), 8 do
                local lo = rd(N(buf) + off) or 0
                local hi = rd(N(buf) + off + 4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then kp = kp + 1 end
            end
            for off = olen, math.min(olen + 32, 0x1FC), 4 do
                local v = rd(N(buf) + off)
                if v and v ~= 0xBBBBBBBB then overcopy = overcopy + 1 end
            end
            if olen > 4 or kp > 0 or overcopy > 0 then
                print(string.format("  UDP opt 0x%02X: len=%d kp=%d oc=%d",
                    optnum, olen, kp, overcopy))
            end
        end
    end

    pcall(function() mk(6)(uint64(udp_fd)) end)
end

-- ======== SECTION D: fexecve + vfork ========
print("")
print("--- D: exec variants ---")

local ok_fe, rv_fe = pcall(function() return mk(492)(uint64(0), uint64(0), uint64(0)) end)
local fe_ret = ok_fe and N(rv_fe) or -999
if fe_ret >= 0x80000000 then fe_ret = fe_ret - 0x100000000 end
print(string.format("fexecve(492): ret=%d ok=%s", fe_ret, tostring(ok_fe)))

local ok_vf, rv_vf = pcall(function() return mk(66)() end)
local vf_ret = ok_vf and N(rv_vf) or -999
if vf_ret >= 0x80000000 then vf_ret = vf_ret - 0x100000000 end
print(string.format("vfork(66): ret=%d ok=%s", vf_ret, tostring(ok_vf)))

-- pdfork(518)
local ok_pf, rv_pf = pcall(function() return mk(518)(uint64(0), uint64(0)) end)
local pf_ret = ok_pf and N(rv_pf) or -999
if pf_ret >= 0x80000000 then pf_ret = pf_ret - 0x100000000 end
print(string.format("pdfork(518): ret=%d ok=%s", pf_ret, tostring(ok_pf)))

print("")
print("alive=" .. tostring(alive()))
print("=== 93d7 COMPLETE ===")
