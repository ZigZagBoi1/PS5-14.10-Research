-- CRASH_CLASS: HIGH
-- PROBE 399e: reproduce /dev/gc mmap from 399c
--
-- 399c: mmap(0, 0x4000, 3, 1, gc_fd, 0) = 3_10A2C000 (success)
-- 399d: mmap(0, 0x10000, 3, 1, gc_fd, 0) = FAIL
-- Theory: size limit (max 16KB?), or per-process state.
-- Test: exact same call as 399c, then probe sizes.

print("=== PROBE 399e: /dev/gc mmap repro ===")

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
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

local sc_open = mk(5)
local sc_close = mk(6)
local sc_mmap = mk(477)
local sc_munmap = mk(73)

local gc_path = memory.alloc(32)
for i = 0, 28, 4 do wd(N(gc_path) + i, 0) end
wd(N(gc_path), 0x7665642F)
wd(N(gc_path) + 4, 0x0063672F)

-- ============================================
-- PART A: Exact reproduction of 399c Part D
-- ============================================
print("")
print("-- A: exact repro 0x4000 --")

local ok_gc, gc_fd_v = pcall(function()
    return sc_open(uint64(N(gc_path)), uint64(2), uint64(0))
end)
local gc_fd = ok_gc and N(gc_fd_v) or -1
if gc_fd > 10000 then gc_fd = -1 end
print(string.format("gc fd=%d", gc_fd))

if gc_fd >= 0 then
    -- PROT_RW=3, MAP_SHARED=1, offset=0, size=0x4000
    local ok_m, rv = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1), uint64(gc_fd), uint64(0))
    end)
    local mh, ml = 0, 0
    if ok_m and rv then mh, ml = get_hi_lo(rv) end
    local mbase = ml + mh * 0x100000000

    if mbase > 0 then
        print(string.format("★ mmap 16KB = %X_%08X", mh, ml))
        local v0 = rd(mbase)
        local v1 = rd(mbase + 4)
        local v2 = rd(mbase + 8)
        local v3 = rd(mbase + 12)
        print(string.format("  [0-15]: %08X %08X %08X %08X",
            v0 or 0xDEAD, v1 or 0xDEAD, v2 or 0xDEAD, v3 or 0xDEAD))

        -- Scan all 16KB for non-0xFF
        local non_ff = 0
        local non_zero = 0
        local interesting = {}
        for off = 0, 0x3FFC, 4 do
            local v = rd(mbase + off)
            if v == nil then
                print(string.format("  READ KILL at +%X", off))
                break
            end
            if v ~= 0xFFFFFFFF then
                non_ff = non_ff + 1
                if v ~= 0 then
                    non_zero = non_zero + 1
                    if #interesting < 20 then
                        table.insert(interesting, {off, v})
                    end
                end
            end
        end
        print(string.format("  non_FF=%d non_zero=%d of 4096 dwords", non_ff, non_zero))
        for _, e in ipairs(interesting) do
            print(string.format("  +%04X = %08X", e[1], e[2]))
        end

        -- Write test at offset 0
        if v0 then
            wd(mbase, 0xAAAA5555)
            local after = rd(mbase)
            wd(mbase, v0)  -- restore
            print(string.format("  write: orig=%08X after=%08X", v0, after or 0xDEAD))
        end

        pcall(function() sc_munmap(rv, uint64(0x4000)) end)
    else
        local ret_n = ok_m and N(rv) or -999
        print(string.format("mmap FAIL ret=%d (raw=%s)", ret_n, tostring(rv)))
    end
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: Size sweep (what's the max?)
-- ============================================
print("")
print("-- B: size sweep --")

if gc_fd >= 0 then
    local sizes = {
        0x1000,   -- 4KB (1 page)
        0x2000,   -- 8KB
        0x4000,   -- 16KB (what worked in 399c)
        0x8000,   -- 32KB
        0xC000,   -- 48KB
        0x10000,  -- 64KB
        0x20000,  -- 128KB
        0x40000,  -- 256KB
    }

    for _, sz in ipairs(sizes) do
        local ok_s, rv_s = pcall(function()
            return sc_mmap(uint64(0), uint64(sz), uint64(0x3),
                uint64(0x1), uint64(gc_fd), uint64(0))
        end)
        local sh, sl = 0, 0
        if ok_s and rv_s then sh, sl = get_hi_lo(rv_s) end
        local sbase = sl + sh * 0x100000000

        if sbase > 0 then
            local v = rd(sbase)
            print(string.format("  sz=0x%X: %X_%08X val=%08X ★",
                sz, sh, sl, v or 0xDEAD))
            pcall(function() sc_munmap(rv_s, uint64(sz)) end)
        else
            print(string.format("  sz=0x%X: FAIL", sz))
        end

        if not alive() then print("CANARY FAIL sz " .. sz); return end
    end
end

-- ============================================
-- PART C: Flag and prot sweep
-- ============================================
print("")
print("-- C: flag/prot sweep --")

if gc_fd >= 0 then
    local combos = {
        {0x1, 0x1, "R,SHARED"},
        {0x3, 0x1, "RW,SHARED"},
        {0x1, 0x2, "R,PRIVATE"},
        {0x3, 0x2, "RW,PRIVATE"},
        {0x1, 0x1001, "R,SHARED|ANON"},
        {0x3, 0x1001, "RW,SHARED|ANON"},
        {0x33, 0x1, "RWX_33,SHARED"},   -- the GNM mapping protection
        {0x10, 0x1, "P_10,SHARED"},      -- SceGnmDriver protection
    }

    for _, c in ipairs(combos) do
        local ok_c, rv_c = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(c[1]),
                uint64(c[2]), uint64(gc_fd), uint64(0))
        end)
        local ch, cl = 0, 0
        if ok_c and rv_c then ch, cl = get_hi_lo(rv_c) end
        local cbase = cl + ch * 0x100000000

        if cbase > 0 then
            local v = rd(cbase)
            print(string.format("  %s: %X_%08X val=%s",
                c[3], ch, cl, v and string.format("%08X", v) or "KILL"))
            pcall(function() sc_munmap(rv_c, uint64(0x4000)) end)
        else
            print(string.format("  %s: FAIL", c[3]))
        end

        if not alive() then print("CANARY FAIL " .. c[3]); return end
    end
end

-- ============================================
-- PART D: Also try /dev/dce and /dev/ajm
-- ============================================
print("")
print("-- D: other device mmap --")

local other_devs = {
    {0x7665642F, 0x6563642F, 0, "dce"},   -- /dev/dce
    {0x7665642F, 0x006D6A61, 0, "ajm"},   -- /dev/ajm  (reversed?)
}

-- Actually encode properly
local dev_names = {"/dev/dce", "/dev/ajm", "/dev/gic", "/dev/dmem0"}

for _, name in ipairs(dev_names) do
    local pbuf = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(pbuf) + i, 0) end
    -- Write path byte by byte via dword packing
    for i = 0, #name - 1, 4 do
        local val = 0
        for j = 0, 3 do
            if i + j < #name then
                val = val + string.byte(name, i + j + 1) * (256 ^ j)
            end
        end
        wd(N(pbuf) + i, val)
    end

    local ok_d, fd_d = pcall(function()
        return sc_open(uint64(N(pbuf)), uint64(2), uint64(0))
    end)
    local fdn = ok_d and N(fd_d) or -1
    if fdn > 10000 then fdn = -1 end

    if fdn >= 0 then
        local ok_dm, rv_dm = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
                uint64(0x1), uint64(fdn), uint64(0))
        end)
        local dh, dl = 0, 0
        if ok_dm and rv_dm then dh, dl = get_hi_lo(rv_dm) end
        local dbase = dl + dh * 0x100000000

        if dbase > 0 then
            local v = rd(dbase)
            print(string.format("  %s fd=%d mmap=%X_%08X val=%s ★",
                name, fdn, dh, dl, v and string.format("%08X", v) or "KILL"))
            pcall(function() sc_munmap(rv_dm, uint64(0x4000)) end)
        else
            print(string.format("  %s fd=%d mmap=FAIL", name, fdn))
        end
        pcall(function() sc_close(uint64(fdn)) end)
    else
        print(string.format("  %s: open fail", name))
    end

    if not alive() then print("CANARY FAIL " .. name); return end
end

if gc_fd >= 0 then
    pcall(function() sc_close(uint64(gc_fd)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 399e COMPLETE ===")
