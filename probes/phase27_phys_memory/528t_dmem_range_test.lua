-- CRASH_CLASS: LOW
-- PROBE 528t: Test dmem0/1/2 ranges and look for non-zeroed memory
--
-- 528s: 4 GB via dmem0 scanned, zero ELFs, zero kernel pointers.
-- dmem0 is the application direct-memory pool, not system RAM.
--
-- Questions:
-- 1. Do dmem1/dmem2 map different physical ranges?
-- 2. Is phys addr 0 on dmem0 really physical address 0, or is it
--    relative to the dmem pool start?
-- 3. Can we map beyond 4 GB on dmem0?
-- 4. What does the /dev/gc device expose via mmap?
-- 5. What about /dev/dce?

print("=== PROBE 528t: DMEM RANGE TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
    end)
    return ok and N(rv) or -1
end

local function try_mmap(fd_n, offset, prot, flags)
    local off_u = uint64(string.format("0x%X", offset))
    local ok_m, rv = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(prot), uint64(flags), uint64(fd_n), off_u)
    end)
    if not ok_m or not rv then return nil, "CRASH" end
    local rh, rl = get_hi_lo(rv)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh == 0xFFFFFFFF then return nil, "FAIL" end
    return rv, "OK"
end

-- ============================================================
-- [A] Test all dmem devices
-- ============================================================
print("[A] dmem devices")
local dmem_devs = {"/dev/dmem0", "/dev/dmem1", "/dev/dmem2"}
for _, dev in ipairs(dmem_devs) do
    local fd = open_dev(dev)
    if fd >= 0 and fd < 200 then
        print(string.format("  %s: fd=%d", dev, fd))
        -- Try offset 0
        local rv, st = try_mmap(fd, 0, 1, 1)
        if rv then
            local d = rd(N(rv))
            if d then
                if d < 0 then d = d + 0x100000000 end
                print(string.format("    off=0: 0x%08X", d))
            else
                print("    off=0: FAULT")
            end
            pcall(function() sc_73(rv, uint64(PAGE)) end)
        else
            print("    off=0: " .. st)
        end
        -- Try offset 1 GB
        rv, st = try_mmap(fd, 0x40000000, 1, 1)
        if rv then
            local d = rd(N(rv))
            if d then
                if d < 0 then d = d + 0x100000000 end
                print(string.format("    off=1G: 0x%08X", d))
            else
                print("    off=1G: FAULT")
            end
            pcall(function() sc_73(rv, uint64(PAGE)) end)
        else
            print("    off=1G: " .. st)
        end
        pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
    else
        print(string.format("  %s: OPEN FAIL (fd=%d)", dev, fd))
    end
end

-- ============================================================
-- [B] Test other accessible devices for mmap
-- ============================================================
print("")
print("[B] Other devices")
local other_devs = {"/dev/gc", "/dev/dce", "/dev/rng", "/dev/zero",
    "/dev/camera", "/dev/ajm", "/dev/hid", "/dev/notification0"}

for _, dev in ipairs(other_devs) do
    local fd = open_dev(dev)
    if fd >= 0 and fd < 200 then
        -- Try mmap at offset 0 with PROT_READ, MAP_SHARED
        local rv, st = try_mmap(fd, 0, 1, 1)
        if rv then
            local d = rd(N(rv))
            local q = rq(N(rv))
            local dstr = "FAULT"
            local qstr = "FAULT"
            if d then
                if d < 0 then d = d + 0x100000000 end
                dstr = string.format("0x%08X", d)
            end
            if q then
                local vh, vl = get_hi_lo(q)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                qstr = string.format("0x%08X%08X", vh, vl)
                -- Kernel pointer check
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    qstr = qstr .. " *** KPTR ***"
                end
            end
            print(string.format("  %s fd=%d: MAPPED d=%s q=%s", dev, fd, dstr, qstr))
            -- Read a few more qwords
            for i = 1, 7 do
                local v2 = rq(N(rv) + i * 8)
                if v2 then
                    local v2h, v2l = get_hi_lo(v2)
                    if v2h < 0 then v2h = v2h + 0x100000000 end
                    if v2l < 0 then v2l = v2l + 0x100000000 end
                    if v2h >= 0xFFFF8000 and v2h < 0xFFFFFFFF then
                        print(string.format("    [+0x%02X] 0x%08X%08X *** KPTR ***", i*8, v2h, v2l))
                    end
                end
            end
            pcall(function() sc_73(rv, uint64(PAGE)) end)
        else
            print(string.format("  %s fd=%d: mmap %s", dev, fd, st))
        end
        pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
    else
        print(string.format("  %s: OPEN FAIL", dev))
    end
end

-- ============================================================
-- [C] Check dmem0: write at offset 0, read at same offset on dmem1
-- ============================================================
print("")
print("[C] Cross-device test")
local fd0 = open_dev("/dev/dmem0")
local fd1 = open_dev("/dev/dmem1")
if fd0 >= 0 and fd1 >= 0 then
    -- Map offset 0 on both
    local rv0, st0 = try_mmap(fd0, 0, 3, 1)  -- RW
    local rv1, st1 = try_mmap(fd1, 0, 1, 1)  -- R

    if rv0 and rv1 then
        -- Read original values
        local orig0 = rd(N(rv0))
        local orig1 = rd(N(rv1))
        print(string.format("  dmem0[0]=0x%X dmem1[0]=0x%X", orig0 or -1, orig1 or -1))

        -- Write to dmem0 offset 0
        wd(N(rv0), 0x12345678)
        local after0 = rd(N(rv0))
        local after1 = rd(N(rv1))
        print(string.format("  after write: dmem0=0x%X dmem1=0x%X", after0 or -1, after1 or -1))

        if after1 == 0x12345678 or after1 == (0x12345678 - 0x100000000) then
            print("  *** SAME PHYSICAL MEMORY! ***")
        else
            print("  different backing memory")
        end

        -- Restore
        if orig0 then wd(N(rv0), orig0) end

        pcall(function() sc_73(rv0, uint64(PAGE)) end)
        pcall(function() sc_73(rv1, uint64(PAGE)) end)
    else
        print(string.format("  dmem0 mmap=%s dmem1 mmap=%s", st0, st1))
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd0)) end)
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd1)) end)
end

-- ============================================================
-- [D] Check if dmem0 offset maps to real physical addresses
-- Write unique pattern at offset X via dmem0,
-- then read it via the GPU mmap heap (which we know is in dmem)
-- ============================================================
print("")
print("[D] dmem0 vs GPU mmap cross-check")
local fd_dm = open_dev("/dev/dmem0")
if fd_dm >= 0 then
    -- Get libkernel for AllocateDirectMemory
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() mk(593)(uint64(0x2001), ib) end)
    local lk_lo = rd(N(ib) + 0x108) or 0
    local lk_hi = rd(N(ib) + 0x10C) or 0
    if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
    if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
    if lk_lo == 0 and lk_hi == 0 then
        for h = 0, 0x100 do
            local ib3 = memory.alloc(0x200)
            wd(N(ib3), 0x160)
            local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
            if ok3 and N(r3) == 0 then
                local name = ""
                for i = 0, 31 do
                    local b = rd(N(ib3) + 8 + i)
                    if b then local c = b % 256; if c == 0 then break end
                        if c >= 32 and c < 127 then name = name .. string.char(c) end
                    end
                end
                if name:find("libkernel") then
                    lk_lo = rd(N(ib3) + 0x108) or 0
                    lk_hi = rd(N(ib3) + 0x10C) or 0
                    if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                    if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                    break
                end
            end
        end
    end
    local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
    local alloc_fn = lk + uint64(0x17EF0)

    -- Allocate 1 page of physical memory
    local phys_out = memory.alloc(8)
    wq(N(phys_out), uint64(0))
    local ok_af, rv_af = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"), uint64(0x4000),
            uint64(0x4000), uint64(0), uint64(N(phys_out)))
    end)
    if ok_af and N(rv_af) == 0 then
        local phys = rq(N(phys_out))
        print("  allocated phys=" .. fmt(phys))
        local ph, pl = get_hi_lo(phys)
        if ph < 0 then ph = ph + 0x100000000 end
        if pl < 0 then pl = pl + 0x100000000 end

        -- Map via dmem0 at that physical address
        local rv_map, st = try_mmap(fd_dm, ph * 0x100000000 + pl, 3, 1)
        if rv_map then
            -- Write unique value
            wd(N(rv_map), 0xBEEFCAFE)
            local rb = rd(N(rv_map))
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print(string.format("  dmem0 map: wrote 0xBEEFCAFE read 0x%X", rb))
            end

            -- Now try to map the SAME phys addr again via another mmap
            local rv_map2, st2 = try_mmap(fd_dm, ph * 0x100000000 + pl, 1, 1)
            if rv_map2 then
                local rb2 = rd(N(rv_map2))
                if rb2 then
                    if rb2 < 0 then rb2 = rb2 + 0x100000000 end
                    print(string.format("  second map same phys: read 0x%X match=%s",
                        rb2, tostring(rb2 == 0xBEEFCAFE)))
                end
                pcall(function() sc_73(rv_map2, uint64(PAGE)) end)
            end

            pcall(function() sc_73(rv_map, uint64(PAGE)) end)
        else
            print("  dmem0 map at alloc'd phys: " .. st)
        end
    else
        print("  alloc FAILED")
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_dm)) end)
end

print("")
print("=== 528t DONE ===")
