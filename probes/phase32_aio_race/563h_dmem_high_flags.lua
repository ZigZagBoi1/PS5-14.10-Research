-- CRASH_CLASS: LOW
-- PROBE 563h: Force dmem0 mmap above 5.375GB with various flags
--
-- 563g PROVED: MapDM VA copyin returns EFAULT (PTE blocks even ring 0).
-- BUT dmem0 mmap is trace-free AND copyin works.
-- 563c showed dmem0 d_mmap rejects >5GB — but only tested flag 0x0001.
--
-- Question: can different mmap flags (MAP_SHARED, MAP_PRIVATE, different prots)
-- convince dmem0's d_mmap to map higher physical offsets?
-- Also: what about /dev/dmem1, /dev/dmem2? They might cover different ranges.
--
-- PLAN:
-- [A] dmem0 with various flags at phys 0x160000000 (just above limit)
-- [B] dmem0 at phys 0x200000000, 0x300000000
-- [C] /dev/dmem1 and /dev/dmem2 at high offsets
-- [D] Direct mmap_dmem(628) syscall — bypasses d_mmap, goes to kernel directly
-- [E] Physical range probing — find exact dmem0 ceiling

print("=== PROBE 563h: DMEM HIGH OFFSET FLAGS ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc477 = mk(477)
local PAGE = 0x4000

-- Helper: write /dev/dmemN path
local function open_dmem(n)
    local dp = memory.alloc(16)
    local path = "/dev/dmem" .. n
    for i = 0, 12, 4 do wd(N(dp) + i, 0) end
    -- Write path bytes
    for i = 0, #path - 1, 4 do
        local val = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #path then
                val = val + string.byte(path, idx) * (256 ^ j)
            end
        end
        wd(N(dp) + i, val)
    end
    local ok_o, fd_raw = pcall(function()
        return native.fcall_with_rax(stub, 5, dp, uint64(2))
    end)
    return ok_o and N(fd_raw) or -999
end

-- Helper: try mmap at offset with given flags
local function try_mmap(fd, phys_str, prot, flags)
    local ok_mm, va_raw = pcall(function()
        return sc477(Z, uint64(PAGE), uint64(prot),
            uint64(flags), uint64(fd), uint64(phys_str))
    end)
    local va = ok_mm and N(va_raw) or 0
    if va > 0x10000 and va < 0x800000000000 then
        local v0 = rb(va)
        if v0 ~= nil then
            pcall(function()
                native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
            end)
            return v0
        end
        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
        end)
        return "MAPPED_NO_READ"
    end
    return nil
end

io.flush()

-- ============================================================
-- [A] dmem0 at 0x160000000 with various flags
-- ============================================================
print("[A] dmem0 @ phys 0x160000000 (above 5.375GB limit)")
local fd0 = open_dmem(0)
print("  fd=" .. fd0)

if fd0 >= 0 then
    local flag_combos = {
        {1, 0x0001, "PROT_READ, MAP_SHARED"},
        {3, 0x0001, "PROT_RW, MAP_SHARED"},
        {1, 0x0002, "PROT_READ, MAP_PRIVATE"},
        {3, 0x0002, "PROT_RW, MAP_PRIVATE"},
        {1, 0x1001, "PROT_READ, MAP_SHARED|MAP_ANON"},
        {1, 0x0011, "PROT_READ, MAP_SHARED|MAP_STACK"},
        {1, 0x0801, "PROT_READ, MAP_SHARED|MAP_NOSYNC"},
        {1, 0x1002, "PROT_READ, MAP_PRIVATE|MAP_ANON"},
        {3, 0x0012, "PROT_RW, MAP_PRIVATE|MAP_STACK"},
    }
    for _, combo in ipairs(flag_combos) do
        local result = try_mmap(fd0, "0x160000000", combo[1], combo[2])
        local status = result == nil and "FAIL" or
            (type(result) == "string" and result or
             string.format("OK 0x%08X", result))
        print(string.format("  prot=%d flags=0x%04X: %s  (%s)",
            combo[1], combo[2], status, combo[3]))
    end
end
io.flush()

-- ============================================================
-- [B] dmem0 at higher addresses
-- ============================================================
print("")
print("[B] dmem0 high addresses (PROT_READ, MAP_SHARED)")
if fd0 >= 0 then
    local addrs = {
        "0x140000000", "0x14FF00000", "0x150000000",
        "0x158000000", "0x160000000", "0x200000000",
        "0x300000000", "0x400000000"
    }
    for _, addr in ipairs(addrs) do
        local result = try_mmap(fd0, addr, 1, 0x0001)
        local status = result == nil and "FAIL" or
            (type(result) == "string" and result or
             string.format("OK 0x%08X", result))
        print(string.format("  %s: %s", addr, status))
    end
end
io.flush()

-- ============================================================
-- [C] /dev/dmem1 and /dev/dmem2
-- ============================================================
print("")
print("[C] dmem1 and dmem2")
for n = 1, 2 do
    local fd_n = open_dmem(n)
    print(string.format("  /dev/dmem%d fd=%d", n, fd_n))
    if fd_n >= 0 then
        -- Try offset 0 first (control)
        local v_zero = try_mmap(fd_n, "0", 1, 0x0001)
        local v_high = try_mmap(fd_n, "0x200000000", 1, 0x0001)
        local v_vhigh = try_mmap(fd_n, "0x400000000", 1, 0x0001)
        print(string.format("    phys=0: %s",
            v_zero == nil and "FAIL" or string.format("0x%08X", v_zero)))
        print(string.format("    phys=8GB: %s",
            v_high == nil and "FAIL" or string.format("0x%08X", v_high)))
        print(string.format("    phys=16GB: %s",
            v_vhigh == nil and "FAIL" or string.format("0x%08X", v_vhigh)))
        pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_n)) end)
    end
end
io.flush()

-- ============================================================
-- [D] mmap_dmem(628) syscall directly
-- ============================================================
print("")
print("[D] mmap_dmem(628) direct syscall")
-- 628 signature from dossier: mmap_dmem(addr, len, memtype, prot, flags, phys_off)
-- Try with different memtypes (0, 1, 2 = dmem0/1/2?)
for mtype = 0, 2 do
    local ok_d, rv_d = pcall(function()
        return mk(628)(Z, uint64(PAGE), uint64(mtype),
            uint64(3), uint64(0), uint64("0x200000000"))
    end)
    local d_rv = ok_d and N(rv_d) or -999
    local status = "FAIL"
    if d_rv > 0x10000 and d_rv < 0x800000000000 then
        local v = rb(d_rv)
        if v ~= nil then
            status = string.format("OK va=0x%X data=0x%08X", d_rv, v)
            pcall(function()
                native.fcall_with_rax(stub, 73, uint64(d_rv), uint64(PAGE))
            end)
        else
            status = string.format("MAPPED va=0x%X READ_FAIL", d_rv)
            pcall(function()
                native.fcall_with_rax(stub, 73, uint64(d_rv), uint64(PAGE))
            end)
        end
    end
    print(string.format("  mtype=%d phys=8GB: rv=%d %s", mtype, d_rv, status))
end
io.flush()

-- ============================================================
-- [E] Find exact dmem0 ceiling (binary search)
-- ============================================================
print("")
print("[E] dmem0 ceiling binary search")
if fd0 >= 0 then
    -- We know 0x140000000 works (from 563b heatmap)
    -- We know 0x160000000 fails (from 563c)
    -- Binary search the boundary
    local lo = 0x140000000
    local hi = 0x160000000

    -- Quick check lo works
    local v_lo = try_mmap(fd0, string.format("0x%X", lo), 1, 0x0001)
    print(string.format("  0x%X: %s", lo, v_lo and "OK" or "FAIL"))

    if v_lo then
        for iter = 1, 16 do
            local mid = lo + math.floor((hi - lo) / 2)
            -- Align to page boundary
            mid = mid - (mid % PAGE)
            if mid == lo then break end

            local v = try_mmap(fd0, string.format("0x%X", mid), 1, 0x0001)
            if v then
                lo = mid
                print(string.format("  0x%X: OK (0x%08X)", mid, v))
            else
                hi = mid
                print(string.format("  0x%X: FAIL", mid))
            end
        end
        print(string.format("  ceiling: 0x%X - 0x%X", lo, hi))
    end

    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd0)) end)
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563h DONE ===")
