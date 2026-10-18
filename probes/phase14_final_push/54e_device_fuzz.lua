-- CRASH_CLASS: MODERATE
-- PROBE 54e: Smart fuzz sys 622 device control multiplexer
--
-- Binary analysis of 13.60 handler at offset 0x7dcd40:
--   - Reads 6 args from struct
--   - Checks arg[4] (r12) > 0x40
--   - Does copyin from arg[3] into stack variable
--   - Short handler with early return paths
--   - narg=6 in sysent
--
-- Strategy: arg[4] is a size/type check (must be > 0x40).
-- arg[3] is a user buffer pointer that gets copyin'd.
-- arg[0] might be a device handle/fd, arg[1] a command code.
-- This looks like an ioctl-style multiplexer.

print("=== PROBE 54e: SYS 622 DEVICE CONTROL FUZZ ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc622 = make_syscall(622)
local inbuf = memory.alloc(0x200)   -- copyin source buffer
local outbuf = memory.alloc(0x200)  -- potential output

-- Phase 1: Basic arg exploration
-- arg[4] must be > 0x40, so use 0x80 as a safe size
print("[*] Phase 1: Argument pattern exploration")
print("    arg layout: 622(a0, a1, a2, inbuf_ptr, size, a5)")
print("")

-- Zero buffers
for i = 0, 0x1FF, 4 do safe_wd(inbuf + i, 0) end
for i = 0, 0x1FF, 4 do safe_wd(outbuf + i, 0) end

-- Test with various arg0 values (might be device handle)
local a0_tests = {0, 1, 2, 3, 4, 5, 0xFF, 0xFFFFFFFF}
for _, a0 in ipairs(a0_tests) do
    local a0_u64
    if a0 >= 0x80000000 then
        a0_u64 = uint64(string.format("0x%X", a0))
    else
        a0_u64 = uint64(a0)
    end

    local ok, ret = pcall(function()
        return sc622(a0_u64, uint64(0), uint64(0), uint64(inbuf), uint64(0x80), uint64(0))
    end)
    if ok then
        print(string.format("  a0=0x%X  ret=%d", a0, signed32(ret)))
    else
        print(string.format("  a0=0x%X  CRASHED: %s", a0, tostring(ret)))
    end
end
print("")

-- Phase 2: Try with arg[4] below and above the 0x40 threshold
print("[*] Phase 2: arg[4] size threshold test (handler checks > 0x40)")
print("")
for _, sz in ipairs({0, 0x20, 0x3F, 0x40, 0x41, 0x80, 0x100, 0x200}) do
    local ok, ret = pcall(function()
        return sc622(uint64(0), uint64(0), uint64(0), uint64(inbuf), uint64(sz), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  size=0x%X  ret=%d%s", sz, rv,
            rv ~= signed32(sc622 and -1 or 0) and "" or ""))
        if rv == 0 then
            print("  >>> SUCCESS at size 0x" .. string.format("%X", sz))
        end
    else
        print(string.format("  size=0x%X  CRASHED: %s", sz, tostring(ret)))
    end
end
print("")

-- Phase 3: arg[1] as command code (ioctl-style)
print("[*] Phase 3: arg[1] command code sweep")
print("")
for cmd = 0, 31 do
    for i = 0, 0x7F, 4 do safe_wd(inbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc622(uint64(0), uint64(cmd), uint64(0), uint64(inbuf), uint64(0x80), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        if rv ~= -1 then
            print(string.format("  cmd=%2d  ret=%d  <<< NON-ERROR", cmd, rv))
        else
            print(string.format("  cmd=%2d  ret=%d", cmd, rv))
        end
    else
        print(string.format("  cmd=%2d  CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 4: arg[3] as inout buffer - fill with pattern, check after call
print("[*] Phase 4: Buffer modification test (does handler write back?)")
print("")
do
    -- Fill buffer with known pattern
    for i = 0, 0x7F, 4 do safe_wd(inbuf + i, 0x41414141 + i) end

    local ok, ret = pcall(function()
        return sc622(uint64(0), uint64(0), uint64(0), uint64(inbuf), uint64(0x80), uint64(0))
    end)

    if ok then
        print("  ret=" .. signed32(ret))
        -- Check if any bytes changed
        local changed = {}
        for i = 0, 0x7F, 4 do
            local expected = 0x41414141 + i
            local actual = safe_rd(inbuf + i)
            if actual and actual ~= expected then
                table.insert(changed, string.format("+%02X: 0x%08X->0x%08X", i, expected, actual))
            end
        end
        if #changed > 0 then
            print("  >>> BUFFER MODIFIED by handler:")
            for _, c in ipairs(changed) do print("    " .. c) end
        else
            print("  Buffer unchanged")
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
end
print("")

-- Phase 5: arg[5] exploration (6th argument)
print("[*] Phase 5: arg[5] (6th arg) variations")
print("")
for _, a5 in ipairs({0, 1, 2, 0x80, 0x100, 0xFFFFFFFF}) do
    local a5_u64
    if a5 >= 0x80000000 then
        a5_u64 = uint64(string.format("0x%X", a5))
    else
        a5_u64 = uint64(a5)
    end

    for i = 0, 0x7F, 4 do safe_wd(inbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc622(uint64(0), uint64(0), uint64(0), uint64(inbuf), uint64(0x80), a5_u64)
    end)
    if ok then
        local rv = signed32(ret)
        -- Scan inbuf for kernel pointers
        local found_kptr = false
        for i = 0, 0x78, 8 do
            local q = safe_rq(inbuf + i)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  a5=0x%X ret=%d  KPTR at +%d: %s", a5, rv, i, hexval(q)))
                    found_kptr = true
                end
            end
        end
        if not found_kptr then
            print(string.format("  a5=0x%X  ret=%d", a5, rv))
        end
    else
        print(string.format("  a5=0x%X  CRASHED: %s", a5, tostring(ret)))
    end
end
print("")

-- Phase 6: Use outbuf as arg[2] (maybe it's an output pointer)
print("[*] Phase 6: arg[2] as output buffer pointer")
print("")
for _, cmd in ipairs({0, 1, 2, 3}) do
    for i = 0, 0x7F, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end
    for i = 0, 0x7F, 4 do safe_wd(inbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc622(uint64(0), uint64(cmd), uint64(outbuf), uint64(inbuf), uint64(0x80), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local sentinel = (safe_rd(outbuf) == 0xDEADBEEF)
        if not sentinel then
            local q0 = safe_rq(outbuf)
            print(string.format("  cmd=%d  ret=%d  outbuf[0]=%s  <<< WRITTEN", cmd, rv, hexval(q0)))
            for i = 0, 0x78, 8 do
                local q = safe_rq(outbuf + i)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print(string.format("  >>> KPTR at +%d: %s", i, hexval(q)))
                    end
                end
            end
        else
            print(string.format("  cmd=%d  ret=%d  outbuf unchanged", cmd, rv))
        end
    else
        print(string.format("  cmd=%d  CRASHED: %s", cmd, tostring(ret)))
    end
end

print("")
print("=== PROBE 54e COMPLETE ===")
