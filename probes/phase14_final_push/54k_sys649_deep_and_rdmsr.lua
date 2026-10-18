-- CRASH_CLASS: MODERATE
-- PROBE 54k: Deep sys 649 member scan + sys 626 RDMSR
--
-- Context: 54f showed sys 649 returns ret=0 with addresses for member types 1-4.
-- This was not previously known. We scan ALL member types (0-255) across
-- multiple module handles to look for any kernel pointer leak.
-- Then we test sys 626 (RDMSR) which has never been sent to the PS5.

print("=== PROBE 54k: SYS 649 DEEP + RDMSR ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

local sc649 = make_syscall(649)
local sc626 = make_syscall(626)
local outbuf = memory.alloc(0x1000)

-- ============================================================
-- PART 1: sys 649 — scan member types 0-255 on handle 0 (eboot)
-- ============================================================
print("--- PART 1: sys 649 member scan (handle=0, members 0-255) ---")
print("")

local found_any = false
for m = 0, 255 do
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc649(uint64(0), uint64(m), uint64(outbuf), uint64(64), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        if rv == 0 then
            local q0 = safe_rq(outbuf)
            local q1 = safe_rq(outbuf + 8)
            local q2 = safe_rq(outbuf + 16)
            local q3 = safe_rq(outbuf + 24)
            print(string.format("  m=%3d ret=0 [0]=%s [8]=%s [16]=%s [24]=%s",
                m, hexval(q0), hexval(q1), hexval(q2), hexval(q3)))
            found_any = true
            -- Check all qwords for kernel pointers
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if is_kptr(qv) then
                    print(string.format("  >>> KPTR at m=%d +%d: %s", m, i, hexval(qv)))
                end
            end
        end
    else
        print(string.format("  m=%3d CRASHED: %s", m, tostring(ret)))
        break
    end
end
if not found_any then print("  No successful members found") end
print("")

-- Also try handle=2 (libkernel) with extended members
print("--- PART 1b: sys 649 member scan (handle=2/libkernel, members 0-32) ---")
for m = 0, 32 do
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return sc649(uint64(2), uint64(m), uint64(outbuf), uint64(64), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        if rv == 0 then
            local q0 = safe_rq(outbuf)
            local q1 = safe_rq(outbuf + 8)
            print(string.format("  h=2 m=%3d ret=0 [0]=%s [8]=%s", m, hexval(q0), hexval(q1)))
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if is_kptr(qv) then
                    print(string.format("  >>> KPTR at h=2 m=%d +%d: %s", m, i, hexval(qv)))
                end
            end
        end
    else
        print(string.format("  h=2 m=%3d CRASHED", m))
        break
    end
end
print("")

-- ============================================================
-- PART 2: sys 649 — try passing output buffer as arg1 instead of arg3
-- Maybe a different arg layout returns more data or different data
-- ============================================================
print("--- PART 2: sys 649 alt arg layouts ---")
local layouts = {
    {0, 1, "outbuf", 512, 0, 0, "649(0,1,outbuf,512)"},
    {"outbuf", 0, 1, 512, 0, 0, "649(outbuf,0,1,512)"},
    {0, "outbuf", 1, 512, 0, 0, "649(0,outbuf,1,512)"},
    {0, 1, 0, "outbuf", 512, 0, "649(0,1,0,outbuf,512)"},
}
for _, lay in ipairs(layouts) do
    for i = 0, 0x7F, 4 do safe_wd(outbuf + i, 0) end
    local args = {}
    for j = 1, 6 do
        if lay[j] == "outbuf" then
            args[j] = uint64(outbuf)
        else
            args[j] = uint64(lay[j])
        end
    end
    local ok, ret = pcall(function()
        return sc649(args[1], args[2], args[3], args[4], args[5], args[6])
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        print(string.format("  %s ret=%d [0]=%s [8]=%s", lay[7], rv, hexval(q0), hexval(q1)))
        for i = 0, 120, 8 do
            local qv = safe_rq(outbuf + i)
            if is_kptr(qv) then
                print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
            end
        end
    else
        print(string.format("  %s CRASHED", lay[7]))
    end
end
print("")

-- ============================================================
-- PART 3: sys 626 RDMSR — the correct handler
-- ============================================================
print("--- PART 3: sys 626 RDMSR ---")
print("")

local msrs = {
    {0x10,       "TSC"},
    {0x1B,       "APIC_BASE"},
    {0x176,      "SYSENTER_EIP"},
    {0xC0000080, "EFER"},
    {0xC0000081, "STAR"},
    {0xC0000082, "LSTAR"},
    {0xC0000083, "CSTAR"},
    {0xC0000084, "SFMASK"},
    {0xC0000100, "FS_BASE"},
    {0xC0000101, "GS_BASE"},
    {0xC0000102, "KERNEL_GS_BASE"},
}

-- Layout A: 626(msr_index, outbuf, len)
print("[A] 626(msr, outbuf, 64)")
for _, msr in ipairs(msrs) do
    local idx = msr[1]
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local idx_u64
    if idx >= 0x80000000 then
        idx_u64 = uint64(string.format("0x%X", idx))
    else
        idx_u64 = uint64(idx)
    end
    local ok, ret = pcall(function()
        return sc626(idx_u64, uint64(outbuf), uint64(64), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  0x%08X %-16s ret=%d buf=%s", idx, msr[2], rv, hexval(q0)))
        if is_kptr(q0) then
            print("  >>> KPTR: " .. hexval(q0))
        end
    else
        print(string.format("  0x%08X %-16s CRASHED: %s", idx, msr[2], tostring(ret)))
    end
end
print("")

-- Layout B: 626(0, msr_index) — maybe it's a simple "read MSR, return value"
print("[B] 626(0, msr) — check return value directly")
for _, msr in ipairs(msrs) do
    local idx = msr[1]
    local idx_u64
    if idx >= 0x80000000 then
        idx_u64 = uint64(string.format("0x%X", idx))
    else
        idx_u64 = uint64(idx)
    end
    local ok, ret = pcall(function()
        return sc626(uint64(0), idx_u64, uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  0x%08X %-16s ret=%d (%s)", idx, msr[2], rv, hexval(ret)))
        if is_kptr(ret) then
            print("  >>> KPTR IN RETVAL: " .. hexval(ret))
        end
    else
        print(string.format("  0x%08X %-16s CRASHED: %s", idx, msr[2], tostring(ret)))
    end
end
print("")

-- Layout C: struct-based — {cmd, msr_index, outbuf_ptr, outlen}
print("[C] 626(struct) — cmd+msr+outbuf packed")
local structbuf = memory.alloc(0x100)
for cmd = 0, 3 do
    for _, msr in ipairs(msrs) do
        local idx = msr[1]
        for i = 0, 0x7F, 4 do safe_wd(structbuf + i, 0) end
        for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

        safe_wd(structbuf, cmd)
        safe_wd(structbuf + 4, 0)
        if idx >= 0x80000000 then
            safe_wd(structbuf + 8, idx)
        else
            safe_wd(structbuf + 8, idx)
        end
        safe_wd(structbuf + 12, 0)
        safe_wq(structbuf + 16, uint64(outbuf))
        safe_wd(structbuf + 24, 64)

        local ok, ret = pcall(function()
            return sc626(uint64(structbuf), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        if ok then
            local rv = signed32(ret)
            if rv ~= -1 then
                local q0 = safe_rq(outbuf)
                print(string.format("  cmd=%d msr=0x%X %-16s ret=%d buf=%s",
                    cmd, idx, msr[2], rv, hexval(q0)))
                if is_kptr(q0) then
                    print("  >>> KPTR: " .. hexval(q0))
                end
            end
        else
            print(string.format("  cmd=%d msr=0x%X CRASHED: %s", cmd, idx, tostring(ret)))
        end
    end
end
print("")

-- ============================================================
-- PART 4: sys 612 (related to 649?) — quick scan
-- ============================================================
print("--- PART 4: sys 612 quick scan ---")
local sc612 = make_syscall(612)
for m = 0, 8 do
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return sc612(uint64(0), uint64(m), uint64(outbuf), uint64(64), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  612(0,%d,outbuf) ret=%d [0]=%s", m, rv, hexval(q0)))
        if is_kptr(q0) then
            print("  >>> KPTR: " .. hexval(q0))
        end
    else
        print(string.format("  612(0,%d) CRASHED", m))
    end
end
print("")

-- ============================================================
-- PART 5: sys 567 RDMSR read with different arg layouts
-- Previous test returned -1 for all. Try struct-based args.
-- ============================================================
print("--- PART 5: sys 567 with struct args ---")
local sc567 = make_syscall(567)
local key_msrs = {0x10, 0xC0000082, 0xC0000102}
for _, idx in ipairs(key_msrs) do
    -- Layout: struct at arg1 with {msr_index, out_ptr, out_len}
    for i = 0, 0x7F, 4 do safe_wd(structbuf + i, 0) end
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    safe_wd(structbuf, idx >= 0x80000000 and idx or idx)
    safe_wd(structbuf + 4, idx >= 0x80000000 and 0 or 0)
    safe_wq(structbuf + 8, uint64(outbuf))
    safe_wd(structbuf + 16, 8)

    local ok, ret = pcall(function()
        return sc567(uint64(structbuf), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  567(struct{msr=0x%X}) ret=%d buf=%s", idx, rv, hexval(q0)))
        if is_kptr(q0) then print("  >>> KPTR: " .. hexval(q0)) end
    else
        print(string.format("  567(struct{msr=0x%X}) CRASHED: %s", idx, tostring(ret)))
    end

    -- Also try: 567(msr_index, outbuf, 8, 0, 0, 0)
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end
    local idx_u64 = idx >= 0x80000000 and uint64(string.format("0x%X", idx)) or uint64(idx)
    local ok2, ret2 = pcall(function()
        return sc567(idx_u64, uint64(outbuf), uint64(8), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv2 = signed32(ret2)
        local q0 = safe_rq(outbuf)
        print(string.format("  567(0x%X,outbuf,8) ret=%d buf=%s", idx, rv2, hexval(q0)))
        if is_kptr(q0) then print("  >>> KPTR: " .. hexval(q0)) end
    else
        print(string.format("  567(0x%X,outbuf,8) CRASHED: %s", idx, tostring(ret2)))
    end
end
print("")

print("=== PROBE 54k COMPLETE ===")
