-- CRASH_CLASS: LOW
-- PROBE 572a: Deeper test of syscall 572 (VM info query)
--
-- 571a showed ret=0 for (outbuf, cmd, size) shapes but zero bytes written.
-- 13.60 decompile says two copyouts, no top gate.
-- Try: size field at buf+0, module handles as cmd, larger cmd range, 4-arg shapes.

print("=== PROBE 572a: sys572 deep re-shape ===")
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
local function fmt_qw(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local sc572 = make_syscall(572)
local SENTINEL = 0xCAFEBABE

local function check_buf(buf, size)
    local modified = 0
    local kptrs = 0
    local first_mod = nil
    for off = 0, size - 8, 8 do
        local qv = safe_rq(buf + off)
        local qh, ql = get_hi_lo(qv)
        if ql ~= SENTINEL or qh ~= 0 then
            modified = modified + 1
            if not first_mod then first_mod = off end
            if is_kptr(qv) then kptrs = kptrs + 1 end
        end
    end
    return modified, kptrs, first_mod
end

local function fill_sentinel(buf, size)
    for off = 0, size - 8, 8 do
        safe_wq(buf + off, uint64(SENTINEL))
    end
end

-- ============================================================
-- PHASE A: (outbuf, cmd, size) with size field at buf+0
-- ============================================================
print("[A] 572(outbuf, cmd, size) with size=0x200 at buf+0...")

for cmd = 0, 20 do
    local buf = memory.alloc(0x200)
    fill_sentinel(buf, 0x200)
    safe_wd(buf, 0x200) -- size field at +0

    local ok, ret = pcall(function()
        return sc572(uint64(buf), uint64(cmd), uint64(0x200))
    end)
    local rv = -999
    if ok then rv = to_num(ret) end

    local modified, kptrs, first = check_buf(buf, 0x200)
    -- +0x00 was set to 0x200 by us, so discount if sentinel was replaced by our size
    if modified > 0 or rv == 0 then
        print(string.format("  cmd=%d ret=%d modified=%d kptrs=%d", cmd, rv, modified, kptrs))
        if modified > 0 and modified <= 20 then
            for off = 0, 0x1F8, 8 do
                local qv = safe_rq(buf + off)
                local qh, ql = get_hi_lo(qv)
                if ql ~= SENTINEL or qh ~= 0 then
                    -- Skip if it's just our size field at +0
                    if off == 0 and ql == 0x200 and qh == 0 then
                        -- our write, skip
                    else
                        print(string.format("    +0x%03X: %s%s", off, fmt_qw(qv),
                            is_kptr(qv) and " *** KPTR ***" or ""))
                    end
                end
            end
        end
    end
end
print("")

-- ============================================================
-- PHASE B: (outbuf, cmd, size) with 0x160 at buf+0 (dynlib style)
-- ============================================================
print("[B] 572(outbuf, cmd, size) with size=0x160 at buf+0...")

for cmd = 0, 10 do
    local buf = memory.alloc(0x200)
    fill_sentinel(buf, 0x200)
    safe_wd(buf, 0x160) -- dynlib-style size

    local ok, ret = pcall(function()
        return sc572(uint64(buf), uint64(cmd), uint64(0x160))
    end)
    local rv = -999
    if ok then rv = to_num(ret) end

    local modified, kptrs = check_buf(buf, 0x200)
    if modified > 0 or rv == 0 then
        print(string.format("  cmd=%d ret=%d modified=%d kptrs=%d", cmd, rv, modified, kptrs))
    end
end
print("")

-- ============================================================
-- PHASE C: 4-arg shapes — (outbuf, cmd, size, handle)
-- ============================================================
print("[C] 572(outbuf, cmd, size, handle) — 4 args...")

local test_handles = {0, 2, 19, 20}
for _, h in ipairs(test_handles) do
    for _, cmd in ipairs({0, 1, 2}) do
        local buf = memory.alloc(0x400)
        fill_sentinel(buf, 0x400)
        safe_wd(buf, 0x400)

        local ok, ret = pcall(function()
            return sc572(uint64(buf), uint64(cmd), uint64(0x400), uint64(h))
        end)
        local rv = -999
        if ok then rv = to_num(ret) end

        local modified, kptrs = check_buf(buf, 0x400)
        if modified > 0 or (rv ~= -1 and rv ~= -999) then
            print(string.format("  handle=%d cmd=%d ret=%d modified=%d kptrs=%d", h, cmd, rv, modified, kptrs))
            if kptrs > 0 then
                for off = 0, 0x3F8, 8 do
                    local qv = safe_rq(buf + off)
                    if is_kptr(qv) then
                        print(string.format("    +0x%03X: %s *** KPTR ***", off, fmt_qw(qv)))
                    end
                end
            end
        end
    end
end
print("")

-- ============================================================
-- PHASE D: (addr, outbuf, size) where addr is a known VA
-- Maybe 572 queries info about a specific VA?
-- ============================================================
print("[D] 572(addr, outbuf, size) — VA query shape...")

local sc593 = make_syscall(593)
-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))
print(string.format("  eboot_base=%s", fmt_qw(eboot_base)))

-- GPU mmap for a heap address
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(0x4000), uint64(0x3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print(string.format("  gpu_page=%s", fmt_qw(gpu)))

local test_addrs = {eboot_base, gpu, uint64(0), uint64(0x1000)}

for _, addr in ipairs(test_addrs) do
    local buf = memory.alloc(0x200)
    fill_sentinel(buf, 0x200)

    local ok, ret = pcall(function()
        return sc572(uint64(addr), uint64(buf), uint64(0x200))
    end)
    local rv = -999
    if ok then rv = to_num(ret) end

    local modified, kptrs = check_buf(buf, 0x200)
    print(string.format("  addr=%s ret=%d modified=%d kptrs=%d",
        fmt_qw(addr), rv, modified, kptrs))
    if modified > 0 and modified <= 16 then
        for off = 0, 0x1F8, 8 do
            local qv = safe_rq(buf + off)
            local qh, ql = get_hi_lo(qv)
            if ql ~= SENTINEL or qh ~= 0 then
                print(string.format("    +0x%03X: %s%s", off, fmt_qw(qv),
                    is_kptr(qv) and " *** KPTR ***" or ""))
            end
        end
    end
end
print("")

-- ============================================================
-- PHASE E: sizep pattern — (outbuf, sizep) where sizep is pointer to size
-- ============================================================
print("[E] 572(outbuf, sizep) — size-pointer pattern...")

local buf = memory.alloc(0x400)
fill_sentinel(buf, 0x400)
local sizep = memory.alloc(8)
safe_wq(sizep, uint64(0x400))

local ok, ret = pcall(function()
    return sc572(uint64(buf), uint64(sizep))
end)
local rv = -999
if ok then rv = to_num(ret) end

local modified, kptrs = check_buf(buf, 0x400)
local new_size = safe_rq(sizep)
print(string.format("  ret=%d modified=%d kptrs=%d size_after=%s", rv, modified, kptrs, fmt_qw(new_size)))

-- Also try (sizep, outbuf)
buf = memory.alloc(0x400)
fill_sentinel(buf, 0x400)
safe_wq(sizep, uint64(0x400))

ok, ret = pcall(function()
    return sc572(uint64(sizep), uint64(buf))
end)
rv = -999
if ok then rv = to_num(ret) end

modified, kptrs = check_buf(buf, 0x400)
new_size = safe_rq(sizep)
print(string.format("  (sizep,outbuf) ret=%d modified=%d kptrs=%d size_after=%s", rv, modified, kptrs, fmt_qw(new_size)))
print("")

print("=== PROBE 572a COMPLETE — process alive ===")
