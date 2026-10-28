-- CRASH_CLASS: LOW
-- PROBE 571a: Test ungated syscalls 599 (dynlib_process_needed_and_relocate) and 656 (dynlib_get_info_for_libdbg)
--
-- 599: ungated, reaches 2 copyouts at depth 4-5 via loader (13.60 decompile)
--      args unknown — try (handle, flags) shapes
-- 656: debug-unit gate (NOT authid, NOT bit-62), narg 2: (id, info* with size 0x160)
--      same struct as 593 but possibly richer; one call settles gate

print("=== PROBE 571a: sys599 + sys656 ===")
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

local sc593 = make_syscall(593)
local sc599 = make_syscall(599)
local sc656 = make_syscall(656)

-- Get module handles via 593
print("[A] Enumerating modules via 593...")
local handles = {}
for h = 0, 50 do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), info) end)
    if ok and to_num(ret) == 0 then
        table.insert(handles, h)
        print(string.format("  handle=%d text=0x%08X_%08X", h,
            safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
    end
end
print(string.format("  Found %d modules", #handles))
print("")

-- ============================================================
-- PHASE B: Test 656 (dynlib_get_info_for_libdbg) — debug-unit gate
-- ============================================================
print("[B] Testing syscall 656 (dynlib_get_info_for_libdbg)...")

for _, h in ipairs(handles) do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)

    local ok, ret = pcall(function() return sc656(uint64(h), uint64(info)) end)
    local rv = -999
    if ok then rv = to_num(ret) end

    if rv == 0 then
        -- SUCCESS — debug gate passed! Scan for kernel pointers
        print(string.format("  handle=%d ret=0 *** GATE PASSED ***", h))
        local kptrs = 0
        for off = 0, 0x158, 8 do
            local qv = safe_rq(info + off)
            if is_kptr(qv) then
                kptrs = kptrs + 1
                print(string.format("    *** KPTR +0x%03X: %s ***", off, fmt_qw(qv)))
            end
        end
        -- Diff against 593
        local info593 = memory.alloc(0x200)
        safe_wd(info593, 0x160)
        pcall(function() sc593(uint64(h), info593) end)
        local diffs = 0
        for off = 0, 0x15F, 4 do
            local a = safe_rd(info593 + off)
            local b = safe_rd(info + off)
            if a ~= b then
                diffs = diffs + 1
                if diffs <= 20 then
                    print(string.format("    DIFF +0x%03X: 593=0x%08X 656=0x%08X", off, a or 0, b or 0))
                end
            end
        end
        print(string.format("    diffs=%d kptrs=%d", diffs, kptrs))
    else
        print(string.format("  handle=%d ret=%d (gate blocked)", h, rv))
    end
end
print("")

-- ============================================================
-- PHASE C: Test 599 (dynlib_process_needed_and_relocate)
-- Try various arg shapes — we don't know the signature
-- ============================================================
print("[C] Testing syscall 599 (dynlib_process_needed_and_relocate)...")

-- Shape 1: no args
print("  [C1] 599() — no args")
local ok, ret = pcall(function() return sc599() end)
local rv = -999
if ok then rv = to_num(ret) end
print(string.format("    ret=%d ok=%s", rv, tostring(ok)))

-- Shape 2: zero args (six zeros)
print("  [C2] 599(0,0,0,0,0,0)")
ok, ret = pcall(function()
    return sc599(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
rv = -999
if ok then rv = to_num(ret) end
print(string.format("    ret=%d ok=%s", rv, tostring(ok)))

-- Shape 3: valid module handle + flags
print("  [C3] 599(handle, flags) for each module")
for _, h in ipairs(handles) do
    for _, flags in ipairs({0, 1, 2, 3, 0x10, 0x100}) do
        local ok2, ret2 = pcall(function()
            return sc599(uint64(h), uint64(flags))
        end)
        local rv2 = -999
        if ok2 then rv2 = to_num(ret2) end
        if rv2 ~= -1 and rv2 ~= -999 then
            print(string.format("    handle=%d flags=0x%X ret=%d *** NON-MINUS-ONE ***", h, flags, rv2))
        end
    end
end
-- Report if all were -1
print("    (all -1 means no shape found)")

-- Shape 4: handle + output buffer
print("  [C4] 599(handle, outbuf)")
for _, h in ipairs(handles) do
    local outbuf = memory.alloc(0x200)
    -- Fill with sentinel
    for off = 0, 0x1F8, 8 do
        safe_wq(outbuf + off, uint64(0xDEADBEEF))
    end
    local ok3, ret3 = pcall(function()
        return sc599(uint64(h), uint64(outbuf))
    end)
    local rv3 = -999
    if ok3 then rv3 = to_num(ret3) end

    -- Check if any sentinel was overwritten
    local modified = 0
    for off = 0, 0x1F8, 8 do
        local qv = safe_rq(outbuf + off)
        local qh, ql = get_hi_lo(qv)
        if ql ~= 0xDEADBEEF or qh ~= 0 then
            modified = modified + 1
        end
    end
    if rv3 ~= -1 or modified > 0 then
        print(string.format("    handle=%d ret=%d modified=%d", h, rv3, modified))
        -- Dump modified qwords
        if modified > 0 and modified <= 16 then
            for off = 0, 0x1F8, 8 do
                local qv = safe_rq(outbuf + off)
                local qh, ql = get_hi_lo(qv)
                if ql ~= 0xDEADBEEF or qh ~= 0 then
                    print(string.format("      +0x%03X: %s%s", off, fmt_qw(qv),
                        is_kptr(qv) and " *** KPTR ***" or ""))
                end
            end
        end
    end
end

-- Shape 5: (0, handle) reversed
print("  [C5] 599(0, handle)")
for _, h in ipairs(handles) do
    local ok4, ret4 = pcall(function()
        return sc599(uint64(0), uint64(h))
    end)
    local rv4 = -999
    if ok4 then rv4 = to_num(ret4) end
    if rv4 ~= -1 and rv4 ~= -999 then
        print(string.format("    handle=%d ret=%d *** NON-MINUS-ONE ***", h, rv4))
    end
end

-- Shape 6: (handle, flags, outbuf) — 3 args
print("  [C6] 599(handle, flags, outbuf) — 3 arg")
for _, h in ipairs(handles) do
    local outbuf = memory.alloc(0x200)
    for off = 0, 0x1F8, 8 do
        safe_wq(outbuf + off, uint64(0xDEADBEEF))
    end
    for _, flags in ipairs({0, 1}) do
        local ok5, ret5 = pcall(function()
            return sc599(uint64(h), uint64(flags), uint64(outbuf))
        end)
        local rv5 = -999
        if ok5 then rv5 = to_num(ret5) end
        local modified = 0
        for off = 0, 0x1F8, 8 do
            local qv = safe_rq(outbuf + off)
            local qh, ql = get_hi_lo(qv)
            if ql ~= 0xDEADBEEF or qh ~= 0 then modified = modified + 1 end
        end
        if rv5 ~= -1 or modified > 0 then
            print(string.format("    handle=%d flags=%d ret=%d modified=%d", h, flags, rv5, modified))
        end
    end
end
print("")

-- ============================================================
-- PHASE D: 572 re-shape (two copyouts, no gate per 13.60)
-- Previous tests used wrong slot layout. Try all 3-arg permutations.
-- ============================================================
print("[D] Testing syscall 572 re-shape...")

local sc572 = make_syscall(572)
local shapes = {
    {"(outbuf, 0, size)",    function(buf, sz) return sc572(uint64(buf), uint64(0), uint64(sz)) end},
    {"(outbuf, 1, size)",    function(buf, sz) return sc572(uint64(buf), uint64(1), uint64(sz)) end},
    {"(0, outbuf, size)",    function(buf, sz) return sc572(uint64(0), uint64(buf), uint64(sz)) end},
    {"(1, outbuf, size)",    function(buf, sz) return sc572(uint64(1), uint64(buf), uint64(sz)) end},
    {"(size, outbuf, 0)",    function(buf, sz) return sc572(uint64(sz), uint64(buf), uint64(0)) end},
    {"(size, 0, outbuf)",    function(buf, sz) return sc572(uint64(sz), uint64(0), uint64(buf)) end},
    {"(outbuf, size, 0)",    function(buf, sz) return sc572(uint64(buf), uint64(sz), uint64(0)) end},
    {"(0, size, outbuf)",    function(buf, sz) return sc572(uint64(0), uint64(sz), uint64(buf)) end},
}

for _, shape in ipairs(shapes) do
    local label, fn = shape[1], shape[2]
    local outbuf = memory.alloc(0x200)
    for off = 0, 0x1F8, 8 do
        safe_wq(outbuf + off, uint64(0xCAFEBABE))
    end
    local ok6, ret6 = pcall(function() return fn(outbuf, 0x200) end)
    local rv6 = -999
    if ok6 then rv6 = to_num(ret6) end
    local modified = 0
    local kptrs = 0
    for off = 0, 0x1F8, 8 do
        local qv = safe_rq(outbuf + off)
        local qh, ql = get_hi_lo(qv)
        if ql ~= 0xCAFEBABE or qh ~= 0 then
            modified = modified + 1
            if is_kptr(qv) then kptrs = kptrs + 1 end
        end
    end
    local tag = ""
    if rv6 == 0 then tag = " *** RET=0 ***" end
    if modified > 0 then tag = tag .. string.format(" MODIFIED=%d", modified) end
    if kptrs > 0 then tag = tag .. string.format(" KPTRS=%d", kptrs) end
    print(string.format("  %-25s ret=%d%s", label, rv6, tag))

    -- Dump modified + kptrs
    if modified > 0 and modified <= 16 then
        for off = 0, 0x1F8, 8 do
            local qv = safe_rq(outbuf + off)
            local qh, ql = get_hi_lo(qv)
            if ql ~= 0xCAFEBABE or qh ~= 0 then
                print(string.format("    +0x%03X: %s%s", off, fmt_qw(qv),
                    is_kptr(qv) and " *** KPTR ***" or ""))
            end
        end
    end
end
print("")

print("=== PROBE 571a COMPLETE — process alive ===")
