-- CRASH_CLASS: LOW
-- PROBE 570a: Test ungated syscalls 591 (dynlib_dlsym) and 660 (dynlib_get_info2)
--
-- 591: dynlib_dlsym(handle, name*, out_addr*) — no authid, no bit-62 gate (13.60 decompile)
-- 660: dynlib_get_info2(id, info*) — no gate, same shape as 593
-- Neither tested with real args on 14.10.

print("=== PROBE 570a: dynlib_dlsym(591) + dynlib_get_info2(660) ===")
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
local sc591 = make_syscall(591)
local sc660 = make_syscall(660)

-- ============================================================
-- PHASE A: Enumerate module handles via 593
-- ============================================================
print("[A] Enumerating module handles via 593...")

local handles = {}
for h = 0, 50 do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), info) end)
    if ok then
        local rv = to_num(ret)
        if rv == 0 then
            local name_bytes = {}
            for i = 0, 31 do
                local b = safe_rd(info + 4 + i)
                if b and b > 0 and b < 128 then
                    table.insert(name_bytes, string.char(b))
                else
                    break
                end
            end
            local name = table.concat(name_bytes)
            local text_lo = safe_rd(info + 0x108)
            local text_hi = safe_rd(info + 0x10C)
            table.insert(handles, {id = h, name = name, text_lo = text_lo, text_hi = text_hi})
            print(string.format("  handle=%d name=%s text=0x%08X%08X", h, name, text_hi or 0, text_lo or 0))
        end
    end
end
print(string.format("  Found %d modules", #handles))
print("")

-- ============================================================
-- PHASE B: Test 660 (dynlib_get_info2) — diff against 593
-- ============================================================
print("[B] Testing syscall 660 (dynlib_get_info2)...")

for _, mod in ipairs(handles) do
    local info593 = memory.alloc(0x200)
    safe_wd(info593, 0x160)
    pcall(function() sc593(uint64(mod.id), info593) end)

    local info660 = memory.alloc(0x200)
    safe_wd(info660, 0x160)
    local ok, ret = pcall(function() return sc660(uint64(mod.id), info660) end)
    local rv = -999
    if ok then rv = to_num(ret) end

    print(string.format("  handle=%d (%s) 660_ret=%d", mod.id, mod.name, rv))

    if rv == 0 then
        -- Diff: scan full 0x160 bytes for differences and kernel pointers
        local diffs = 0
        local kptrs = 0
        for off = 0, 0x15F, 4 do
            local v593 = safe_rd(info593 + off)
            local v660 = safe_rd(info660 + off)
            if v593 ~= v660 then
                diffs = diffs + 1
                if diffs <= 16 then
                    print(string.format("    DIFF +0x%03X: 593=0x%08X 660=0x%08X", off, v593 or 0, v660 or 0))
                end
            end
        end
        -- Qword scan for kernel pointers in 660 output
        for off = 0, 0x158, 8 do
            local qv = safe_rq(info660 + off)
            if is_kptr(qv) then
                kptrs = kptrs + 1
                print(string.format("    *** KPTR at +0x%03X: %s ***", off, fmt_qw(qv)))
            end
        end
        print(string.format("    diffs=%d kptrs=%d", diffs, kptrs))
    end
end
print("")

-- ============================================================
-- PHASE C: Test 591 (dynlib_dlsym) with known symbol names
-- ============================================================
print("[C] Testing syscall 591 (dynlib_dlsym)...")

-- Try various symbol name formats
local test_names = {
    "sceKernelGetProcessTime",
    "sceKernelAllocateDirectMemory",
    "sceKernelMapDirectMemory",
    "sceKernelGetDirectMemorySize",
    "sceKernelDlsym",
    "sceKernelLoadStartModule",
    "sceKernelGetModuleInfo",
    "getpid",
    "mmap",
    "socket",
    "printf",
    "malloc",
    "free",
    "pthread_create",
    "sceKernelDebugOutText",
    "_ZN3sce2np12NotifySystem6NotifyEjy",
}

-- Find libkernel handle (usually 0 or 1)
local lk_handle = nil
for _, mod in ipairs(handles) do
    if mod.name:find("libkernel") or mod.name:find("libSce") then
        if lk_handle == nil then lk_handle = mod.id end
    end
end

-- If no libkernel found, try handle 0 and 1
if lk_handle == nil then lk_handle = 0 end

-- Test with first 3 module handles
local test_handles = {}
for i = 1, math.min(3, #handles) do
    table.insert(test_handles, handles[i])
end

for _, mod in ipairs(test_handles) do
    print(string.format("  --- handle=%d (%s) ---", mod.id, mod.name))
    for _, sym_name in ipairs(test_names) do
        -- Write symbol name to buffer
        local name_buf = memory.alloc(256)
        for i = 1, #sym_name do
            local ok = pcall(function()
                memory.write_dword(name_buf + (i - 1), string.byte(sym_name, i))
            end)
        end
        safe_wd(name_buf + #sym_name, 0)  -- null terminator

        local out_buf = memory.alloc(16)
        safe_wq(out_buf, uint64(0))

        local ok, ret = pcall(function()
            return sc591(uint64(mod.id), uint64(name_buf), uint64(out_buf))
        end)

        local rv = -999
        if ok then rv = to_num(ret) end

        local resolved = safe_rq(out_buf)
        local rh, rl = get_hi_lo(resolved)

        if rv == 0 or (rh ~= 0 or rl ~= 0) then
            print(string.format("    %-40s ret=%d addr=%s%s",
                sym_name, rv, fmt_qw(resolved),
                is_kptr(resolved) and " *** KERNEL ***" or ""))
        end
    end
end
print("")

-- ============================================================
-- PHASE D: 591 with handle=0 (special) and handle=-1
-- ============================================================
print("[D] Testing 591 edge cases...")

local edge_handles = {0, 0xFFFFFFFF, 0xFFFE}
local edge_names = {"getpid", "sceKernelGetProcessTime"}

for _, eh in ipairs(edge_handles) do
    for _, sym_name in ipairs(edge_names) do
        local name_buf = memory.alloc(256)
        for i = 1, #sym_name do
            pcall(function() memory.write_dword(name_buf + (i - 1), string.byte(sym_name, i)) end)
        end
        safe_wd(name_buf + #sym_name, 0)

        local out_buf = memory.alloc(16)
        safe_wq(out_buf, uint64(0))

        local ok, ret = pcall(function()
            return sc591(uint64(eh), uint64(name_buf), uint64(out_buf))
        end)
        local rv = -999
        if ok then rv = to_num(ret) end

        local resolved = safe_rq(out_buf)
        print(string.format("  handle=0x%X name=%-30s ret=%d addr=%s", eh, sym_name, rv, fmt_qw(resolved)))
    end
end
print("")

-- ============================================================
-- PHASE E: 660 full qword dump of first module (for deep diff)
-- ============================================================
print("[E] Full qword dump: 593 vs 660 for handle 0...")

local info593 = memory.alloc(0x200)
safe_wd(info593, 0x160)
pcall(function() sc593(uint64(0), info593) end)

local info660 = memory.alloc(0x200)
safe_wd(info660, 0x160)
local ok660, ret660 = pcall(function() return sc660(uint64(0), info660) end)
local rv660 = -999
if ok660 then rv660 = to_num(ret660) end
print(string.format("  660 ret=%d", rv660))

if rv660 == 0 then
    for off = 0, 0x158, 8 do
        local q593 = safe_rq(info593 + off)
        local q660 = safe_rq(info660 + off)
        local h593, l593 = get_hi_lo(q593)
        local h660, l660 = get_hi_lo(q660)
        local marker = ""
        if h593 ~= h660 or l593 ~= l660 then marker = " <-- DIFF" end
        if is_kptr(q660) then marker = marker .. " *** KPTR ***" end
        if marker ~= "" then
            print(string.format("  +0x%03X: 593=%s  660=%s%s", off, fmt_qw(q593), fmt_qw(q660), marker))
        end
    end
end

print("")
print("=== PROBE 570a COMPLETE — process alive ===")
