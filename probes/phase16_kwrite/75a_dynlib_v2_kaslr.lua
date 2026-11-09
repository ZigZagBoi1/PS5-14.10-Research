-- CRASH_CLASS: LOW
-- PROBE 75a: dynlib v2/relocation KASLR search
--
-- Three untested dynlib handlers from 13.60 offline decode:
-- 1. sys 660 dynlib_get_info2 — NO gate, v2 filler may include kernel ptrs 593 skips
-- 2. sys 599 dynlib_process_needed_and_relocate — ungated, reaches deep copyouts
-- 3. sys 656 dynlib_get_info_for_libdbg — debug-unit gate, might pass on retail
--
-- For 660: dump all 0x160 bytes for each valid handle, diff against 593 output

print("=== PROBE 75a: DYNLIB V2 KASLR SEARCH ===")
print("")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc593 = mk(593)
local sc660 = mk(660)
local sc656 = mk(656)
local sc599 = mk(599)

-- ============================================================
-- [A] Find valid module handles (same method as 69l)
-- ============================================================
print("")
print("[A] Enumerating valid module handles")
local valid_handles = {}
local info_buf = memory.alloc(0x200)
for h = 0, 80 do
    for off = 0, 0x1FF, 4 do wd(N(info_buf) + off, 0) end
    wd(N(info_buf), 0x160) -- size field
    local ret = -1
    pcall(function() ret = N(sc593(uint64(h), info_buf)) end)
    if ret == 0 then
        valid_handles[#valid_handles + 1] = h
    end
end
print("  valid handles: " .. #valid_handles)
local handles_str = ""
for i, h in ipairs(valid_handles) do
    if i <= 20 then handles_str = handles_str .. h .. " " end
end
print("  first 20: " .. handles_str)

if #valid_handles == 0 then
    print("FATAL: no valid handles")
    return
end

-- ============================================================
-- [B] Full 660 vs 593 diff for every handle
-- ============================================================
print("")
print("[B] sys 660 vs 593: full 0x160 byte comparison")

local buf_593 = memory.alloc(0x200)
local buf_660 = memory.alloc(0x200)
local total_660_kptrs = 0
local total_diff_qwords = 0

for idx, h in ipairs(valid_handles) do
    -- Fill both with sentinels, then set size as QWORD (size field is 8 bytes)
    for off = 0, 0x19F, 4 do
        wd(N(buf_593) + off, 0xDEDEDEDE)
        wd(N(buf_660) + off, 0xDEDEDEDE)
    end

    -- Size field is a qword at +0x00 — must be exactly 0x160
    wq(N(buf_593), uint64(0x160))
    wq(N(buf_660), uint64(0x160))

    -- Call 593
    local ret_593 = -1
    pcall(function() ret_593 = N(sc593(uint64(h), buf_593)) end)

    -- Call 660
    local ret_660 = -1
    pcall(function() ret_660 = N(sc660(uint64(h), buf_660)) end)

    if ret_660 ~= 0 then
        if idx <= 5 then
            print(string.format("  h=%d: 660 ret=%d (593 ret=%d)", h, ret_660, ret_593))
        end
    else
        -- Both returned 0. Compare all 0x160 bytes by qword
        local diff_count = 0
        local kptrs_660 = 0
        local diff_offsets = {}

        for off = 0, 0x158, 8 do
            local q593 = rq(uint64(N(buf_593) + off))
            local q660 = rq(uint64(N(buf_660) + off))
            local h593, l593 = get_hi_lo(q593)
            local h660, l660 = get_hi_lo(q660)

            if h593 ~= h660 or l593 ~= l660 then
                diff_count = diff_count + 1
                diff_offsets[#diff_offsets + 1] = {off = off, v593 = q593, v660 = q660}
            end

            if is_kptr(q660) then
                kptrs_660 = kptrs_660 + 1
                print(string.format("  *** h=%d +0x%03X: 660 KPTR %s (593=%s) ***",
                    h, off, fmt(q660), fmt(q593)))
            end
        end

        total_diff_qwords = total_diff_qwords + diff_count
        total_660_kptrs = total_660_kptrs + kptrs_660

        if diff_count > 0 and idx <= 10 then
            print(string.format("  h=%d: %d differing qwords, %d kptrs", h, diff_count, kptrs_660))
            for _, d in ipairs(diff_offsets) do
                if d.off <= 0x160 then
                    print(string.format("    +0x%03X: 593=%s  660=%s", d.off, fmt(d.v593), fmt(d.v660)))
                end
            end
        end
    end

    if not alive() then print("DEAD during handle " .. h); return end
end

print(string.format("  TOTAL: %d differing qwords across %d handles, %d kernel ptrs in 660",
    total_diff_qwords, #valid_handles, total_660_kptrs))

-- ============================================================
-- [C] 660-only fields: scan for any non-zero bytes 593 left as sentinel
-- ============================================================
print("")
print("[C] 660-only fields (non-zero where 593 left sentinel)")
local extra_fields = 0
local extra_kptrs = 0

for idx, h in ipairs(valid_handles) do
    -- Fill 593 buf with zeros, 660 buf with zeros, set size as qword
    for off = 0, 0x19F, 4 do
        wd(N(buf_593) + off, 0)
        wd(N(buf_660) + off, 0)
    end
    wq(N(buf_593), uint64(0x160))
    wq(N(buf_660), uint64(0x160))

    local ret_593 = -1
    pcall(function() ret_593 = N(sc593(uint64(h), buf_593)) end)
    local ret_660 = -1
    pcall(function() ret_660 = N(sc660(uint64(h), buf_660)) end)

    if ret_593 == 0 and ret_660 == 0 then
        -- Check for qwords that are 0 in 593 but non-zero in 660
        for off = 8, 0x158, 8 do
            local q593 = rq(uint64(N(buf_593) + off))
            local q660 = rq(uint64(N(buf_660) + off))
            local h593, l593 = get_hi_lo(q593)
            local h660, l660 = get_hi_lo(q660)

            if (h593 == 0 and l593 == 0) and (h660 ~= 0 or l660 ~= 0) then
                extra_fields = extra_fields + 1
                if is_kptr(q660) then
                    extra_kptrs = extra_kptrs + 1
                    print(string.format("  *** h=%d +0x%03X: 660-ONLY KPTR %s ***", h, off, fmt(q660)))
                else
                    if idx <= 5 then
                        print(string.format("  h=%d +0x%03X: 660-only value %s", h, off, fmt(q660)))
                    end
                end
            end
        end
    end
end
print(string.format("  660-only non-zero fields: %d, kernel ptrs: %d", extra_fields, extra_kptrs))

-- ============================================================
-- [D] sys 656 dynlib_get_info_for_libdbg (debug-unit gate)
-- ============================================================
print("")
print("[D] sys 656 (debug-unit gate) test")
for _, h in ipairs({valid_handles[1], valid_handles[2] or 0}) do
    for off = 0, 0x19F, 4 do wd(N(buf_660) + off, 0xCCCCCCCC) end
    wq(N(buf_660), uint64(0x160))
    local ret = -1
    pcall(function() ret = N(sc656(uint64(h), buf_660)) end)
    local modified = 0
    for off = 4, 0x15C, 4 do
        if rd(N(buf_660) + off) ~= 0xCCCCCCCC then modified = modified + 1 end
    end
    print(string.format("  h=%d ret=%d modified_dwords=%d", h, ret, modified))

    if ret == 0 and modified > 0 then
        -- Scan for kernel pointers
        for off = 0, 0x158, 8 do
            local q = rq(uint64(N(buf_660) + off))
            if q and is_kptr(q) then
                print(string.format("    *** +0x%03X: KPTR %s ***", off, fmt(q)))
            end
        end
    end
end

-- ============================================================
-- [E] sys 599 dynlib_process_needed_and_relocate
-- ============================================================
print("")
print("[E] sys 599 (dynlib relocate) — argument exploration")

-- 599 has narg=0 in some records, but the offline decode says it reaches
-- copyouts through the loader. Try various arg shapes.
local out_buf = memory.alloc(0x1000)

-- Shape 1: zero args
for off = 0, 0xFF, 4 do wd(N(out_buf) + off, 0xDEAD) end
local ret = -1
pcall(function() ret = N(sc599(uint64(0), uint64(0), uint64(0), uint64(0))) end)
print(string.format("  shape(0,0,0,0): ret=%d", ret))

-- Shape 2: valid handle, zero flags
for _, h in ipairs({valid_handles[1], valid_handles[2] or 0}) do
    pcall(function() ret = N(sc599(uint64(h), uint64(0))) end)
    print(string.format("  shape(h=%d,0): ret=%d", h, ret))
end

-- Shape 3: valid handle, flags=1
for _, h in ipairs({valid_handles[1]}) do
    pcall(function() ret = N(sc599(uint64(h), uint64(1))) end)
    print(string.format("  shape(h=%d,1): ret=%d", h, ret))

    pcall(function() ret = N(sc599(uint64(h), uint64(2))) end)
    print(string.format("  shape(h=%d,2): ret=%d", h, ret))

    pcall(function() ret = N(sc599(uint64(h), uint64(0x100))) end)
    print(string.format("  shape(h=%d,0x100): ret=%d", h, ret))
end

-- Shape 4: handle + output buffer
for _, h in ipairs({valid_handles[1]}) do
    for off = 0, 0xFF, 4 do wd(N(out_buf) + off, 0xDEAD) end
    pcall(function() ret = N(sc599(uint64(h), uint64(N(out_buf)))) end)
    local mod = 0
    for off = 0, 0xFC, 4 do
        if rd(N(out_buf) + off) ~= 0xDEAD then mod = mod + 1 end
    end
    print(string.format("  shape(h=%d,buf): ret=%d modified=%d", h, ret, mod))
    if mod > 0 then
        for off = 0, 0xF8, 8 do
            local q = rq(uint64(N(out_buf) + off))
            if q and is_kptr(q) then
                print(string.format("    *** +0x%02X: KPTR %s ***", off, fmt(q)))
            end
        end
    end
end

if not alive() then print("DEAD after [E]"); return end

-- ============================================================
-- [F] sys 591 dynlib_dlsym with valid handles + NID-style strings
-- ============================================================
print("")
print("[F] sys 591 (dynlib_dlsym) with real handles")

local sc591 = mk(591)
local sym_buf = memory.alloc(0x100)
local res_buf = memory.alloc(16)

-- PS5 NIDs are typically 11-char base64 encoded hashes
-- Try some known PS5 NID patterns
local nid_candidates = {
    "sceKernelSleep",           -- plain name (unlikely)
    "sceKernelGetProcParam",    -- plain name
    "module_start",             -- standard ELF
    "module_stop",
    "_init",
    "_fini",
    "sceKernelGetCompiledSdkVersion",
    "sceKernelLoadStartModule",
    "sceKernelDlsym",
    "sceKernelClose",
    "sceKernelOpen",
    "sceKernelRead",
    "sceKernelWrite",
    "sceKernelMmap",
    "sceKernelGetModuleList",
}

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local total_591_hits = 0
for _, h in ipairs({valid_handles[1], valid_handles[2] or 0, 0}) do
    local hits = 0
    for _, sym in ipairs(nid_candidates) do
        local s = put_str(sym)
        wq(N(res_buf), uint64(0))
        local ret = -1
        -- Try 3-arg: 591(handle, name, result)
        pcall(function() ret = N(sc591(uint64(h), s, res_buf)) end)
        if ret == 0 then
            local addr = rq(uint64(N(res_buf)))
            hits = hits + 1
            print(string.format("  h=%d sym=%s ret=0 addr=%s%s",
                h, sym, fmt(addr), is_kptr(addr) and " ***KPTR***" or ""))
        end
    end
    if hits > 0 then
        print(string.format("  h=%d: %d/%d resolved", h, hits, #nid_candidates))
        total_591_hits = total_591_hits + hits
    else
        if h == valid_handles[1] then
            print(string.format("  h=%d: 0/%d (trying 4-arg variant...)", h, #nid_candidates))
            -- Try 4-arg: 591(handle, name, result, flags)
            for fi = 0, 3 do
                local s = put_str(nid_candidates[1])
                wq(N(res_buf), uint64(0))
                pcall(function() ret = N(sc591(uint64(h), s, res_buf, uint64(fi))) end)
                if ret == 0 then
                    print(string.format("    flags=%d ret=0 addr=%s", fi, fmt(rq(uint64(N(res_buf))))))
                    total_591_hits = total_591_hits + 1
                end
            end
        end
    end
end
print("  total 591 hits: " .. total_591_hits)

-- ============================================================
-- [G] SUMMARY
-- ============================================================
print("")
print("[G] SUMMARY")
print("  660 vs 593 diff qwords: " .. total_diff_qwords)
print("  660 kernel pointers: " .. total_660_kptrs)
print("  660-only extra fields: " .. extra_fields .. " (kptrs: " .. extra_kptrs .. ")")
print("  591 resolved symbols: " .. total_591_hits)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 75a COMPLETE ===")
