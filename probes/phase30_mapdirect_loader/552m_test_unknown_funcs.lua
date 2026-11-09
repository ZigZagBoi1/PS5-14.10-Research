-- CRASH_CLASS: MODERATE
-- PROBE 552m: Test unknown libkernel functions from GOT catalog
--
-- From 552l GOT scan, 13 libkernel imports found. Testing unknowns:
--   lk+0x15250, lk+0x153C0, lk+0x16BB0, lk+0x18360, lk+0x18490
--   lk+0x02E10, lk+0x0F0A0, lk+0x1CDA0, lk+0x1CE80, lk+0x216A0
--
-- Goal: identify MapDirectMemory/MapFlexibleMemory/Munmap/Query
-- Strategy: call each with (0,0,0,0,0,0) via fcall — most will return
-- -1 or 0 harmlessly, lethal ones kill like +0x15020.
-- Test ONE per connection to survive crashes.

print("=== PROBE 552m: Test unknown libkernel functions ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
pcall(function() memory.write_qword(N(sa_buf), uint64(1)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

-- Test each unknown function with various arg patterns
-- Using output buffers so even functions that write results are safe
local outbuf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(outbuf) + i, 0) end

local funcs = {
    {off = 0x18490, name = "near_alloc_1"},
    {off = 0x18360, name = "near_alloc_2"},
    {off = 0x153C0, name = "near_map_1"},
    {off = 0x15250, name = "near_map_2"},
    {off = 0x16BB0, name = "mid_range"},
    {off = 0x02E10, name = "low_offset"},
    {off = 0x0F0A0, name = "mid_low"},
    {off = 0x1CDA0, name = "high_1"},
    {off = 0x1CE80, name = "high_2"},
    {off = 0x216A0, name = "highest"},
}

for fi, f in ipairs(funcs) do
    if not alive() then
        print(string.format("\n*** PROCESS DIED at func %d (lk+0x%05X %s) ***",
            fi - 1, funcs[fi - 1] and funcs[fi - 1].off or 0,
            funcs[fi - 1] and funcs[fi - 1].name or "?"))
        break
    end

    local fn = lk + uint64(f.off)
    print(string.format("\n[%d] lk+0x%05X (%s)", fi, f.off, f.name))
    io.flush()

    -- Test 1: call with all zeros
    local ok1, rv1 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    if not alive() then
        print("  zeros: KILLED")
        break
    end
    print(string.format("  zeros: ok=%s rv=%s", tostring(ok1),
        ok1 and tostring(N(rv1)) or "crash"))

    -- Test 2: call with output buffer as first arg
    local ok2, rv2 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(N(outbuf)), uint64(0x4000), uint64(3),
            uint64(0), uint64(0), uint64(0))
    end)
    if not alive() then
        print("  buf_test: KILLED")
        break
    end
    print(string.format("  buf_test: ok=%s rv=%s", tostring(ok2),
        ok2 and tostring(N(rv2)) or "crash"))

    -- Check if output buffer was written
    local written = false
    for i = 0, 0x1C, 4 do
        local v = rd(N(outbuf) + i)
        if v and v ~= 0 then
            print(string.format("    outbuf+0x%X = 0x%X", i, v))
            written = true
        end
    end

    -- Test 3: with physical address arg (like AllocateDirectMemory output)
    local ok3, rv3 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(N(outbuf)), uint64("0x150000000"), uint64(0x4000),
            uint64(0x4000), uint64(0), uint64(N(outbuf) + 0x40))
    end)
    if not alive() then
        print("  phys_test: KILLED")
        break
    end
    print(string.format("  phys_test: ok=%s rv=%s", tostring(ok3),
        ok3 and tostring(N(rv3)) or "crash"))
end

-- Also check: DirectMemoryQuery might be one of these
-- sceKernelDirectMemoryQuery(off_t offset, int flags, SceKernelDirectMemoryQueryInfo *info, size_t infoSize)
-- Try calling with offset=0, flags=0, info buffer, size
print("")
print("[QUERY TEST] Testing likely DirectMemoryQuery patterns")
if alive() then
    local query_buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do wd(N(query_buf) + i, 0) end

    -- Try each surviving function with query-like args
    for fi, f in ipairs(funcs) do
        if not alive() then break end
        local fn = lk + uint64(f.off)
        -- DirectMemoryQuery(offset, flags, info*, infoSize)
        local ok_q, rv_q = pcall(function()
            return native.fcall_with_rax(fn, 0,
                uint64(0), uint64(0), uint64(N(query_buf)), uint64(0x40),
                uint64(0), uint64(0))
        end)
        if not alive() then
            print(string.format("  lk+0x%05X query: KILLED", f.off))
            break
        end
        local rv = ok_q and N(rv_q) or -999
        if rv == 0 then
            print(string.format("  lk+0x%05X query: rv=0 *** RETURNED DATA? ***", f.off))
            for i = 0, 0x3C, 4 do
                local v = rd(N(query_buf) + i)
                if v and v ~= 0 then
                    print(string.format("    +0x%X: 0x%X", i, v < 0 and v + 0x100000000 or v))
                end
            end
        end
        -- Reset buffer
        for i = 0, 0xFC, 4 do wd(N(query_buf) + i, 0) end
    end
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
