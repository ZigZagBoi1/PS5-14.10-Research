-- CRASH_CLASS: MODERATE
-- PROBE 553a: Test untested libkernel GOT functions (safe-first order)
--
-- From 552l: 13 libkernel imports. 3 known, 2 kill, 8 untested.
-- Test order: farthest from Map cluster first (least likely auth-gated).
-- Each function called with (0,0,0,0,0,0) then with output buffer.
-- Print result after each call — if process dies, last printed line tells us which killed.

print("=== PROBE 553a: Test libkernel GOT functions ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
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
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid
end

-- Suppress SIGPIPE/SIGALRM
local sa_buf = memory.alloc(0x20)
pcall(function() memory.write_qword(N(sa_buf), uint64(1)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- libkernel base
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

local outbuf = memory.alloc(0x200)

-- Test order: farthest from Map cluster first
-- KNOWN RESULTS:
--   +0x02E10 = returns userland ptr (getter), SAFE
--   +0x0F0A0 = KILLS
--   +0x15020 = KILLS (MapDirectMemory)
--   +0x17810 = GetDirectMemorySize OK
--   +0x17EF0 = AllocateDirectMemory OK
--   +0x18490 = KILLS
-- SKIP killers, test remaining
local funcs = {
    {off = 0x02E10, name = "getter_ptr"},
    {off = 0x216A0, name = "highest"},
    {off = 0x1CE80, name = "high_2"},
    {off = 0x1CDA0, name = "high_1"},
    {off = 0x16BB0, name = "mid_range"},
    {off = 0x15250, name = "near_map_2"},
    {off = 0x153C0, name = "near_map_1"},
    {off = 0x18360, name = "near_alloc"},
}

for fi, f in ipairs(funcs) do
    if not alive() then
        print(string.format("*** DIED before func #%d (lk+0x%05X %s) ***", fi, f.off, f.name))
        break
    end

    local fn = lk + uint64(f.off)
    print(string.format("[%d] lk+0x%05X (%s) CALLING...", fi, f.off, f.name))

    -- Zero output buffer
    for i = 0, 0x7C, 4 do wd(N(outbuf) + i, 0) end

    -- Test 1: all zeros
    local ok1, rv1 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)

    if not alive() then
        print("  zeros: KILLED")
        break
    end

    print(string.format("  zeros: rv=%s ok=%s", ok1 and fmt(rv1) or "crash", tostring(ok1)))

    -- Test 2: with output buffer as arg1
    for i = 0, 0x7C, 4 do wd(N(outbuf) + i, 0) end
    local ok2, rv2 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(N(outbuf)), uint64(0x100), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)

    if not alive() then
        print("  buf: KILLED")
        break
    end

    print(string.format("  buf: rv=%s ok=%s", ok2 and fmt(rv2) or "crash", tostring(ok2)))

    -- Check if output buffer was written
    for i = 0, 0x3C, 8 do
        local v = rq(N(outbuf) + i)
        if v then
            local h, l = get_hi_lo(v)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            if h ~= 0 or l ~= 0 then
                print(string.format("    outbuf+0x%02X = %s", i, fmt(v)))
            end
        end
    end

    -- If rv is a pointer, try reading what it points to
    if ok2 and rv2 then
        local rv_h, rv_l = get_hi_lo(rv2)
        if rv_h < 0 then rv_h = rv_h + 0x100000000 end
        if rv_h > 0 and rv_h < 0xFFFF0000 then
            print("  rv looks like userland ptr, reading target:")
            for i = 0, 0x38, 8 do
                local tv = rq(N(rv2) + i)
                if tv then
                    print(string.format("    [rv+0x%02X] = %s", i, fmt(tv)))
                end
            end
        end
    end

    -- Test 3: with meaningful size args (query-like)
    for i = 0, 0x7C, 4 do wd(N(outbuf) + i, 0) end
    local ok3, rv3 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(N(outbuf)),
            uint64(0x100), uint64(0), uint64(0))
    end)

    if not alive() then
        print("  query: KILLED")
        break
    end

    print(string.format("  query: rv=%s ok=%s", ok3 and fmt(rv3) or "crash", tostring(ok3)))

    for i = 0, 0x3C, 4 do
        local v = rd(N(outbuf) + i)
        if v and v ~= 0 then
            print(string.format("    outbuf+0x%X = 0x%X", i, v < 0 and v + 0x100000000 or v))
        end
    end

    print("")
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
