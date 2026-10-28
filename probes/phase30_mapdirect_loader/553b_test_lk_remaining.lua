-- CRASH_CLASS: MODERATE
-- PROBE 553b: Test remaining untested libkernel GOT functions
--
-- Known results from 553a:
--   +0x02E10 = getter ptr (returns libkernel .data addr), SAFE
--   +0x0F0A0 = KILLS
--   +0x15020 = KILLS (MapDirectMemory)
--   +0x17810 = GetDirectMemorySize OK
--   +0x17EF0 = AllocateDirectMemory OK
--   +0x18490 = KILLS
--   +0x216A0 = returns 1, SAFE
--   +0x1CE80 = writes binary to stdout (needs investigation)
--
-- This probe tests: 0x1CDA0, 0x16BB0, 0x15250, 0x153C0, 0x18360
-- Plus deeper investigation of 0x1CE80

print("=== PROBE 553b: Remaining libkernel GOT tests ===")
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

local sa_buf = memory.alloc(0x20)
pcall(function() memory.write_qword(N(sa_buf), uint64(1)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

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

local function test_func(off, name)
    if not alive() then return false end
    local fn = lk + uint64(off)
    print(string.format("[lk+0x%05X] %s", off, name))

    -- Zero output buffer
    for i = 0, 0xFC, 4 do wd(N(outbuf) + i, 0) end

    -- Call with all zeros
    local ok1, rv1 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)

    if not alive() then
        print("  KILLED on zeros")
        return false
    end

    print(string.format("  zeros: %s", ok1 and fmt(rv1) or "pcall_fail"))

    -- Call with output buffer
    for i = 0, 0xFC, 4 do wd(N(outbuf) + i, 0) end
    local ok2, rv2 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(N(outbuf)), uint64(0x100), uint64(3),
            uint64(0), uint64(0), uint64(0))
    end)

    if not alive() then
        print("  KILLED on buf args")
        return false
    end

    print(string.format("  buf: %s", ok2 and fmt(rv2) or "pcall_fail"))

    -- Dump outbuf changes
    local any_written = false
    for i = 0, 0x78, 8 do
        local v = rq(N(outbuf) + i)
        if v then
            local h, l = get_hi_lo(v)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            if h ~= 0 or l ~= 0 then
                print(string.format("    out+0x%02X: %s", i, fmt(v)))
                any_written = true
            end
        end
    end
    if not any_written then print("    (buffer clean)") end

    -- If rv is a pointer, peek at target
    if ok2 and rv2 then
        local h, l = get_hi_lo(rv2)
        if h < 0 then h = h + 0x100000000 end
        if h > 0 and h < 0xFFFF0000 then
            print("  rv is ptr, target:")
            for i = 0, 0x18, 8 do
                local tv = rq(N(rv2) + i)
                if tv then print(string.format("    [+0x%02X]: %s", i, fmt(tv))) end
            end
        end
    end

    print("")
    return true
end

-- Test in safe-first order
print("")
print("=== SECTION A: Untested functions ===")
test_func(0x1CDA0, "high_1")
test_func(0x16BB0, "mid_range")
test_func(0x18360, "near_alloc")
test_func(0x15250, "near_map_2")
test_func(0x153C0, "near_map_1")

-- Section B: Deeper look at 0x1CE80
-- This function wrote binary data in 553a. Call it but redirect output.
-- Actually just call it carefully and check buffer.
if alive() then
    print("=== SECTION B: Deep look at lk+0x1CE80 ===")
    local fn_ce80 = lk + uint64(0x1CE80)

    for i = 0, 0xFC, 4 do wd(N(outbuf) + i, 0) end

    -- Call with buffer as arg1, size as arg2
    local ok_b, rv_b = pcall(function()
        return native.fcall_with_rax(fn_ce80, 0,
            uint64(N(outbuf)), uint64(0x100), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)

    if alive() then
        print(string.format("  rv: %s ok=%s", ok_b and fmt(rv_b) or "crash", tostring(ok_b)))

        -- Dump what it wrote
        for i = 0, 0x78, 8 do
            local v = rq(N(outbuf) + i)
            if v then
                local h, l = get_hi_lo(v)
                if h < 0 then h = h + 0x100000000 end
                if l < 0 then l = l + 0x100000000 end
                if h ~= 0 or l ~= 0 then
                    print(string.format("    out+0x%02X: %s", i, fmt(v)))
                end
            end
        end
    else
        print("  KILLED")
    end
end

-- Section C: Deeper look at 0x02E10 getter
if alive() then
    print("")
    print("=== SECTION C: lk+0x02E10 getter deep dump ===")
    local fn_2e10 = lk + uint64(0x02E10)
    local ok_g, rv_g = pcall(function()
        return native.fcall_with_rax(fn_2e10, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok_g and rv_g and alive() then
        print(string.format("  ptr: %s", fmt(rv_g)))
        -- Dump 256 bytes
        for i = 0, 0xF8, 8 do
            local v = rq(N(rv_g) + i)
            if v then
                local h, l = get_hi_lo(v)
                if h < 0 then h = h + 0x100000000 end
                if l < 0 then l = l + 0x100000000 end
                if h ~= 0 or l ~= 0 then
                    print(string.format("    [+0x%02X]: %s", i, fmt(v)))
                end
            end
        end
    end
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
