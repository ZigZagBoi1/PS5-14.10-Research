-- CRASH_CLASS: MODERATE
-- PROBE 553c: Deep investigation of interesting libkernel functions
--
-- 0x18360: returned 0 with zeros. Possible Release/Free/Munmap.
--          Test with AllocateDirectMemory output (real phys addr).
-- 0x153C0: never reached in 553b. Test solo.
-- 0x15250: returned 0 then HUNG on buf args. Test only zeros call,
--          check alive, do NOT call with buf args.
--
-- Also: investigate 0x1CE80 (wrote binary in 553a) — call without
--       printing its output, just check rv and buffer state.

print("=== PROBE 553c: Investigate interesting functions ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
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

-- ============ SECTION A: Test lk+0x153C0 solo ============
print("")
print("=== A: lk+0x153C0 (never tested) ===")
if alive() then
    local fn = lk + uint64(0x153C0)

    local ok1, rv1 = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    if alive() then
        print(string.format("  zeros: %s ok=%s", ok1 and fmt(rv1) or "crash", tostring(ok1)))
    else
        print("  KILLED on zeros")
    end
end

-- ============ SECTION B: lk+0x18360 with real args ============
-- First allocate direct memory to get a real physical address
print("")
print("=== B: lk+0x18360 (returned 0 with zeros) ===")
if alive() then
    -- AllocateDirectMemory: (searchStart, searchEnd, len, align, memType, physOut)
    local alloc_fn = lk + uint64(0x17EF0)
    local phys_out = memory.alloc(16)
    wq(N(phys_out), uint64(0))

    local ok_a, rv_a = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(0),                      -- searchStart
            uint64("0x150000000"),           -- searchEnd
            uint64(0x4000),                  -- len (16KB, one page)
            uint64(0x4000),                  -- alignment
            uint64(0),                       -- memType
            uint64(N(phys_out)))             -- physAddrOut
    end)

    local alloc_rv = ok_a and N(rv_a) or -1
    local phys_addr = rq(N(phys_out))
    print(string.format("  AllocDM: rv=%d phys=%s", alloc_rv, fmt(phys_addr)))

    if alloc_rv == 0 and phys_addr then
        -- Now test 0x18360 with the allocated physical address
        -- Could be: ReleaseDirectMemory(phys, len)
        --       or: MapDirectMemory variant
        --       or: QueryDirectMemory
        local fn_360 = lk + uint64(0x18360)

        -- Test as ReleaseDirectMemory(phys, len)
        local ok_r1, rv_r1 = pcall(function()
            return native.fcall_with_rax(fn_360, 0,
                phys_addr,                  -- physical address
                uint64(0x4000),             -- length
                uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        if alive() then
            print(string.format("  release(phys,len): %s", ok_r1 and fmt(rv_r1) or "crash"))
        else
            print("  release(phys,len): KILLED")
        end

        -- Re-allocate if that worked
        if alive() and ok_r1 and N(rv_r1) == 0 then
            print("  Release returned 0! Re-allocating...")
            wq(N(phys_out), uint64(0))
            pcall(function()
                return native.fcall_with_rax(alloc_fn, 0,
                    uint64(0), uint64("0x150000000"),
                    uint64(0x4000), uint64(0x4000),
                    uint64(0), uint64(N(phys_out)))
            end)
            local phys2 = rq(N(phys_out))
            print(string.format("  Re-alloc phys: %s", fmt(phys2)))
        end
    end

    -- Test as DirectMemoryQuery(offset, flags, info*, size)
    if alive() then
        local fn_360 = lk + uint64(0x18360)
        for i = 0, 0x7C, 4 do wd(N(outbuf) + i, 0) end

        local ok_q, rv_q = pcall(function()
            return native.fcall_with_rax(fn_360, 0,
                uint64(0),                  -- offset = start of pool
                uint64(0),                  -- flags
                uint64(N(outbuf)),          -- info buffer
                uint64(0x40),               -- info size
                uint64(0), uint64(0))
        end)
        if alive() then
            print(string.format("  query(0,0,buf,0x40): %s", ok_q and fmt(rv_q) or "crash"))
            for i = 0, 0x38, 8 do
                local v = rq(N(outbuf) + i)
                if v then
                    local h, l = get_hi_lo(v)
                    if h < 0 then h = h + 0x100000000 end
                    if l < 0 then l = l + 0x100000000 end
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    info+0x%02X: %s", i, fmt(v)))
                    end
                end
            end
        end
    end
end

-- ============ SECTION C: lk+0x1CE80 careful test ============
print("")
print("=== C: lk+0x1CE80 (binary output in 553a) ===")
if alive() then
    local fn = lk + uint64(0x1CE80)
    for i = 0, 0xFC, 4 do wd(N(outbuf) + i, 0) end

    -- Call with buf arg
    local ok_c, rv_c = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(N(outbuf)), uint64(0x100), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    if alive() then
        print(string.format("  rv: %s", ok_c and fmt(rv_c) or "crash"))

        -- Check buffer changes
        local any = false
        for i = 0, 0x78, 8 do
            local v = rq(N(outbuf) + i)
            if v then
                local h, l = get_hi_lo(v)
                if h < 0 then h = h + 0x100000000 end
                if l < 0 then l = l + 0x100000000 end
                if h ~= 0 or l ~= 0 then
                    print(string.format("    buf+0x%02X: %s", i, fmt(v)))
                    any = true
                end
            end
        end
        if not any then print("    (buffer clean)") end
    else
        print("  KILLED")
    end
end

-- ============ SECTION D: lk+0x1CDA0 and 0x16BB0 with real args ============
print("")
print("=== D: Sony error funcs with real args ===")
if alive() then
    -- 0x1CDA0 returned EINVAL/EFAULT. Try with pid as arg
    local fn_da0 = lk + uint64(0x1CDA0)
    local ok_d1, rv_d1 = pcall(function()
        return native.fcall_with_rax(fn_da0, 0,
            uint64(pid), uint64(0), uint64(N(outbuf)),
            uint64(0x100), uint64(0), uint64(0))
    end)
    if alive() then
        print(string.format("  0x1CDA0(pid,0,buf,0x100): %s", ok_d1 and fmt(rv_d1) or "crash"))
    end

    -- 0x16BB0 — try (buf, size, 0, 0)
    if alive() then
        for i = 0, 0xFC, 4 do wd(N(outbuf) + i, 0) end
        local fn_bb0 = lk + uint64(0x16BB0)
        local ok_d2, rv_d2 = pcall(function()
            return native.fcall_with_rax(fn_bb0, 0,
                uint64(N(outbuf)), uint64(0x4000), uint64(3),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if alive() then
            print(string.format("  0x16BB0(buf,0x4000,3,0x1002,-1,0): %s",
                ok_d2 and fmt(rv_d2) or "crash"))
        end
    end
end

-- ============ SECTION E: lk+0x02E10 deeper ============
print("")
print("=== E: lk+0x02E10 getter — full 256-byte dump ===")
if alive() then
    local fn = lk + uint64(0x02E10)
    local ok_e, rv_e = pcall(function()
        return native.fcall_with_rax(fn, 0,
            uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok_e and rv_e and alive() then
        print(string.format("  ptr: %s (lk+0x%X)",
            fmt(rv_e), N(rv_e) - N(lk)))
        for i = 0, 0xF8, 8 do
            local v = rq(N(rv_e) + i)
            if v then
                print(string.format("    [+0x%02X]: %s", i, fmt(v)))
            end
        end
    end
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
