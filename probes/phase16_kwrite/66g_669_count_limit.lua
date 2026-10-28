-- CRASH_CLASS: MODERATE
-- PROBE 66g: Measure sys 669 (AIO submit) count limit on 14.10
--
-- 662 (delete) rejects count≥129 on 14.10 (stack clash guard).
-- 669 (submit) count limit is UNKNOWN. The 13.60 decompile shows
-- malloc(count * 0x28) for the per-request array — if count is
-- unclamped, large values overflow the allocation into adjacent heap.
--
-- Also tests: what happens when the copyin source (reqs array) is
-- too small for the declared count? The kernel copies count*0x28 bytes
-- from userland — if the user buffer is only 0x28 bytes but count>1,
-- it reads past our buffer into unmapped memory → copyin fault.
-- If copyin fault is handled gracefully (ret=-1), we can test counts up to large values.

print("=== PROBE 66g: 669 count limit ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- =========================================================
-- [A] Binary search for 669 count limit
-- =========================================================
print("")
print("[A] 669 count limit binary search")

-- Build a large reqs buffer with valid entries
local big_reqs = memory.alloc(0x4000)  -- 16KB = room for 409 entries at 0x28 each
local dbuf = memory.alloc(0x4000)
local rbuf = memory.alloc(0x100)
local ids = memory.alloc(0x1000)

-- Fill with valid request entries
for i = 0, 127 do
    local base = N(big_reqs) + i * 0x28
    wq(base, uint64(0))          -- cmd/flags
    wq(base + 8, uint64(16))     -- size
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(base + 0x10, bl); wd(base + 0x14, bh)  -- data buffer
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(base + 0x18, rl); wd(base + 0x1C, rh)  -- result buffer
    wd(base + 0x20, fd_zero); wd(base + 0x24, 0)  -- fd
end

-- Test specific counts
local test_counts = {1, 2, 4, 8, 16, 32, 64, 128, 129, 130, 192, 256, 384, 512}

for _, cnt in ipairs(test_counts) do
    if not alive() then print("  DEAD at count=" .. cnt); break end

    -- Zero ids buffer
    for i = 0, math.min(cnt, 256) - 1 do
        wd(N(ids) + i * 4, 0)
    end

    local ok, ret = pcall(function()
        return mk(669)(uint64(1), uint64(N(big_reqs)), uint64(cnt), uint64(1), uint64(N(ids)))
    end)

    if not ok then
        print(string.format("  count=%d: CRASH", cnt))
        break
    end

    local r = sgn(ret)
    -- Count how many IDs were returned
    local got = 0
    for i = 0, math.min(cnt, 256) - 1 do
        local id = rd(N(ids) + i * 4) or 0
        if id ~= 0 then got = got + 1 end
    end

    print(string.format("  count=%3d: ret=%d ids=%d", cnt, r, got))

    -- Cleanup: delete any created requests
    if got > 0 then
        local del_b = memory.alloc(4 * got + 4)
        local del_s = memory.alloc(4 * got + 4)
        local j = 0
        for i = 0, math.min(cnt, 256) - 1 do
            local id = rd(N(ids) + i * 4) or 0
            if id ~= 0 then
                -- Poll first (required for delete)
                local po = memory.alloc(8)
                wd(N(po), id)
                local ps = memory.alloc(8)
                wd(N(ps), 0)
                pcall(function()
                    mk(664)(uint64(N(po)), uint64(1), uint64(N(ps)))
                end)
                wd(N(del_b) + j * 4, id)
                wd(N(del_s) + j * 4, 0xDEAD)
                j = j + 1
            end
        end
        if j > 0 then
            pcall(function()
                mk(662)(uint64(N(del_b)), uint64(j), uint64(N(del_s)))
            end)
        end
    end
end

if not alive() then print("DEAD after count test"); return end

-- =========================================================
-- [B] Test 669 with valid large buffer but count > entries
-- =========================================================
print("")
print("[B] 669 with count exceeding valid reqs buffer")

-- The reqs buffer is 0x4000 bytes = 128 entries of 0x28
-- What happens if we say count=129 but only have 128 valid entries?
-- The kernel does copyin(count * 0x28) → reads 129 * 0x28 = 0x1428 bytes
-- But our buffer is only 0x4000... so 129 entries fit.
-- Let's try count=409 (409 * 0x28 = 0x3F68 ≤ 0x4000) — this fits in our buffer
-- And count=410 (410 * 0x28 = 0x3F90 ≤ 0x4000) — also fits

for _, cnt in ipairs({128, 129, 256, 384, 409}) do
    if not alive() then break end

    -- Fill ALL entries (not just first 128)
    for i = 128, cnt - 1 do
        local base = N(big_reqs) + i * 0x28
        wq(base, uint64(0))
        wq(base + 8, uint64(16))
        local bh, bl = get_hi_lo(uint64(N(dbuf)))
        wd(base + 0x10, bl); wd(base + 0x14, bh)
        local rh, rl = get_hi_lo(uint64(N(rbuf)))
        wd(base + 0x18, rl); wd(base + 0x1C, rh)
        wd(base + 0x20, fd_zero); wd(base + 0x24, 0)
    end

    -- Need larger ids buffer for big counts
    local big_ids = memory.alloc(cnt * 4 + 16)
    for i = 0, cnt - 1 do wd(N(big_ids) + i * 4, 0) end

    local ok, ret = pcall(function()
        return mk(669)(uint64(1), uint64(N(big_reqs)), uint64(cnt), uint64(1), uint64(N(big_ids)))
    end)

    if not ok then
        print(string.format("  count=%d: PCALL-FAIL", cnt))
    else
        local r = sgn(ret)
        local got = 0
        for i = 0, math.min(cnt, 512) - 1 do
            local id = rd(N(big_ids) + i * 4) or 0
            if id ~= 0 then got = got + 1 end
        end
        print(string.format("  count=%d: ret=%d ids=%d", cnt, r, got))

        -- Cleanup
        if got > 0 and got <= 512 then
            for i = 0, got - 1 do
                local id = rd(N(big_ids) + i * 4) or 0
                if id ~= 0 then
                    local po = memory.alloc(8); wd(N(po), id)
                    local ps = memory.alloc(8); wd(N(ps), 0)
                    pcall(function() mk(664)(uint64(N(po)), uint64(1), uint64(N(ps))) end)
                end
            end
            local del_b = memory.alloc(got * 4 + 4)
            local del_s = memory.alloc(got * 4 + 4)
            for i = 0, got - 1 do
                local id = rd(N(big_ids) + i * 4) or 0
                wd(N(del_b) + i * 4, id)
                wd(N(del_s) + i * 4, 0)
            end
            pcall(function()
                mk(662)(uint64(N(del_b)), uint64(got), uint64(N(del_s)))
            end)
        end
    end
end

print("")
print("=== PROBE 66g COMPLETE ===")
