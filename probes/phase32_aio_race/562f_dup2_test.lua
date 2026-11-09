-- CRASH_CLASS: LOW
-- PROBE 562f: Test dup2 fd redirect for suppressing child "77" output
--
-- dup(41) returns -1 on PS5.
-- Try: dup2(90)(1, 100) to copy fd 1 → fd 100
-- Then close(1), spawn child (no output), dup2(100, 1) to restore.
--
-- Also test: fcntl(92) F_DUPFD=0

print("=== PROBE 562f: DUP2 FD REDIRECT TEST ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n-4, 4 do wd(buf + off, 0) end
end

local Z = uint64(0)
local sc6   = mk(6)    -- close
local sc20  = mk(20)   -- getpid
local sc41  = mk(41)   -- dup
local sc90  = mk(90)   -- dup2
local sc92  = mk(92)   -- fcntl
local sc477 = mk(477)

local pid = N(sc20())
print("pid=" .. pid)

-- ============================================================
-- TEST 1: dup(1) — already known to fail
-- ============================================================
local ok1, r1 = pcall(function() return sc41(uint64(1)) end)
print(string.format("dup(1): ok=%s rv=%d", tostring(ok1), ok1 and N(r1) or -999))

-- ============================================================
-- TEST 2: dup2(1, 100) — copy fd 1 to fd 100
-- ============================================================
local ok2, r2 = pcall(function() return sc90(uint64(1), uint64(100)) end)
local rv2 = ok2 and N(r2) or -999
print(string.format("dup2(1,100): ok=%s rv=%d", tostring(ok2), rv2))

-- ============================================================
-- TEST 3: fcntl(1, F_DUPFD=0, 50) — dup fd 1 to >=50
-- ============================================================
local ok3, r3 = pcall(function() return sc92(uint64(1), uint64(0), uint64(50)) end)
local rv3 = ok3 and N(r3) or -999
print(string.format("fcntl(1,F_DUPFD,50): ok=%s rv=%d", tostring(ok3), rv3))

-- ============================================================
-- TEST 4: If dup2 worked, test redirect cycle
-- ============================================================
if rv2 == 100 or rv2 == 0 then
    print("")
    print("--- redirect test ---")
    io.flush()

    -- fd 100 should now be a copy of fd 1's output
    -- Write to fd 100 to verify
    local sc4 = mk(4)  -- write
    local msg = memory.alloc(32)
    wd(msg, 0x54534554)     -- "TEST"
    wd(msg + 4, 0x0A303031) -- "100\n"
    pcall(function() sc4(uint64(100), uint64(msg), uint64(8)) end)

    -- Close fd 1
    pcall(function() sc6(uint64(1)) end)

    -- Try writing to fd 1 (should fail with EBADF)
    local ok_w, rv_w = pcall(function()
        return sc4(uint64(1), uint64(msg), uint64(4))
    end)
    -- Can't print here — fd 1 is closed!

    -- Restore fd 1 from fd 100
    pcall(function() sc90(uint64(100), uint64(1)) end)

    -- Now print should work again
    print("fd1 restored!")
    local wrote_to_closed = ok_w and N(rv_w) or -999
    print(string.format("write_to_closed_fd1=%d", wrote_to_closed))
    io.flush()
else
    print("dup2 failed, skip redirect test")
end

-- ============================================================
-- TEST 5: If redirect works, test with a mini child thread
-- ============================================================
if rv2 == 100 or rv2 == 0 then
    print("")
    print("--- child with redirect ---")
    io.flush()

    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    local sc593 = mk(593)
    pcall(function() sc593(Z, info) end)
    local eb_lo = rd(info + 0x108) or 0
    local eb_hi = rd(info + 0x10C) or 0
    if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
    if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
    local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

    local bare_ret    = eboot + uint64(0x42)
    local pop_rax_ret = eboot + uint64(0x992)
    local pop_rdi_ret = eboot + uint64(0xC9DFE)
    local mov_mem_rdi_rax = eboot + uint64(0x92C67)

    local shared = memory.alloc(0x20)
    zero(shared, 0x20)

    local ss = 0x4000
    local sc455 = mk(455)
    local ok_sb, stk = pcall(function()
        return sc477(Z, uint64(ss), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)

    local stk_n = N(stk)
    local rsp_n = (stk_n + ss) - ((stk_n + ss) % 16) - 8
    local rsp = stk + uint64(rsp_n - stk_n)

    local ci = 0
    local function wc(v) wq(rsp + uint64(ci*8), v); ci=ci+1 end

    wc(pop_rax_ret)
    wc(uint64("0xCAFE1234"))
    wc(pop_rdi_ret)
    wc(shared)
    wc(mov_mem_rdi_rax)
    for i = 1, 16 do wc(bare_ret) end

    local pa = memory.alloc(0x40)
    zero(pa, 0x40)
    wq(pa, bare_ret)
    wq(pa + 0x10, uint64(stk))
    wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8)
    wq(pa + 0x30, uint64(tid))

    -- REDIRECT: save fd 1, close, spawn, wait, restore
    pcall(function() sc90(uint64(1), uint64(100)) end)
    pcall(function() sc6(uint64(1)) end)

    -- Spawn child (77 output goes nowhere!)
    pcall(function() sc455(uint64(pa), uint64(0x38)) end)

    -- Wait
    for w = 1, 2000 do
        for j = 1, 200 do local x = j * j end
        local s = rb(shared) or 0
        if s == 0xCAFE1234 then break end
    end

    -- Restore fd 1
    pcall(function() sc90(uint64(100), uint64(1)) end)
    pcall(function() sc6(uint64(100)) end)

    -- Print result
    local val = rb(shared) or 0
    print(string.format("child sentinel=0x%X", val))

    local sc73 = mk(73)
    pcall(function() sc73(stk, uint64(ss)) end)
end

io.flush()
print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 562f DONE ===")
