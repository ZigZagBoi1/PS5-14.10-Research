-- CRASH_CLASS: HIGH
-- PROBE 43p: AIO via make_syscall — test if AIO sandbox kill is in resolve() or kernel
--
-- Context:
-- Probes 19-19g confirmed all aio_* syscalls kill the process. BUT those probes used
-- syscall.resolve(), not make_syscall(). Probe 41w proved sysctl works through
-- make_syscall() while resolve() reports it blocked — the sandbox filter is Lua-side.
--
-- If AIO syscalls survive via make_syscall(), the entire AIO subsystem opens up and
-- race conditions become possible (AIO is inherently async — no threading needed).
--
-- The Relapse exploit (fw 7.00-13.60) used aio_multi_wait UAF. That specific bug is
-- patched in 14.00, but the bug CLASS (AIO race conditions) is only dead if AIO
-- itself is dead at the kernel level.
--
-- Strategy: Test each AIO syscall individually, safest first (aio_error/cancel),
-- dangerous last (aio_read/write). Each is wrapped in pcall. If ANY survive,
-- the sandbox kill is resolve()-side only and AIO races are alive on 14.10.

print("=== PROBE 43p: AIO BYPASS VIA MAKE_SYSCALL ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- FreeBSD AIO syscall numbers
local AIO_SYSCALLS = {
    {num = 317, name = "aio_error",        desc = "Check AIO request status (safest)"},
    {num = 316, name = "aio_cancel",       desc = "Cancel AIO request"},
    {num = 314, name = "aio_return",       desc = "Return AIO completion status"},
    {num = 315, name = "aio_suspend",      desc = "Wait for AIO completion (may block)"},
    {num = 255, name = "aio_read",         desc = "Async read"},
    {num = 256, name = "aio_write",        desc = "Async write"},
    {num = 257, name = "lio_listio",       desc = "Batch AIO operations"},
    {num = 359, name = "aio_waitcomplete", desc = "Wait for any AIO completion"},
    {num = 465, name = "aio_fsync",        desc = "Async fsync"},
    {num = 543, name = "aio_mlock",        desc = "Async mlock"},
}

-- ============================================================
-- PHASE 1: Canary — verify make_syscall is working
-- ============================================================
print("--- PHASE 1: Canary (sysctl via make_syscall) ---")
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(8)
safe_wd(mib, 1)
safe_wd(mib + 4, 4)
local cbuf = memory.alloc(256)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 256)
local ok, ret = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(cbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
if ok then
    print("  Canary OK: sysctl ret=" .. tostring(to_num(ret)))
else
    print("  CANARY FAILED — aborting")
    print("=== PROBE ABORTED ===")
    return
end
print("")

-- ============================================================
-- PHASE 2: Test each AIO syscall with NULL arguments
-- ============================================================
print("--- PHASE 2: AIO Syscall Survival Test (NULL args) ---")
print("If process dies here, the LAST printed syscall is the killer.")
print("")

local survived = {}
local killed = {}

for i, aio in ipairs(AIO_SYSCALLS) do
    print(string.format("  [%d/%d] %s (syscall %d) — %s",
        i, #AIO_SYSCALLS, aio.name, aio.num, aio.desc))

    local sc = make_syscall(aio.num)
    local test_ok, test_ret = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if test_ok then
        local rv = to_num(test_ret)
        local rv_signed = rv
        if rv >= 0x80000000 then rv_signed = rv - 0x100000000 end
        print(string.format("    SURVIVED! ret=%d (0x%X)", rv_signed, rv))
        table.insert(survived, {name = aio.name, num = aio.num, ret = rv_signed})
    else
        print(string.format("    pcall failed: %s", tostring(test_ret)))
        table.insert(killed, {name = aio.name, num = aio.num, err = tostring(test_ret)})
    end

    -- Post-test canary
    local alive_ok = pcall(function() return memory.read_dword(mib) end)
    if not alive_ok then
        print("    !!! POST-TEST CANARY FAILED — memory corrupted !!!")
        break
    end
end

print("")
print(string.format("=== AIO RESULTS: %d survived, %d failed ===", #survived, #killed))
print("")

if #survived > 0 then
    print("*** AIO SYSCALLS ALIVE VIA MAKE_SYSCALL ***")
    for _, s in ipairs(survived) do
        print(string.format("  %s (%d): ret=%d", s.name, s.num, s.ret))
    end
    print("")
    print("!!! CRITICAL: AIO sandbox kill is in resolve(), NOT the kernel !!!")
    print("!!! Race conditions via AIO are possible on fw 14.10 !!!")
end

if #killed > 0 then
    print("AIO syscalls that failed:")
    for _, k in ipairs(killed) do
        print(string.format("  %s (%d): %s", k.name, k.num, k.err))
    end
end
print("")

-- ============================================================
-- PHASE 3: If any AIO survived, test with real file descriptors
-- ============================================================
if #survived > 0 then
    print("--- PHASE 3: AIO Deep Test (real arguments) ---")
    print("")

    -- Open /dev/null for safe I/O testing
    local sc_open = make_syscall(5)
    local devnull_path = memory.alloc(16)
    safe_wd(devnull_path, 0x7665642F)
    safe_wd(devnull_path + 4, 0x6C756E2F)
    safe_wd(devnull_path + 8, 0x0000006C)
    local devnull_ok, devnull_ret = pcall(function()
        return sc_open(uint64(devnull_path), uint64(2), uint64(0))  -- O_RDWR
    end)
    local test_fd = -1
    if devnull_ok then
        test_fd = to_num(devnull_ret)
        print("  /dev/null fd=" .. test_fd)
    else
        print("  /dev/null open failed, using fd=3")
        test_fd = 3
    end

    -- Build aiocb (FreeBSD struct aiocb, ~168 bytes on amd64)
    local aiocb = memory.alloc(256)
    for j = 0, 248, 4 do safe_wd(aiocb + j, 0) end

    local aio_data = memory.alloc(256)
    for j = 0, 248, 4 do safe_wd(aio_data + j, 0) end

    safe_wd(aiocb, test_fd)                        -- +0x00: aio_fildes
    safe_wq(aiocb + 0x08, uint64(0))               -- +0x08: aio_offset = 0
    safe_wq(aiocb + 0x10, uint64(aio_data))        -- +0x10: aio_buf
    safe_wq(aiocb + 0x18, uint64(64))              -- +0x18: aio_nbytes = 64
    -- +0x30: aio_sigevent = SIGEV_NONE (0, already zeroed)

    -- Test survived syscalls with real args
    local has_read = false
    local has_write = false

    for _, s in ipairs(survived) do
        repeat
            if s.name == "aio_error" then
                print("  aio_error(aiocb)...")
                local ok2, ret2 = pcall(function()
                    return make_syscall(317)(uint64(aiocb))
                end)
                if ok2 then
                    print("    ret=" .. to_num(ret2))
                else
                    print("    failed: " .. tostring(ret2))
                end

            elseif s.name == "aio_cancel" then
                print("  aio_cancel(fd, aiocb)...")
                local ok2, ret2 = pcall(function()
                    return make_syscall(316)(uint64(test_fd), uint64(aiocb))
                end)
                if ok2 then
                    -- AIO_CANCELED=1, AIO_NOTCANCELED=2, AIO_ALLDONE=3
                    local rv = to_num(ret2)
                    print("    ret=" .. rv .. " (1=CANCELED, 2=NOTCANCELED, 3=ALLDONE)")
                else
                    print("    failed: " .. tostring(ret2))
                end

            elseif s.name == "aio_return" then
                print("  aio_return(aiocb)...")
                local ok2, ret2 = pcall(function()
                    return make_syscall(314)(uint64(aiocb))
                end)
                if ok2 then
                    print("    ret=" .. to_num(ret2))
                else
                    print("    failed: " .. tostring(ret2))
                end

            elseif s.name == "aio_read" then
                has_read = true
                print("  !!! aio_read(aiocb) — ASYNC READ TEST !!!")
                local ok2, ret2 = pcall(function()
                    return make_syscall(255)(uint64(aiocb))
                end)
                if ok2 then
                    local rv = to_num(ret2)
                    print("    ret=" .. rv)
                    if rv == 0 then
                        print("    *** AIO_READ WORKS! Checking completion... ***")
                        -- Brief spin then check aio_error
                        local err_ok, err_ret = pcall(function()
                            return make_syscall(317)(uint64(aiocb))
                        end)
                        if err_ok then
                            local ev = to_num(err_ret)
                            -- EINPROGRESS=36 on FreeBSD
                            print("    aio_error=" .. ev .. (ev == 36 and " (EINPROGRESS)" or ev == 0 and " (COMPLETED)" or ""))
                        end
                        -- Check if data arrived
                        local d0 = safe_rd(aio_data)
                        local d1 = safe_rd(aio_data + 4)
                        print(string.format("    buffer: %08X %08X", d0 or 0, d1 or 0))
                    end
                else
                    print("    failed: " .. tostring(ret2))
                end

            elseif s.name == "aio_write" then
                has_write = true
                print("  !!! aio_write(aiocb) — ASYNC WRITE TEST !!!")
                safe_wd(aio_data, 0x41414141)
                safe_wd(aio_data + 4, 0x42424242)
                local ok2, ret2 = pcall(function()
                    return make_syscall(256)(uint64(aiocb))
                end)
                if ok2 then
                    local rv = to_num(ret2)
                    print("    ret=" .. rv)
                    if rv == 0 then
                        print("    *** AIO_WRITE WORKS! ***")
                    end
                else
                    print("    failed: " .. tostring(ret2))
                end

            elseif s.name == "aio_waitcomplete" then
                print("  aio_waitcomplete (with zero timeout to avoid block)...")
                -- Pass a zero timespec to avoid hanging
                local ts = memory.alloc(16)
                safe_wq(ts, uint64(0))      -- tv_sec = 0
                safe_wq(ts + 8, uint64(0))  -- tv_nsec = 0
                local aiocbp_out = memory.alloc(8)
                safe_wq(aiocbp_out, uint64(0))
                local ok2, ret2 = pcall(function()
                    return make_syscall(359)(uint64(aiocbp_out), uint64(ts))
                end)
                if ok2 then
                    print("    ret=" .. to_num(ret2))
                else
                    print("    failed: " .. tostring(ret2))
                end

            elseif s.name == "lio_listio" then
                print("  lio_listio(LIO_NOWAIT, [aiocb], 1, NULL)...")
                local aiocb_list = memory.alloc(16)
                safe_wq(aiocb_list, uint64(aiocb))
                -- LIO_NOWAIT=1, set opcode in aiocb
                safe_wd(aiocb + 0x68, 1)  -- aio_lio_opcode = LIO_READ
                local ok2, ret2 = pcall(function()
                    return make_syscall(257)(uint64(1), uint64(aiocb_list), uint64(1), uint64(0))
                end)
                if ok2 then
                    local rv = to_num(ret2)
                    print("    ret=" .. rv)
                    if rv == 0 then
                        print("    *** LIO_LISTIO WORKS! Batch AIO alive! ***")
                    end
                else
                    print("    failed: " .. tostring(ret2))
                end
            end
            break
        until true
    end

    -- If aio_read and aio_write both work, we have async I/O
    if has_read and has_write then
        print("")
        print("*** ASYNC I/O CONFIRMED — RACE CONDITIONS ARE POSSIBLE ***")
        print("Next: build read/write races on kernel objects")
    end
    print("")
end

-- ============================================================
-- PHASE 4: Hunt for Sony aio_multi_wait
-- ============================================================
print("--- PHASE 4: Sony aio_multi_wait Hunt ---")
print("Scanning Sony syscall ranges for AIO-style syscalls...")
print("")

local sony_candidates = {
    532, 533, 534, 535, 536, 537, 538, 539,
    620, 621, 622, 623, 624, 625, 626, 627, 628, 629,
    630, 631, 632, 633, 634, 635, 636, 637, 638, 639,
    640, 641, 642, 643, 644, 645, 646, 647, 648, 649,
    650, 651, 652, 653, 654, 655, 656, 657, 658, 659,
    660, 661, 662, 663, 664, 665, 666, 667, 668, 669,
    670, 671, 672, 673, 674, 675, 676, 677, 678, 679,
    680, 681, 682, 683, 684, 685, 686, 687, 688, 689,
    690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700,
}

local sony_live = {}
for _, snum in ipairs(sony_candidates) do
    local sc = make_syscall(snum)
    local ok2, ret2 = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv = to_num(ret2)
        -- -1 = 0xFFFFFFFF (not found), anything else is interesting
        if rv ~= 4294967295 and rv ~= 0xFFFFFFFF then
            print(string.format("  *** LIVE: syscall %d returned %d (0x%X) ***", snum, rv, rv))
            table.insert(sony_live, {num = snum, ret = rv})
        end
    end
    -- Canary check every 20 syscalls
    if snum % 20 == 0 then
        local alive = pcall(function() return memory.read_dword(mib) end)
        if not alive then
            print("  !!! CANARY DEAD at syscall " .. snum .. " !!!")
            break
        end
    end
end

if #sony_live > 0 then
    print("")
    print("Sony live syscalls found in extended range:")
    for _, s in ipairs(sony_live) do
        print(string.format("  syscall %d: ret=%d", s.num, s.ret))
    end
    print("These need deeper investigation with AIO-style arguments!")
else
    print("  No additional live Sony syscalls found in 532-700 range")
end
print("")

-- ============================================================
-- PHASE 5: Summary
-- ============================================================
print("=== SUMMARY ===")
print(string.format("Standard AIO syscalls tested: %d", #AIO_SYSCALLS))
print(string.format("  Survived via make_syscall: %d", #survived))
print(string.format("  Failed/crashed: %d", #killed))
print(string.format("Sony extended range scanned: %d syscalls", #sony_candidates))
print(string.format("  Live: %d", #sony_live))
print("")

if #survived > 0 then
    print("BREAKTHROUGH: AIO is alive via make_syscall!")
    print("The resolve() sandbox was the only thing blocking AIO.")
    print("Race conditions via async I/O are now possible on fw 14.10.")
    print("")
    print("Implications:")
    print("  - aio_read/write create kernel worker threads internally")
    print("  - Concurrent kernel operations without userland threading")
    print("  - TOCTOU races on file descriptors become exploitable")
    print("  - The Relapse bug CLASS (AIO races) lives even if the specific bug is patched")
else
    print("AIO sandbox kill is kernel-enforced, not just resolve().")
    print("AIO is confirmed dead at the kernel level on fw 14.10.")
    print("Race conditions require a different path (ktimer signals, async socket I/O).")
end
print("")
print("=== PROBE 43p COMPLETE ===")
