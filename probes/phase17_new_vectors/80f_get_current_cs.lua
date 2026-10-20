-- CRASH_CLASS: LOW
-- PROBE 80f: Get current thread's CS/SS values
--
-- Context: We need to know what CS/SS the PS5 kernel uses for user-mode
-- threads. Standard FreeBSD is CS=0x43/SS=0x3B, but Sony may differ.
-- Use getcontext (sigreturn setup) or sysarch to read the current values.
--
-- Strategy:
--   A: Use sysarch GET_FSBASE(128)/GET_GSBASE(130) — already tested, but
--      we can try reading CS directly via sysarch
--   B: Allocate a ucontext and use getcontext(SYS_getcontext=421) to fill it
--   C: Read CS/SS from the sigreturn context if available
--   D: Try sigaltstack + signal to capture context in signal handler

print("=== PROBE 80f: GET CURRENT THREAD CS/SS ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. tostring(syscall.sc_getpid():tonumber()))

-- ============================================================
-- A: getcontext (syscall 421)
-- ============================================================
print("")
print("=== A: getcontext(421) ===")

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)

-- Fill with sentinel so we can see what gets written
for off = 0, 0x5FC, 4 do
    wd(ctx + off, 0xAAAAAAAA)
end

local sc_getctx = make_syscall(421)
local ok_a, rv_a = pcall(function()
    return sc_getctx(uint64(ctx))
end)
print("  rv=" .. tostring(rv_a) .. " ok=" .. tostring(ok_a))

if ok_a then
    -- Dump the interesting mcontext region
    -- ctx+0x90 = mc_rip, ctx+0x98 = mc_cs, ctx+0xA0 = mc_rflags
    -- ctx+0xA8 = mc_rsp, ctx+0xB0 = mc_ss
    print("")
    print("  Context dump (ctx-relative, key offsets):")
    print("  +0x0D0 (uc_flags?): " .. q(rq(ctx + 0x0D0)))
    print("  +0x090 (mc_rip):    " .. q(rq(ctx + 0x90)))
    print("  +0x098 (mc_cs):     " .. q(rq(ctx + 0x98)))
    print("  +0x0A0 (mc_rflags): " .. q(rq(ctx + 0xA0)))
    print("  +0x0A8 (mc_rsp):    " .. q(rq(ctx + 0xA8)))
    print("  +0x0B0 (mc_ss):     " .. q(rq(ctx + 0xB0)))
    print("  +0x108 (mc_len):    " .. q(rq(ctx + 0x108)))
    print("  +0x110 (mc_flags):  " .. q(rq(ctx + 0x110)))

    -- Also dump registers
    print("")
    print("  Registers:")
    print("  +0x058 (mc_rdi):    " .. q(rq(ctx + 0x58)))
    print("  +0x060 (mc_rsi):    " .. q(rq(ctx + 0x60)))
    print("  +0x068 (mc_rdx):    " .. q(rq(ctx + 0x68)))
    print("  +0x070 (mc_rbx):    " .. q(rq(ctx + 0x70)))
    print("  +0x078 (mc_rcx):    " .. q(rq(ctx + 0x78)))
    print("  +0x080 (mc_rax):    " .. q(rq(ctx + 0x80)))
    print("  +0x088 (mc_rbp):    " .. q(rq(ctx + 0x88)))

    -- Full hex dump of the mcontext area
    print("")
    print("  Full dump +0x80 to +0x120:")
    for off = 0x80, 0x120, 8 do
        print("    +" .. string.format("%03X", off) .. ": " .. q(rq(ctx + off)))
    end

    -- Check if CS is a recognizable value
    local cs_val = rd(ctx + 0x98)
    local ss_val = rd(ctx + 0xB0)
    if cs_val then
        print("")
        print("  *** CS = 0x" .. string.format("%04X", cs_val) .. " ***")
        print("  *** SS = 0x" .. string.format("%04X", ss_val or 0) .. " ***")
        print("  CS RPL = " .. (cs_val % 4))
        print("  CS GDT index = " .. math.floor(cs_val / 8))
    end
end

-- ============================================================
-- B: Also try sysarch(165) if getcontext failed
-- ============================================================
if not ok_a or to_num(rv_a) ~= 0 then
    print("")
    print("=== B: sysarch(165) ===")
    local sc_sysarch = make_syscall(165)

    -- Try various commands to read segment registers
    for _, cmd in ipairs({128, 129, 130, 131, 132, 133}) do
        local out = memory.alloc(16)
        zero(out, 16)
        local ok_b, rv_b = pcall(function()
            return sc_sysarch(uint64(cmd), uint64(out))
        end)
        print("  cmd=" .. cmd .. " rv=" .. tostring(rv_b) .. " out=" .. q(rq(out)))
    end
end

-- ============================================================
-- C: sysctl kern.proc (check our thread state)
-- ============================================================
print("")
print("=== C: Process info check ===")
local pid = syscall.sc_getpid():tonumber()

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
wd(mib, 1)       -- CTL_KERN
wd(mib + 4, 14)  -- KERN_PROC
wd(mib + 8, 1)   -- KERN_PROC_PID
wd(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
wq(oldlenp, uint64(0x800))
zero(outbuf, 0x800)

local ok_c, rv_c = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
print("  sysctl rv=" .. tostring(rv_c))

if ok_c and to_num(rv_c) == 0 then
    local outlen = rd(oldlenp)
    print("  output length: " .. tostring(outlen))
end

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] canary: " .. tostring(alive))
print("=== PROBE 80f COMPLETE ===")
