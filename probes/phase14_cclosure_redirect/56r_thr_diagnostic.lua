-- CRASH_CLASS: MODERATE
-- PROBE 56r: thr_create diagnostic — understand the -1 return
--
-- Context: 56q mc_len sweep had zero effect. All thr_create calls return
-- the same value regardless of mc_len. Need to understand:
-- 1. What's the ACTUAL return value (raw bytes)?
-- 2. Can we get errno?
-- 3. Does native.fcall_with_rax + gen_fcall_chain work for thr_create?
-- 4. Is there a Sony-specific sandbox block on thread creation?

print("=== PROBE 56r: THR_CREATE DIAGNOSTIC ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Get eboot base + ret gadget
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)

local ret_gadget = nil
if eboot_lo and eboot_hi then
    local ok_sc, scan_data = pcall(function()
        return native.read_buffer(uint64(string.format("0x%X%08X", eboot_hi, eboot_lo)), 4096)
    end)
    if ok_sc and scan_data then
        for i = 1, #scan_data do
            if scan_data:byte(i) == 0xC3 then
                ret_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                break
            end
        end
    end
end
print("ret_gadget=" .. fmt_addr(ret_gadget))

-- Allocate stack
local sc_mmap = make_syscall(477)
local ok_stk, new_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stk_h, stk_l = get_hi_lo(new_stack)

-- ============================================================
-- TEST 1: Raw return value analysis
-- ============================================================
print("")
print("--- TEST 1: RAW RETURN VALUE ---")

local uctx = memory.alloc(0x500)
for i = 0, 0x4FF, 4 do safe_wd(uctx + i, 0) end
local mc = to_num(uctx) + 0x10

local rg_h, rg_l = get_hi_lo(ret_gadget)
safe_wd(mc + 0xB0, rg_l)
safe_wd(mc + 0xB4, rg_h)
safe_wd(mc + 0xB8, 0x43)
safe_wd(mc + 0xC0, 0x202)
local sp_l = stk_l + 0x10000 - 0x100
safe_wd(mc + 0xC8, sp_l)
safe_wd(mc + 0xCC, stk_h)
safe_wd(mc + 0xD0, 0x3B)
safe_wd(mc + 0x48, sp_l)
safe_wd(mc + 0x4C, stk_h)

local tid_out = memory.alloc(16)
safe_wq(tid_out, uint64(0))

local sc_thr = make_syscall(430)
local ok1, ret1 = pcall(function()
    return sc_thr(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
end)

print("pcall ok=" .. tostring(ok1))
print("type(ret)=" .. type(ret1))
print("tostring(ret)=" .. tostring(ret1))

if type(ret1) == "table" then
    print("ret is table, keys:")
    for k, v in pairs(ret1) do
        print("  " .. tostring(k) .. "=" .. tostring(v))
    end
    if ret1.h then print("  .h=" .. string.format("0x%X", ret1.h)) end
    if ret1.l then print("  .l=" .. string.format("0x%X", ret1.l)) end
    if ret1.tonumber then print("  :tonumber()=" .. tostring(ret1:tonumber())) end
end

local rh, rl = get_hi_lo(ret1)
print(string.format("get_hi_lo: h=0x%X l=0x%X", rh, rl))

local tid_val = safe_rq(tid_out)
print("TID=" .. fmt_addr(tid_val) .. " (" .. to_num(tid_val) .. ")")

-- ============================================================
-- TEST 2: fcall_with_rax for direct syscall
-- ============================================================
print("")
print("--- TEST 2: FCALL_WITH_RAX SYSCALL 430 ---")

local stub = syscall.pipe.fn_addr
print("stub=" .. fmt_addr(stub))

-- First verify fcall_with_rax works
local ok_gp, ret_gp = pcall(function() return native.fcall_with_rax(stub, 20) end)
print("getpid: ok=" .. tostring(ok_gp) .. " ret=" .. tostring(ret_gp))

-- Build fresh ucontext
local uctx2 = memory.alloc(0x500)
for i = 0, 0x4FF, 4 do safe_wd(uctx2 + i, 0) end
local mc2 = to_num(uctx2) + 0x10

safe_wd(mc2 + 0xB0, rg_l)
safe_wd(mc2 + 0xB4, rg_h)
safe_wd(mc2 + 0xB8, 0x43)
safe_wd(mc2 + 0xC0, 0x202)
safe_wd(mc2 + 0xC8, sp_l)
safe_wd(mc2 + 0xCC, stk_h)
safe_wd(mc2 + 0xD0, 0x3B)
safe_wd(mc2 + 0x48, sp_l)
safe_wd(mc2 + 0x4C, stk_h)

local tid_out2 = memory.alloc(16)
safe_wq(tid_out2, uint64(0))

-- Call thr_create via fcall_with_rax (syscall 430)
-- Args: rdi=ctx, rsi=id, rdx=flags
local ok2, ret2 = pcall(function()
    return native.fcall_with_rax(stub, 430, to_num(uctx2), to_num(tid_out2), 0)
end)
print("thr_create via fcall: ok=" .. tostring(ok2))
if ok2 then
    print("  ret=" .. tostring(ret2))
    print("  type=" .. type(ret2))
    if type(ret2) == "number" then
        print(string.format("  ret_hex=0x%X", ret2))
    end
end
local tid2 = to_num(safe_rq(tid_out2))
print("  TID=" .. tid2)

-- ============================================================
-- TEST 3: gen_fcall_chain approach
-- ============================================================
print("")
print("--- TEST 3: GEN_FCALL_CHAIN 430 ---")

local ok_gc, chain = pcall(function()
    return native.gen_fcall_chain(stub, 430)
end)
print("gen_fcall_chain: ok=" .. tostring(ok_gc))
if ok_gc and chain then
    print("  type=" .. type(chain))
    if type(chain) == "table" then
        for k, v in pairs(chain) do
            if type(v) ~= "table" and type(v) ~= "function" then
                print("  " .. tostring(k) .. "=" .. tostring(v))
            elseif type(v) == "table" then
                print("  " .. tostring(k) .. "=[table]")
            end
        end
    end
end

-- ============================================================
-- TEST 4: Check for Sony sandbox — try thr_self first
-- ============================================================
print("")
print("--- TEST 4: THREAD SYSCALLS ---")

-- thr_self(432) — should work since we're a thread
local sc_thr_self = make_syscall(432)
local self_buf = memory.alloc(16)
safe_wq(self_buf, uint64(0))
local ok_ts, ret_ts = pcall(function()
    return sc_thr_self(uint64(to_num(self_buf)))
end)
print("thr_self: ok=" .. tostring(ok_ts) .. " ret=" .. tostring(ret_ts))
print("  self_tid=" .. to_num(safe_rq(self_buf)))

-- thr_set_name(464) — see if we can set our own thread name
local sc_name = make_syscall(464)
local name_buf = memory.alloc(32)
safe_wd(name_buf, 0x74736574)  -- "test"
safe_wd(name_buf + 4, 0)
local ok_tn, ret_tn = pcall(function()
    return sc_name(uint64(to_num(safe_rq(self_buf))), uint64(to_num(name_buf)))
end)
print("thr_set_name: ok=" .. tostring(ok_tn) .. " ret=" .. tostring(ret_tn))

-- ============================================================
-- TEST 5: Try with FULLY populated mcontext
-- ============================================================
print("")
print("--- TEST 5: FULL MCONTEXT POPULATION ---")

local uctx3 = memory.alloc(0x800)
for i = 0, 0x7FF, 4 do safe_wd(uctx3 + i, 0) end
local mc3 = to_num(uctx3) + 0x10

-- All GP registers zeroed is fine, except these:
safe_wd(mc3 + 0x38, 0)  -- RAX = 0
safe_wd(mc3 + 0x48, sp_l)  -- RBP
safe_wd(mc3 + 0x4C, stk_h)

-- Segment registers
safe_wd(mc3 + 0x88, 0)    -- mc_fs = 0 (uses FSBASE MSR)
safe_wd(mc3 + 0x8C, 0)    -- mc_gs = 0
safe_wd(mc3 + 0x98, 0x1)  -- mc_flags = MC_HASSEGS
safe_wd(mc3 + 0xA0, 0x3B) -- mc_es
safe_wd(mc3 + 0xA4, 0x3B) -- mc_ds

-- RIP, CS, RFLAGS, RSP, SS
safe_wd(mc3 + 0xB0, rg_l)   -- mc_rip
safe_wd(mc3 + 0xB4, rg_h)
safe_wd(mc3 + 0xB8, 0x43)   -- mc_cs
safe_wd(mc3 + 0xC0, 0x202)  -- mc_rflags
safe_wd(mc3 + 0xC8, sp_l)   -- mc_rsp
safe_wd(mc3 + 0xCC, stk_h)
safe_wd(mc3 + 0xD0, 0x3B)   -- mc_ss

-- Try EVERY possible mc_len offset from +0xC8 to +0xF0
-- with a common value like 0x340
for off = 0xC8, 0xF0, 8 do
    safe_wq(uctx3 + 0x10 + off, uint64(0))
end
-- Set mc_len at +0xD8 to a common value
safe_wd(mc3 + 0xD8, 0x340)

-- FPU state
safe_wd(mc3 + 0xE0, 0x10002)  -- mc_fpformat = _MC_FPFMT_XMM
safe_wd(mc3 + 0xE8, 0x20000)  -- mc_ownedfp = _MC_FPOWNED_NONE

-- uc_flags at the end of ucontext (after mcontext + link + stack)
-- Try setting _UC_CPU = 0x04
-- ucontext starts with uc_sigmask (16 bytes), then mcontext
-- uc_flags is AFTER mcontext, link, stack
-- On FreeBSD: sizeof(mcontext_t) + 8 (link) + 24 (stack) + 4 (flags)
-- If mcontext is ~0x340, then uc_flags is at uctx + 0x10 + 0x340 + 8 + 24
-- = uctx + 0x37C
-- But this depends on the exact mcontext size...

local tid_out3 = memory.alloc(16)
safe_wq(tid_out3, uint64(0))

-- Try with fcall_with_rax for cleaner error info
local ok5, ret5 = pcall(function()
    return native.fcall_with_rax(stub, 430, to_num(uctx3), to_num(tid_out3), 0)
end)
print("fcall thr_create: ok=" .. tostring(ok5))
if ok5 then
    print("  ret=" .. tostring(ret5))
    if type(ret5) == "number" then
        print(string.format("  ret=0x%X (decimal %d)", ret5, ret5))
        -- On FreeBSD, if carry flag is set, rax = errno
        -- Common errors: EINVAL=22, EPERM=1, EFAULT=14, EAGAIN=35
        if ret5 == 22 then print("  >>> EINVAL — invalid argument!")
        elseif ret5 == 1 then print("  >>> EPERM — permission denied!")
        elseif ret5 == 14 then print("  >>> EFAULT — bad address!")
        elseif ret5 == 35 then print("  >>> EAGAIN — resource busy!")
        elseif ret5 == 78 then print("  >>> ENOSYS — not implemented!")
        elseif ret5 == 13 then print("  >>> EACCES — access denied!")
        elseif ret5 == 0 then print("  >>> SUCCESS!")
        end
    end
end
local tid3 = to_num(safe_rq(tid_out3))
print("  TID=" .. tid3)

-- ============================================================
-- TEST 6: Check if the thread was actually created + died
-- ============================================================
print("")
print("--- TEST 6: THREAD EXISTENCE CHECK ---")

local sc_thr_kill = make_syscall(433)
-- Check all TIDs we got
for _, tid in ipairs({to_num(safe_rq(tid_out)), tid2, tid3}) do
    if tid > 0 then
        local ok_k, ret_k = pcall(function()
            return sc_thr_kill(uint64(tid), uint64(0))
        end)
        print(string.format("  thr_kill(%d, 0): ok=%s ret=%s", tid, tostring(ok_k), tostring(ret_k)))
    end
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56r COMPLETE ===")
