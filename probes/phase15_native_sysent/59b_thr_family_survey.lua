-- CRASH_CLASS: MODERATE
-- PROBE 59b: Survey the thr_* syscall family (430-635)
--
-- Context: ATTACK_SURFACE.md documents only thr_new(455) as BLOCKED and
-- thr_self(432) as WORKING. The sysent has 16 thr_* entries; 14 are
-- undocumented. PR #21 (ng643) decoded thr_create(430) and showed it was
-- never properly tested — probe 54b called it with arg0=NULL (instant
-- copyin fault) and mislabeled it "thr_new."
--
-- This probe surveys the SAFE and MODERATE thr_* calls to build a
-- reachability map. It deliberately EXCLUDES:
--   thr_create (430) — probe 58e covers this with a decoded context
--   thr_exit   (431) — terminates the calling thread; lethal by design
--   thr_new    (455) — already confirmed blocked (probe 27)
--
-- What this probe measures, in increasing order of risk:
--   A thr_self(432)                 control — known to return tid
--   B thr_get_name(616)             read thread name into buffer
--   C thr_set_name(464)             write thread name (reversible)
--   D thr_kill(433, sig=0)          null signal to self — permission check only
--   E thr_kill2(481, pid, tid, 0)   cross-process null signal
--   F thr_suspend(442)              with immediate timeout (0 nsec)
--   G thr_wake(443)                 wake self (no-op if not suspended)
--   H thr_get_ucontext(634)         read ucontext for current thread
--   I thr_set_ucontext(635)         NULL arg — reachability only
--   J thr_suspend_ucontext(632)     NULL arg — reachability only
--   K thr_resume_ucontext(633)      NULL arg — reachability only
--
-- PREPARED — NOT RUN. Offline, read-only, no console contact.

print("=== PROBE 59b: THR_* FAMILY SURVEY ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- Canary
local sc_getpid = make_syscall(20)
local our_pid = 0
pcall(function() our_pid = to_num(sc_getpid()) end)
print("PID: " .. our_pid)
print("")

-- Syscall handles
local sc_thr_self             = make_syscall(432)
local sc_thr_kill             = make_syscall(433)
local sc_thr_suspend          = make_syscall(442)
local sc_thr_wake             = make_syscall(443)
local sc_thr_set_name         = make_syscall(464)
local sc_thr_kill2            = make_syscall(481)
local sc_thr_get_name         = make_syscall(616)
local sc_thr_suspend_ucontext = make_syscall(632)
local sc_thr_resume_ucontext  = make_syscall(633)
local sc_thr_get_ucontext     = make_syscall(634)
local sc_thr_set_ucontext     = make_syscall(635)

-- Shared buffers
local tid_buf  = memory.alloc(16)    -- 8 bytes for tid output
local name_buf = memory.alloc(256)   -- thread name (MAXCOMLEN=19 + NUL)
local ctx_buf  = memory.alloc(0x600) -- ucontext_t

-- Track our tid for later sections
local our_tid = 0

--------------------------------------------------------------------
-- SECTION A: thr_self(432) — control, known to work
--------------------------------------------------------------------
print("=== SECTION A: thr_self(432) — control ===")
safe_wq(tid_buf, uint64(0))

print("[BEFORE] A: thr_self(tid_buf)")
local ok_a, ret_a = pcall(function()
    return sc_thr_self(uint64(tid_buf))
end)
if ok_a then
    local rv = to_num(ret_a)
    local tid = safe_rd(tid_buf) or 0
    our_tid = tid
    print(string.format("[RETURNED] A: rv=%d tid=%d", rv, tid))
    if rv == 0 and tid > 0 then
        print("  >>> thr_self WORKS — tid=" .. tid .. " <<<")
    elseif rv == 0 and tid == 0 then
        print("  >>> thr_self returned rv=0 but tid=0 (probe 27 pattern) <<<")
    else
        print("  >>> thr_self returned rv=" .. rv .. " <<<")
    end
else
    print("[RETURNED] A: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION B: thr_get_name(616) — read thread name
--------------------------------------------------------------------
print("=== SECTION B: thr_get_name(616) ===")
for i = 0, 63 do safe_wd(name_buf + i*4, 0) end

print("[BEFORE] B: thr_get_name(our_tid, name_buf, 256)")
local ok_b, ret_b = pcall(function()
    return sc_thr_get_name(uint64(our_tid), uint64(name_buf), uint64(256))
end)
if ok_b then
    local rv = to_num(ret_b)
    -- Read the name as bytes
    local name_str = ""
    for i = 0, 63 do
        local b = safe_rb(name_buf + i)
        if not b or b == 0 then break end
        name_str = name_str .. string.char(b)
    end
    print(string.format("[RETURNED] B: rv=%d name=\"%s\" (len=%d)", rv, name_str, #name_str))
    if rv == 0 then
        print("  >>> thr_get_name WORKS <<<")
    end
else
    print("[RETURNED] B: PCALL-FAIL")
end

-- Also try with tid=0 (meaning "current thread" on some FreeBSD versions)
for i = 0, 63 do safe_wd(name_buf + i*4, 0) end
print("[BEFORE] B2: thr_get_name(0, name_buf, 256)")
local ok_b2, ret_b2 = pcall(function()
    return sc_thr_get_name(uint64(0), uint64(name_buf), uint64(256))
end)
if ok_b2 then
    local rv = to_num(ret_b2)
    local name_str = ""
    for i = 0, 63 do
        local b = safe_rb(name_buf + i)
        if not b or b == 0 then break end
        name_str = name_str .. string.char(b)
    end
    print(string.format("[RETURNED] B2: rv=%d name=\"%s\"", rv, name_str))
else
    print("[RETURNED] B2: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION C: thr_set_name(464) — write thread name
--------------------------------------------------------------------
print("=== SECTION C: thr_set_name(464) ===")

-- Write a known name into the buffer
local test_name = "probe59b"
for i = 0, 63 do safe_wd(name_buf + i*4, 0) end
for i = 1, #test_name do
    pcall(function() memory.write_byte(name_buf + (i-1), string.byte(test_name, i)) end)
end
pcall(function() memory.write_byte(name_buf + #test_name, 0) end)

print("[BEFORE] C: thr_set_name(our_tid, \"probe59b\")")
local ok_c, ret_c = pcall(function()
    return sc_thr_set_name(uint64(our_tid), uint64(name_buf))
end)
if ok_c then
    local rv = to_num(ret_c)
    print(string.format("[RETURNED] C: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_set_name WORKS <<<")
        -- Verify via thr_get_name
        local verify_buf = memory.alloc(256)
        for i = 0, 63 do safe_wd(verify_buf + i*4, 0) end
        local ok_v, ret_v = pcall(function()
            return sc_thr_get_name(uint64(our_tid), uint64(verify_buf), uint64(256))
        end)
        if ok_v then
            local vname = ""
            for i = 0, 63 do
                local b = safe_rb(verify_buf + i)
                if not b or b == 0 then break end
                vname = vname .. string.char(b)
            end
            print(string.format("  verify readback: \"%s\"", vname))
        end
    end
else
    print("[RETURNED] C: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION D: thr_kill(433, sig=0) — null signal to self
--------------------------------------------------------------------
print("=== SECTION D: thr_kill(433) — null signal ===")

-- thr_kill(long id, int sig)
-- sig=0 is a null signal: checks permission without delivering anything
print("[BEFORE] D: thr_kill(our_tid, 0)")
local ok_d, ret_d = pcall(function()
    return sc_thr_kill(uint64(our_tid), uint64(0))
end)
if ok_d then
    local rv = to_num(ret_d)
    print(string.format("[RETURNED] D: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_kill(sig=0) WORKS — thread exists and is signalable <<<")
    end
else
    print("[RETURNED] D: PCALL-FAIL")
end

-- Also try with tid=0
print("[BEFORE] D2: thr_kill(0, 0)")
local ok_d2, ret_d2 = pcall(function()
    return sc_thr_kill(uint64(0), uint64(0))
end)
if ok_d2 then
    print(string.format("[RETURNED] D2: rv=%d", to_num(ret_d2)))
else
    print("[RETURNED] D2: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION E: thr_kill2(481, pid, tid, sig=0) — cross-process null signal
--------------------------------------------------------------------
print("=== SECTION E: thr_kill2(481) — cross-process null signal ===")

-- thr_kill2(pid_t pid, long id, int sig)
-- CVE-2026-45256 is about thr_kill2 ignoring p_cansignal result
print("[BEFORE] E: thr_kill2(our_pid, our_tid, 0)")
local ok_e, ret_e = pcall(function()
    return sc_thr_kill2(uint64(our_pid), uint64(our_tid), uint64(0))
end)
if ok_e then
    local rv = to_num(ret_e)
    print(string.format("[RETURNED] E: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_kill2(sig=0) WORKS <<<")
    end
else
    print("[RETURNED] E: PCALL-FAIL")
end

-- Try targeting pid=1 (init) — should fail permission check unless CVE-2026-45256 applies
print("[BEFORE] E2: thr_kill2(1, 1, 0)")
local ok_e2, ret_e2 = pcall(function()
    return sc_thr_kill2(uint64(1), uint64(1), uint64(0))
end)
if ok_e2 then
    local rv = to_num(ret_e2)
    print(string.format("[RETURNED] E2: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_kill2(pid=1) ACCEPTED — CVE-2026-45256 may apply <<<")
    else
        print("  >>> thr_kill2(pid=1) REFUSED (rv=" .. rv .. ") — permission check active <<<")
    end
else
    print("[RETURNED] E2: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- Canary mid-probe
--------------------------------------------------------------------
local alive1 = false
pcall(function()
    local p = to_num(sc_getpid())
    if p == our_pid then alive1 = true end
end)
print("Mid-probe canary: " .. (alive1 and "ALIVE" or "DEAD"))
if not alive1 then
    print("=== PROBE 59b ABORTED (process died) ===")
    return
end
print("")

--------------------------------------------------------------------
-- SECTION F: thr_suspend(442) — with zero timeout
--------------------------------------------------------------------
print("=== SECTION F: thr_suspend(442) — zero timeout ===")

-- thr_suspend(const struct timespec *timeout)
-- With timeout={0,0}: immediate return if no wake pending
local ts_buf = memory.alloc(16)
safe_wq(ts_buf, uint64(0))       -- tv_sec = 0
safe_wq(ts_buf + 8, uint64(0))   -- tv_nsec = 0

print("[BEFORE] F: thr_suspend(&{0,0})")
local ok_f, ret_f = pcall(function()
    return sc_thr_suspend(uint64(ts_buf))
end)
if ok_f then
    local rv = to_num(ret_f)
    print(string.format("[RETURNED] F: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_suspend(zero timeout) WORKS <<<")
    end
else
    print("[RETURNED] F: PCALL-FAIL")
end

-- Also try with NULL (no timeout — but this would block forever if it works,
-- so we do NOT test NULL. Documenting why.)
print("  NOTE: thr_suspend(NULL) NOT TESTED — would block indefinitely")
print("")

--------------------------------------------------------------------
-- SECTION G: thr_wake(443) — wake self
--------------------------------------------------------------------
print("=== SECTION G: thr_wake(443) ===")

-- thr_wake(long id)
-- Waking a non-suspended thread is a no-op (or sets a pending wake flag)
print("[BEFORE] G: thr_wake(our_tid)")
local ok_g, ret_g = pcall(function()
    return sc_thr_wake(uint64(our_tid))
end)
if ok_g then
    local rv = to_num(ret_g)
    print(string.format("[RETURNED] G: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_wake WORKS <<<")
    end
else
    print("[RETURNED] G: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION H: thr_get_ucontext(634) — read ucontext
--------------------------------------------------------------------
print("=== SECTION H: thr_get_ucontext(634) ===")
for i = 0, 0x17F do safe_wd(ctx_buf + i*4, 0) end

-- thr_get_ucontext(struct thread *td, struct ucontext *ucp)
-- From userland: thr_get_ucontext(ucontext_t *ucp) — single arg
print("[BEFORE] H: thr_get_ucontext(ctx_buf)")
local ok_h, ret_h = pcall(function()
    return sc_thr_get_ucontext(uint64(ctx_buf))
end)
if ok_h then
    local rv = to_num(ret_h)
    print(string.format("[RETURNED] H: rv=%d", rv))
    if rv == 0 then
        print("  >>> thr_get_ucontext WORKS <<<")
        -- Dump the first 128 bytes to see the structure
        print("  First 128 bytes of ucontext:")
        for row = 0, 0x70, 0x10 do
            local vals = {}
            for col = 0, 0xC, 4 do
                vals[#vals+1] = string.format("%08X", safe_rd(ctx_buf + row + col) or 0)
            end
            print(string.format("    +%03X: %s", row, table.concat(vals, " ")))
        end
        -- Check magic field at +0x108 (should be 0x480 per PR #21 decode)
        local magic = safe_rd(ctx_buf + 0x108) or 0
        print(string.format("  ctx+0x108 (magic): 0x%08X (expected 0x480)", magic))
        -- Check type field at +0x110
        local type_val = safe_rd(ctx_buf + 0x110) or 0
        print(string.format("  ctx+0x110 (type):  0x%08X", type_val))
    end
else
    print("[RETURNED] H: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION I: thr_set_ucontext(635) — NULL arg, reachability only
--------------------------------------------------------------------
print("=== SECTION I: thr_set_ucontext(635) — NULL reachability ===")
print("[BEFORE] I: thr_set_ucontext(0)")
local ok_i, ret_i = pcall(function()
    return sc_thr_set_ucontext(uint64(0))
end)
if ok_i then
    print(string.format("[RETURNED] I: rv=%d", to_num(ret_i)))
else
    print("[RETURNED] I: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION J: thr_suspend_ucontext(632) — NULL arg, reachability only
--------------------------------------------------------------------
print("=== SECTION J: thr_suspend_ucontext(632) — NULL reachability ===")
print("[BEFORE] J: thr_suspend_ucontext(0)")
local ok_j, ret_j = pcall(function()
    return sc_thr_suspend_ucontext(uint64(0))
end)
if ok_j then
    print(string.format("[RETURNED] J: rv=%d", to_num(ret_j)))
else
    print("[RETURNED] J: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SECTION K: thr_resume_ucontext(633) — NULL arg, reachability only
--------------------------------------------------------------------
print("=== SECTION K: thr_resume_ucontext(633) — NULL reachability ===")
print("[BEFORE] K: thr_resume_ucontext(0)")
local ok_k, ret_k = pcall(function()
    return sc_thr_resume_ucontext(uint64(0))
end)
if ok_k then
    print(string.format("[RETURNED] K: rv=%d", to_num(ret_k)))
else
    print("[RETURNED] K: PCALL-FAIL")
end
print("")

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("=== SUMMARY ===")
print("  thr_create (430): NOT TESTED — see probe 58e")
print("  thr_exit   (431): NOT TESTED — LETHAL (terminates thread)")
print("  thr_self   (432): " .. (ok_a and "rv=" .. to_num(ret_a) or "PCALL-FAIL"))
print("  thr_kill   (433): " .. (ok_d and "rv=" .. to_num(ret_d) or "PCALL-FAIL"))
print("  thr_suspend(442): " .. (ok_f and "rv=" .. to_num(ret_f) or "PCALL-FAIL"))
print("  thr_wake   (443): " .. (ok_g and "rv=" .. to_num(ret_g) or "PCALL-FAIL"))
print("  thr_new    (455): NOT TESTED — confirmed blocked (probe 27)")
print("  thr_set_name(464): " .. (ok_c and "rv=" .. to_num(ret_c) or "PCALL-FAIL"))
print("  thr_kill2  (481): " .. (ok_e and "rv=" .. to_num(ret_e) or "PCALL-FAIL"))
print("  thr_get_name(616): " .. (ok_b and "rv=" .. to_num(ret_b) or "PCALL-FAIL"))
print("  thr_suspend_ucontext(632): " .. (ok_j and "rv=" .. to_num(ret_j) or "PCALL-FAIL"))
print("  thr_resume_ucontext (633): " .. (ok_k and "rv=" .. to_num(ret_k) or "PCALL-FAIL"))
print("  thr_get_ucontext    (634): " .. (ok_h and "rv=" .. to_num(ret_h) or "PCALL-FAIL"))
print("  thr_set_ucontext    (635): " .. (ok_i and "rv=" .. to_num(ret_i) or "PCALL-FAIL"))
print("")

--------------------------------------------------------------------
-- FINAL CANARY
--------------------------------------------------------------------
local alive2 = false
pcall(function()
    local p = to_num(sc_getpid())
    if p == our_pid then alive2 = true end
end)
print("Final canary: " .. (alive2 and "ALIVE (pid=" .. our_pid .. ")" or "DEAD"))
print("")
print("=== PROBE 59b COMPLETE ===")
