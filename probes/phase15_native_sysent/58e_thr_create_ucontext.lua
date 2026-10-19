-- CRASH_CLASS: RISKY
-- PROBE 58e: thr_create(430) with a readable, field-valid ucontext_t
--
-- Context: probe 54b Phase 2 called 430 with arg0 = NULL and recorded -1. That
-- row was mislabeled "thr_new" and never tested a context at all. The 13.60
-- handler body at RVA 0x437cf0 (sysent slot 0x265c10) begins with
-- copyin(arg0, stack, 0x500), so arg0 = NULL can only fault inside copyin.
-- No capture in this repo has ever passed a readable context to 430.
--
-- docs/THR_CREATE_430_CONTEXT.md decodes the 13.60 path. The entry copies 0x500
-- bytes from arg0, stores arg1 (the id out-pointer) at ctx+0x500 in its own
-- frame, and calls the worker shared with 455 at 0x437f30. That worker
-- allocates a thread and calls the ops entry 0x265fc8 -> 0x437d90, which
-- copyout()s the new thread id and tail-calls the machine-context consumer
-- 0xa0ac60(new_thread, ctx+0x40). The consumer rejects the context unless
-- (13.60, context-relative offsets):
--   ctx+0x108 (qword) == 0x480
--   ctx+0x0d0 (dword) <= 7
--   ctx+0x110 (qword) == 0x10000 or 0x10002
-- and, only on 0x10002, ctx+0x118 in {0x20000, 0x20001, 0x20002}.
--
-- What this probe measures, in increasing order of risk:
--   A 430(0, 0, 0)          baseline: is 430 reachable through make_syscall
--   B 430(ctx_zero, 0, 0)   readable but zeroed context: reaches the checks
--   C 430(ctx_zero, id, 0)  same, plus the id oracle. The id copyout happens
--                           BEFORE the machine-context validation
--                           (0x437d9a-0x437dc2), so a nonzero id proves the
--                           handler reached thread allocation.
--   D 430(ctx_ok, id, 0)    the three validated fields set: first call in the
--                           corpus that can reach thread creation
--   E 430(ctx_alt, id, 0)   type 0x10002 / subtype 0x20001 variant
--
-- The id oracle is the point of C: a failed call returns -1 either way, but
-- only a call that reached thread allocation writes the id.
--
-- RISK: if D or E returns 0, a second thread exists. Its trap frame is built
-- from the zeroed register block in this buffer, so it may fault at RIP=0 and
-- kill the process before the [RETURNED] line prints. A capture that ends at
-- "[BEFORE] D" is a result, not a broken run.
--
-- PREPARED — NOT RUN. No console was contacted.

print("=== PROBE 58e: thr_create(430) WITH A VALID-SHAPED ucontext ===")
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

-- House format (53d/57e): get_hi_lo + %08X_%08X, guarded so a representation
-- surprise cannot abort the probe.
local function fmt_q(addr)
    local v = safe_rq(addr)
    if v == nil then return "0x<unreadable>" end
    local ok, s = pcall(function()
        local h, l = get_hi_lo(v)
        return string.format("0x%08X_%08X", h, l)
    end)
    if ok then return s end
    return "<qword unprintable>"
end

local function describe(v)
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok then return tostring(n) end
    end
    local ok, s = pcall(function() return tostring(v) end)
    if ok then return s end
    return "<unprintable>"
end

-- Zero a buffer with dword stores; alloc() is not guaranteed zeroed.
local function fill_zero(buf, n)
    local ok = 0
    for off = 0, n - 4, 4 do
        if safe_wd(buf + off, 0) then ok = ok + 1 end
    end
    return ok
end

print("[0] Setup")
local ctx_zero = memory.alloc(0x600)
local ctx_ok   = memory.alloc(0x600)
local ctx_alt  = memory.alloc(0x600)
local id_slot  = memory.alloc(0x10)
print("  ctx_zero=" .. tostring(ctx_zero))
print("  ctx_ok="   .. tostring(ctx_ok))
print("  ctx_alt="  .. tostring(ctx_alt))
print("  id_slot="  .. tostring(id_slot))

local z1 = fill_zero(ctx_zero, 0x600)
local z2 = fill_zero(ctx_ok, 0x600)
local z3 = fill_zero(ctx_alt, 0x600)
local z4 = fill_zero(id_slot, 0x10)
print(string.format("  zeroed dwords: ctx_zero=%d ctx_ok=%d ctx_alt=%d id_slot=%d",
    z1, z2, z3, z4))

-- D: the three fields 0xa0ac60 validates before it copies registers.
-- Offsets are context-relative: the consumer receives ctx+0x40, so its
-- +0xc8/+0x90/+0xd0 are ctx+0x108/+0xd0/+0x110.
local w1 = safe_wq(ctx_ok + 0x108, 0x480)
local w2 = safe_wd(ctx_ok + 0x0d0, 0)
local w3 = safe_wq(ctx_ok + 0x110, 0x10000)
print(string.format("  ctx_ok writes: +0x108=%s +0x0d0=%s +0x110=%s",
    tostring(w1), tostring(w2), tostring(w3)))

-- E: type 0x10002 needs the subtype field in {0x20000, 0x20001, 0x20002}.
local w4 = safe_wq(ctx_alt + 0x108, 0x480)
local w5 = safe_wd(ctx_alt + 0x0d0, 0)
local w6 = safe_wq(ctx_alt + 0x110, 0x10002)
local w7 = safe_wq(ctx_alt + 0x118, 0x20001)
print(string.format("  ctx_alt writes: +0x108=%s +0x0d0=%s +0x110=%s +0x118=%s",
    tostring(w4), tostring(w5), tostring(w6), tostring(w7)))

print("  readback ctx_ok:  +0x108=" .. fmt_q(ctx_ok + 0x108)
    .. " +0x110=" .. fmt_q(ctx_ok + 0x110)
    .. " +0x0d0=" .. string.format("%d", safe_rd(ctx_ok + 0x0d0) or -1))
print("  readback ctx_alt: +0x108=" .. fmt_q(ctx_alt + 0x108)
    .. " +0x110=" .. fmt_q(ctx_alt + 0x110)
    .. " +0x118=" .. fmt_q(ctx_alt + 0x118)
    .. " +0x0d0=" .. string.format("%d", safe_rd(ctx_alt + 0x0d0) or -1))
print("")

local sc_430 = make_syscall(430)
local function prefill_id()
    safe_wd(id_slot, 0xDEADBEEF)
    safe_wd(id_slot + 4, 0xDEADBEEF)
end

-- A: null context. If this returns anything other than a failure, the number
-- is not the 13.60 handler or the loader rewrote the arguments.
print("[A] null context (baseline)")
print("  [BEFORE] A 430(ctx=0x0, id=0x0, flags=0)")
local a_ok, a_rv = pcall(function() return sc_430(uint64(0), uint64(0), uint64(0)) end)
print(string.format("  [RETURNED] A ok=%s rv=%s", tostring(a_ok), describe(a_rv)))
print("")

-- B: readable but zeroed context. copyin succeeds; the 0x480 magic check fails.
print("[B] zeroed 0x500 context, no id pointer")
print("  [BEFORE] B 430(ctx=ctx_zero, id=0x0, flags=0)")
local b_ok, b_rv = pcall(function()
    return sc_430(uint64(ctx_zero), uint64(0), uint64(0))
end)
print(string.format("  [RETURNED] B ok=%s rv=%s", tostring(b_ok), describe(b_rv)))
print("")

-- C: the id oracle with an invalid context. The id copyout precedes the
-- machine-context validation, so a nonzero id here is expected if the call
-- reaches thread allocation.
print("[C] zeroed context + id pointer (does the handler reach allocation?)")
prefill_id()
print("  id before=" .. fmt_q(id_slot))
print("  [BEFORE] C 430(ctx=ctx_zero, id=id_slot, flags=0)")
local c_ok, c_rv = pcall(function()
    return sc_430(uint64(ctx_zero), uint64(id_slot), uint64(0))
end)
print(string.format("  [RETURNED] C ok=%s rv=%s", tostring(c_ok), describe(c_rv)))
print("  id after=" .. fmt_q(id_slot))
print("")

-- D: the primary experiment. The three validated fields are set; the register
-- block is still zero, so a created thread would start at RIP=0.
print("[D] validated fields + id pointer (first reachable thread creation)")
prefill_id()
print("  id before=" .. fmt_q(id_slot))
print("  [BEFORE] D 430(ctx=ctx_ok, id=id_slot, flags=0)")
local d_ok, d_rv = pcall(function()
    return sc_430(uint64(ctx_ok), uint64(id_slot), uint64(0))
end)
print(string.format("  [RETURNED] D ok=%s rv=%s", tostring(d_ok), describe(d_rv)))
print("  id after=" .. fmt_q(id_slot))
print("")

-- E: alternate context type. Only the subtype field differs from D.
print("[E] type 0x10002 / subtype 0x20001 variant")
prefill_id()
print("  id before=" .. fmt_q(id_slot))
print("  [BEFORE] E 430(ctx=ctx_alt, id=id_slot, flags=0)")
local e_ok, e_rv = pcall(function()
    return sc_430(uint64(ctx_alt), uint64(id_slot), uint64(0))
end)
print(string.format("  [RETURNED] E ok=%s rv=%s", tostring(e_ok), describe(e_rv)))
print("  id after=" .. fmt_q(id_slot))
print("")

print("=== PROBE 58e COMPLETE ===")
print("Reading: A != failure means 430 is not the decoded handler.")
print("C id != 0xDEADBEEF_DEADBEEF means the handler allocated a thread.")
print("D/E rv == 0 means a second thread was created (and may fault at RIP=0).")
