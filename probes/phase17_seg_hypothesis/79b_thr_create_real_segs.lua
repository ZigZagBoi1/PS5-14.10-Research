-- 79b: thr_create with REAL cs/ss/rflags (H1 discriminator).
-- 76d crashed with every entry point while all segment fields were zero.
-- Hypothesis H1: iretq with CS=0 faults in kernel doreti -> double fault -> panic.
-- This probe is 76d (entry = Thrd_exit) plus real selectors and IF=1 rflags.
--   rv=0 AND no panic  -> H1 confirmed; null-entry threads become safe.
--   rv=0 AND panic     -> H1 dead; favors teardown (H2) / IF-stall (H3) split.
--   rv=-1              -> selector values rejected by the handler gate.
-- Fill TEST_CS/TEST_SS/RFLAGS from 79a's dump before running. Defaults below
-- are stock FreeBSD user selectors (0x33 cs, 0x2b ss) and rflags 0x202.
print("=== PROBE 79b: THR_CREATE REAL SEGS ===")

local TEST_CS  = 0x33   -- from 79a live dump
local TEST_SS  = 0x2b   -- from 79a live dump
local TEST_RFLAGS = 0x202  -- IF=1
-- Candidate offsets (ctx-relative): rsp@0xE0, entry@0xF8 per 76d; FreeBSD
-- rsp,ss,cs adjacency predicts ss@0xE8, cs@0xF0, rflags@0x100. CONFIRM via 79a.
local OFF_SS, OFF_CS, OFF_RFLAGS = 0xE8, 0xF0, 0x100

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end
local function wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("canary_getpid=" .. tostring(syscall.sc_getpid():tonumber()))

local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local stack = memory.alloc(0x4000)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(stack, 0x4000)

-- Gates proven by 58e/76d.
wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)

-- Entry = Thrd_exit(0), fresh stack (identical to 76d).
wq(ctx + 0xE0, stack + 0x3FF0)
wq(ctx + 0xF8, libc_addrofs.Thrd_exit)

-- THE DELTA: real selectors + IF=1.
wq(ctx + OFF_SS, TEST_SS)
wq(ctx + OFF_CS, TEST_CS)
wq(ctx + OFF_RFLAGS, TEST_RFLAGS)
print(string.format("segs: cs=0x%X ss=0x%X rflags=0x%X @ +0x%X/+0x%X/+0x%X",
    TEST_CS, TEST_SS, TEST_RFLAGS, OFF_CS, OFF_SS, OFF_RFLAGS))
print("thrd_exit=" .. q(libc_addrofs.Thrd_exit))

print("[BEFORE] 430(real-segs exit-only context)")
local ok_call, rv = pcall(function()
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = 430
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc(uint64(ctx), uint64(id_slot), uint64(0))
end)
print("[RETURNED] ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
local id_ok, id_val = pcall(function() return memory.read_qword(id_slot) end)
if id_ok then print("id_after=" .. q(id_val)) end

local ok2, pid2 = pcall(function() return syscall.sc_getpid():tonumber() end)
print("canary2_getpid=" .. tostring(pid2))
print("If this line prints, the console survived at least the syscall return.")
print("=== PROBE 79b COMPLETE ===")
print("JUDGE BY: console alive 60s after COMPLETE (no delayed panic).")
