-- CRASH_CLASS: MODERATE (the 390 calls run in child threads; a fault there
--               need not take the parent, and SIGSYS is ignored inside the child)
-- PROBE 1341c: kenv(390) with real arguments, in a child thread
--
-- prior art:
--   results/phase8_live_network/42a_kernel_rw_20261016_001156.txt  ends at "--- kenv ---"
--   results/42g2_high_phys_decode_20261016_070600.txt              88 bytes, ends at the kenv header
--   docs/SYSENT_PRESENCE_14_10.md:413  | 390 | kenv | - | kills |
--   docs/sysent-names-13.60.csv        390 = kenv, handler_rva 0x266070 (a real handler, not nosys)
--   docs/SYSCALL_ABSENT_VS_LETHAL.md   "a kill is a result about the call"
--   docs/CHAIN_14_10.md, docs/THREADING_ALIVE_14_10.md  child-ROP gadget catalog
--   probes/phase21_next_vectors/396f_pop_r8_verify.lua  verified chain shape
--   results/phase35_dead_end_reruns/1341a2_...  thr_new(455) from this loader returns 0 (tid 0x18F0A)
--
-- FreeBSD kenv is `kenv(int what, const char *name, char *buf, int len)` with
-- KERN_ENVGET=0 (look up `name`) and KERN_ENVNAME=1 (`name` is an integer index,
-- buf receives the variable name). Four shapes, each in its own child, each
-- preceded by sigaction(SIGSYS, SIG_IGN) so an absent slot returns -1 instead
-- of raising. The child stores its RAX into a marker before thr_exit, so the
-- parent reads the result even though the child is gone. A control child calls
-- getpid(20) and proves the chain shape.

print("=== PROBE 1341c: KENV(390) IN A CHILD THREAD ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function parts(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    local n = N(v)
    if n < 0 then return 4294967295, 4294967295 end
    return math.floor(n / 4294967296) % 4294967296, n % 4294967296
end
local function hx(v)
    local h, l = parts(v)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function s64(v)
    local h, l = parts(v)
    if h >= 2147483648 then return l + (h - 4294967296) * 4294967296 end
    return h * 4294967296 + l
end

local pid = 0
pcall(function() pid = N(mk(20)()) end)
print("pid=" .. pid)

local stub = nil
pcall(function() stub = syscall.pipe.fn_addr end)
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local elo, ehi = rd(N(info) + 0x108), rd(N(info) + 0x10C)
if elo == nil or stub == nil then
    print("[0] no module base or stub; aborting")
    print("=== PROBE 1341c ABORTED ===")
    return
end
local eb = ehi * 4294967296 + elo
print(string.format("eb=%X  stub=%s", eb, tostring(stub)))

local function g(off)
    local lo = elo + off
    local hi = ehi
    if lo >= 4294967296 then
        hi = hi + math.floor(lo / 4294967296)
        lo = lo % 4294967296
    end
    return uint64(string.format("0x%X%08X", hi, lo))
end
local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)

-- fake TCB so a failing syscall inside a child can read %fs:0
local tcb_buf = memory.alloc(0x10000)
zero(tcb_buf, 0x10000)
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- sigaction struct with sa_handler = SIG_IGN (1)
local sa = memory.alloc(16)
zero(sa, 16)
wq(sa, uint64(1))

-- the kenv name buffer: "kernel"
local nambuf = memory.alloc(16)
zero(nambuf, 16)
wd(N(nambuf), 0x6E72656B)      -- 'k','e','r','n'
wd(N(nambuf) + 4, 0x00006C65)  -- 'e','l',0,0

-- spawn one child that runs `n` (syscall number) with up to 4 args, stores the
-- result in *marker, then thr_exit(0). Returns tid, marker address.
local function spawn(num, a1, a2, a3, a4)
    local marker = memory.alloc(8)
    wq(marker, uint64(0xDEADDEAD))
    local stk = memory.alloc(0x10000)
    zero(stk, 0x10000)
    local base = N(stk)
    local nominal = 0x400
    local top = base + nominal
    local rsp = (top - (top % 16)) - 8
    local sp = rsp
    local function push(v) wq(sp, v); sp = sp + 8 end
    -- sysarch(165, SET_FSBASE=129, &fake_tcb)
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)
    -- sigaction(416, 12, &sa{SIG_IGN}, NULL)
    push(uint64(416))
    push(pop_rdi_ret); push(uint64(12))
    push(pop_rsi_ret); push(uint64(N(sa)))
    push(pop_rdx_ret); push(uint64(0))
    push(stub)
    -- the measured call
    push(uint64(num))
    push(pop_rdi_ret); push(uint64(a1))
    push(pop_rsi_ret); push(uint64(a2))
    push(pop_rdx_ret); push(uint64(a3))
    push(pop_rcx_ret); push(uint64(a4))
    push(stub)
    -- *marker = rax
    push(pop_rdi_ret); push(uint64(N(marker)))
    push(mov_rdi_rax)
    -- thr_exit(431, 0)
    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    local pa = memory.alloc(0x38)
    zero(pa, 0x38)
    local tidp = memory.alloc(8)
    wq(tidp, uint64(0xDEADDEAD))
    wq(pa + 0x00, pop_rax_ret)
    wq(pa + 0x08, uint64(0))
    wq(pa + 0x10, uint64(base))
    wq(pa + 0x18, uint64(nominal))
    wq(pa + 0x30, uint64(N(tidp)))
    local ok, rv = pcall(mk(455), uint64(N(pa)), uint64(0x38))
    print(string.format("  spawn(%d): ok=%s rv=%s tid=%s", num, tostring(ok),
        ok and s64(rv) or "?", hx(rq(tidp))))
    return rq(tidp), N(marker), ok
end

print("")
print("[A] control: 20 getpid")
local ctid, cmarker, cok = spawn(20, 0, 0, 0, 0)

print("")
print("[B] 390 shapes")
local kind = memory.alloc(0x200)
zero(kind, 0x200)
local t1, m1 = spawn(390, 0, N(nambuf), N(kind), 0x100)      -- KERN_ENVGET "kernel"
local t2, m2 = spawn(390, 1, 0, N(kind), 0x100)             -- KERN_ENVNAME index 0
local t3, m3 = spawn(390, 0, 1, N(kind), 0x100)             -- bad name pointer
local t4, m4 = spawn(390, 2, N(nambuf), N(kind), 0x100)     -- invalid what

local ts = memory.alloc(16)
wq(ts, uint64(0))
wq(ts + 8, uint64(400000000))
pcall(function() mk(240)(uint64(N(ts)), uint64(0)) end)

print("")
print("[C] results (child RAX as written by mov [rdi],rax)")
local function report(tag, m)
    local v = rq(m)
    if v == nil then
        print(string.format("  %-28s <unreadable>", tag))
        return
    end
    print(string.format("  %-28s %-5d %s", tag, s64(v), hx(v)))
end
report("control getpid", cmarker)
report("390(0, \"kernel\", buf, 0x100)", m1)
report("390(1, 0, buf, 0x100)", m2)
report("390(0, badptr, buf, 0x100)", m3)
report("390(2, \"kernel\", buf, 0x100)", m4)

local nz = 0
local first = -1
for off = 0, 0x1FC, 4 do
    local v = rd(N(kind) + off)
    if v and v ~= 0 then
        nz = nz + 1
        if first < 0 then first = off end
    end
end
print(string.format("  kenv out buffer: nonzero=%d first=%s", nz,
    first >= 0 and string.format("+0x%X", first) or "-"))
if first >= 0 then
    for off = first, math.min(first + 0x30, 0x1FC), 4 do
        local v = rd(N(kind) + off)
        if v and v ~= 0 then print(string.format("    +0x%03X: %08X", off, v)) end
    end
end

local pid2 = 0
local okc = pcall(function() pid2 = N(mk(20)()) end)
print(string.format("canary: ok=%s pid=%s (was %d) %s", tostring(okc), tostring(pid2), pid,
    (okc and pid2 == pid) and "OK" or "CHANGED"))
print("")
print("=== PROBE 1341c COMPLETE ===")
