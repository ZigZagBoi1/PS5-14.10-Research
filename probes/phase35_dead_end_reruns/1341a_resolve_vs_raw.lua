-- CRASH_CLASS: LOW
-- PROBE 1341a: the loader's named syscall table versus make_syscall(N)
--
-- prior art:
--   docs/DEAD_ENDS.md  "Threading via resolve() - fork/rfork/thr_new all -1"
--                      and the void-capture table at the bottom of that file
--   .local/loader_syscall.lua: syscall.resolve(list) installs
--       syscall[name] = fcall(syscall.syscall_address, num); this copy carries
--       no per-number filter at all, so the filter can only be the name list
--   probes/phase10_untested_theories/43e_blocked_syscall_bypass.lua (raw path)
--   probes/phase11_network_attacks/46d_socket_bypass.lua
--       (results/46d_socket_bypass_20261016_194839.txt: named syscall.socket()
--       returned fds 33-43, so a named entry reaches the same libkernel stub)
--   probes/phase17_new_vectors/156c_thr_create_correct_offsets.lua,
--       156d_thr_create_child_executes.lua (verified context + field offsets)
--   probes/phase21_next_vectors/396f_pop_r8_verify.lua (verified gadget chain)
--   docs/THREADING_ALIVE_14_10.md, docs/CHAIN_14_10.md
--
-- Question: for the same syscall number and the same argument setup, does the
-- named entry behave differently from make_syscall(N)? A named -1 against a raw
-- 0 would put a filter in front of the raw path; two identical results put the
-- "filter" in the registration list only. The four names the dead-end bullet
-- names are fork(2), rfork(251), thr_new(455) and thr_create(430); getpid(20) is
-- the control because the loader resolves it itself.

print("=== PROBE 1341a: NAMED SYSCALL TABLE VS make_syscall ===")
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
-- signed 64-bit view of a returned value
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

local stab = syscall
if stab == nil then print("[0] syscall table absent; aborting") return end

local stub = nil
pcall(function() stub = syscall.pipe.fn_addr end)
local pid0 = 0
pcall(function() pid0 = N(mk(20)()) end)
print(string.format("pid=%d  stub=%s", pid0, tostring(stub)))

-- ------------------------------------------------------------------
-- 0) what the loader's table already carries
-- ------------------------------------------------------------------
print("")
print("[0] the console loader's syscall table")
local keys = {}
for k, v in pairs(stab) do
    if type(k) == "string" then keys[#keys + 1] = k .. ":" .. type(v) end
end
table.sort(keys)
print("  " .. table.concat(keys, " "))
print("  resolve is a " .. type(stab.resolve))
print("  resolve(number) test: " .. type(stab.getpid))

-- ------------------------------------------------------------------
-- 1) fork(2) and rfork(251) - zero/simple args, both paths
-- ------------------------------------------------------------------
print("")
print("[1] fork(2) and rfork(251), identical arguments on both paths")
local function both(label, num, args)
    local raw = mk(num)
    local ok, rv = pcall(function() return raw(unpack(args)) end)
    show(label .. " raw", ok, rv)
    local named = stab[label]
    if type(named) ~= "function" then
        print(string.format("  %-26s absent from the table", label .. " named"))
        return
    end
    local ok2, rv2 = pcall(function() return named(unpack(args)) end)
    show(label .. " named", ok2, rv2)
end

both("getpid", 20, {})
both("fork", 2, {})
both("rfork", 251, { uint64(0) })

-- ------------------------------------------------------------------
-- 2) thr_new(455) - a chain that calls sysarch then thr_exit(0)
-- ------------------------------------------------------------------
print("")
print("[2] thr_new(455)")
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
if eb_lo == 0 or stub == nil then
print("[2] no module base or no syscall stub; skipping thread cases")
else
print(string.format("  eb=%X_%08X", eb_hi, eb_lo))
local function g(off) return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off)) end
local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)

-- fake TCB so a failing syscall inside the child can read %fs:0
local tcb_buf = memory.alloc(0x10000)
zero(tcb_buf, 0x10000)
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

-- sysarch(165, SET_FSBASE=129, &fake_tcb) then thr_exit(431, 0)
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
wq(tidp, uint64(0xDEADDEAD))
wq(pa + 0x00, pop_rax_ret)          -- start_func
wq(pa + 0x08, uint64(0))            -- arg
wq(pa + 0x10, uint64(stk_base))     -- stack_base
wq(pa + 0x18, uint64(nominal))      -- stack_size
wq(pa + 0x30, uint64(N(tidp)))      -- child_tid
print(string.format("  param=%X start_func=%s stack=%X+%X",
    N(pa), hexq(pop_rax_ret), stk_base, nominal))

local function thr_new_call(tag, f)
    if type(f) ~= "function" then
        print(string.format("  %-26s absent from the table", tag))
        return
    end
    wq(tidp, uint64(0xDEADDEAD))
    local ok, rv = pcall(function() return f(uint64(N(pa)), uint64(0x38)) end)
    show(tag, ok, rv)
    print(string.format("  %-26s child_tid=%s", tag .. " tid", hexq(rq(tidp))))
end

thr_new_call("thr_new raw", mk(455))
if type(stab.thr_new) ~= "function" and type(stab.resolve) == "function" then
    local ok, rv = pcall(function() return stab.resolve({ thr_new = 455 }) end)
    print(string.format("  resolve({thr_new=455}): ok=%s -> %s", tostring(ok), tostring(rv)))
end
thr_new_call("thr_new named", stab.thr_new)

-- ------------------------------------------------------------------
-- 3) thr_create(430) - the 156c context, child exits via thr_exit
-- ------------------------------------------------------------------
print("")
print("[3] thr_create(430)")
local CTX_SIZE = 0x500
local stk2 = memory.alloc(0x10000)
zero(stk2, 0x10000)
local stk2_base = N(stk2)
local ctx_rsp = stk2_base + 0x8000
write_chain(ctx_rsp)

local ctx = memory.alloc(CTX_SIZE)
zero(ctx, CTX_SIZE)
wq(ctx + 0x108, uint64(0x480))       -- magic
wd(ctx + 0x0D0, 0)                   -- flags <= 7
wq(ctx + 0x110, uint64(0x10000))     -- type
wq(ctx + 0x0C0, uint64(0x43))        -- CS
wq(ctx + 0x0E0, pop_rax_ret)         -- RIP
wq(ctx + 0x0F8, uint64(ctx_rsp))     -- RSP
wq(ctx + 0x100, uint64(0x3B))        -- SS
local tid2 = memory.alloc(8)
wq(tid2, uint64(0xDEADDEAD))
print(string.format("  ctx=%X rsp=%X", N(ctx), ctx_rsp))

local function thr_create_call(tag, f)
    if type(f) ~= "function" then
        print(string.format("  %-26s absent from the table", tag))
        return
    end
    wq(tid2, uint64(0xDEADDEAD))
    local ok, rv = pcall(function() return f(uint64(N(ctx)), uint64(N(tid2)), uint64(0)) end)
    show(tag, ok, rv)
    local tid = rq(tid2)
    print(string.format("  %-26s tid=%s", tag .. " tid", hexq(tid)))
    return tid
end

thr_create_call("thr_create raw", mk(430))
if type(stab.thr_create) ~= "function" and type(stab.resolve) == "function" then
    local ok, rv = pcall(function() return stab.resolve({ thr_create = 430 }) end)
    print(string.format("  resolve({thr_create=430}): ok=%s -> %s", tostring(ok), tostring(rv)))
end
thr_create_call("thr_create named", stab.thr_create)

-- let the children run their chains, then check they are gone
local ts = memory.alloc(16)
wq(ts, uint64(0))
wq(ts + 8, uint64(200000000))
pcall(function() mk(240)(uint64(N(ts)), uint64(0)) end)
local okc, pidc = pcall(function() return N(mk(20)()) end)
print(string.format("  canary after 200ms: ok=%s pid=%s (was %d)", tostring(okc), tostring(pidc), pid0))
end

print("")
print("=== PROBE 1341a COMPLETE ===")
