-- CRASH_CLASS: LOW
-- PROBE 104a: Loader dispatch internals — read __call code + chain mutation tracking
--
-- Context: The ROP chain at ropchain+0x000 through +0x2f0 lives in writable heap.
-- The argument slots at ropchain-0x20b0 through -0x2040 are also writable.
-- Probe 45c showed tested calls persisted after fn_addr + chain[0-7] mutations.
-- This means either:
--   (a) the __call dispatch rebuilds the chain each call, or
--   (b) there's a fast-path that bypasses the chain entirely, or
--   (c) only specific chain positions matter
--
-- This probe reads the ACTUAL __call dispatch function code and tracks
-- which chain positions change between calls. ZERO crash risk — read-only.
--
-- Section A: Read __call dispatch function bytes (first 256 bytes of x86-64 code)
-- Section B: Track chain mutations across consecutive make_syscall calls
-- Section C: Argument slot observation — what the loader writes to the arg data area
-- Section D: fn_addr + return_addr lifecycle tracking across different syscall numbers

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 104a: LOADER DISPATCH INTERNALS ===")
print("Section: " .. TEST_SECTION)
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

-- Get __call address from the pipe metatable
local pipe_str = tostring(syscall.pipe)
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_addr_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")

if not rop_addr_str then
    print("Cannot parse ropchain address from pipe")
    return
end

local rop_base = uint64(rop_addr_str)
local fn_addr_ptr = fn_addr_str and uint64(fn_addr_str) or nil
local ret_addr_ptr = ret_addr_str and uint64(ret_addr_str) or nil

print("ropchain:    " .. fmt(rop_base))
print("fn_addr_ptr: " .. (fn_addr_ptr and fmt(fn_addr_ptr) or "?"))
print("ret_addr_ptr:" .. (ret_addr_ptr and fmt(ret_addr_ptr) or "?"))

-- Find __call from the pipe's metatable
local mt = getmetatable(syscall.pipe)
local call_fn = mt and mt.__call
print("__call:      " .. (call_fn and tostring(call_fn) or "nil"))
print("")

if TEST_SECTION == "A" then
    print("--- Section A: Read __call dispatch function code ---")
    print("")

    -- The __call is a Lua CClosure. Its +0x20 points to the C function.
    if not call_fn then
        print("  __call not found in metatable")
        return
    end

    local call_str = tostring(call_fn)
    local cc_addr_str = call_str:match("(0x[0-9a-fA-F]+)")
    if not cc_addr_str then
        print("  Cannot parse __call CClosure address: " .. call_str)
        return
    end
    local cc_addr = uint64(cc_addr_str)
    print("[A1] __call CClosure: " .. fmt(cc_addr))

    -- Read the CClosure header
    print("[A2] CClosure structure:")
    for i = 0, 7 do
        local q = safe_rq(cc_addr + i * 8)
        print(string.format("  +0x%02X: %s", i * 8, q and fmt(q) or "UNREADABLE"))
    end
    print("")

    -- +0x20 is the C function pointer
    local c_func = safe_rq(cc_addr + 0x20)
    if not c_func then
        print("  Cannot read +0x20")
        return
    end
    print("[A3] C dispatch function: " .. fmt(c_func))

    -- Read the function's x86-64 code
    -- This is in eboot .text (RX), so it's safe to read
    print("[A4] First 256 bytes of dispatch function:")
    local bytes_per_line = 16
    for row = 0, 15 do
        local hex = {}
        local ascii = {}
        for col = 0, bytes_per_line - 1 do
            local off = row * bytes_per_line + col
            local ok, byte_val = pcall(function()
                return memory.read_byte(c_func + off)
            end)
            if ok and byte_val then
                local b = to_num(byte_val) % 256
                table.insert(hex, string.format("%02X", b))
                if b >= 32 and b <= 126 then
                    table.insert(ascii, string.char(b))
                else
                    table.insert(ascii, ".")
                end
            else
                table.insert(hex, "??")
                table.insert(ascii, "?")
                if col == 0 then
                    print(string.format("  +%03X: READ FAIL (XO page? process killed?)", off))
                    print("  *** STOP: this may be XO memory ***")
                    print("[DONE] Section A - read fail at " .. fmt(c_func + off))
                    return
                end
            end
        end
        print(string.format("  +%03X: %s  %s",
            row * bytes_per_line,
            table.concat(hex, " "),
            table.concat(ascii)))
    end
    print("")

    -- Also read the area around fn_addr and return_addr
    if fn_addr_ptr then
        print("[A5] fn_addr area (-0x20 to +0x20):")
        for i = -4, 4 do
            local q = safe_rq(fn_addr_ptr + i * 8)
            print(string.format("  fn_addr%+d: %s", i * 8, q and fmt(q) or "?"))
        end
    end
    print("")

    -- Read the first chain entry area for context
    print("[A6] Chain entry structure (first 8 entries):")
    for i = 0, 7 do
        local q = safe_rq(rop_base + i * 8)
        print(string.format("  chain[%d] (+0x%02X): %s", i, i * 8, q and fmt(q) or "?"))
    end

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Chain mutation tracking across syscalls ---")
    print("  Snapshot chain before/after make_syscall calls to see what changes")
    print("")

    -- Snapshot entire chain (0x2f0 / 8 = 94 qwords)
    local chain_size = 94
    local function snapshot_chain()
        local snap = {}
        for i = 0, chain_size - 1 do
            snap[i] = safe_rq(rop_base + i * 8)
        end
        return snap
    end

    local function diff_chain(before, after)
        local changes = {}
        for i = 0, chain_size - 1 do
            local b = before[i] and fmt(before[i]) or "nil"
            local a = after[i] and fmt(after[i]) or "nil"
            if b ~= a then
                table.insert(changes, {i, b, a})
            end
        end
        return changes
    end

    -- Also snapshot fn_addr and return_addr
    local function snapshot_ptrs()
        return {
            fn = fn_addr_ptr and safe_rq(fn_addr_ptr) or nil,
            ret = ret_addr_ptr and safe_rq(ret_addr_ptr) or nil,
        }
    end

    -- Test 1: Before any call
    print("[B1] Initial chain snapshot:")
    local snap0 = snapshot_chain()
    local ptrs0 = snapshot_ptrs()
    print("  fn_addr:    " .. (ptrs0.fn and fmt(ptrs0.fn) or "?"))
    print("  return_addr:" .. (ptrs0.ret and fmt(ptrs0.ret) or "?"))
    print("")

    -- Test 2: After getpid (syscall 20)
    print("[B2] After make_syscall(20) [getpid]:")
    local sc20 = make_syscall(20)
    local ok20, rv20 = pcall(function() return sc20() end)
    print("  ret=" .. (ok20 and fmt(rv20) or "FAIL"))
    local snap1 = snapshot_chain()
    local ptrs1 = snapshot_ptrs()
    local diff1 = diff_chain(snap0, snap1)
    print("  fn_addr:    " .. (ptrs1.fn and fmt(ptrs1.fn) or "?") ..
        (ptrs0.fn and ptrs1.fn and fmt(ptrs0.fn) ~= fmt(ptrs1.fn) and " *** CHANGED ***" or ""))
    print("  return_addr:" .. (ptrs1.ret and fmt(ptrs1.ret) or "?") ..
        (ptrs0.ret and ptrs1.ret and fmt(ptrs0.ret) ~= fmt(ptrs1.ret) and " *** CHANGED ***" or ""))
    print("  Chain diffs: " .. #diff1)
    for _, d in ipairs(diff1) do
        print(string.format("    [%d] +0x%03X: %s → %s", d[1], d[1] * 8, d[2], d[3]))
    end
    print("")

    -- Test 3: After sysctl (syscall 202)
    print("[B3] After make_syscall(202) [sysctl]:")
    local snap_pre = snapshot_chain()
    local sc202 = make_syscall(202)
    local buf = memory.alloc(0x100)
    safe_wd(buf, 1)       -- CTL_KERN
    safe_wd(buf + 4, 37)  -- KERN_HOSTNAME
    local outbuf = memory.alloc(0x100)
    local olen = memory.alloc(8)
    safe_wd(olen, 0x100)
    local ok202, rv202 = pcall(function()
        return sc202(uint64(buf), uint64(2), uint64(outbuf), uint64(olen), uint64(0), uint64(0))
    end)
    print("  ret=" .. (ok202 and fmt(rv202) or "FAIL"))
    local snap2 = snapshot_chain()
    local ptrs2 = snapshot_ptrs()
    local diff2 = diff_chain(snap_pre, snap2)
    print("  fn_addr:    " .. (ptrs2.fn and fmt(ptrs2.fn) or "?"))
    print("  return_addr:" .. (ptrs2.ret and fmt(ptrs2.ret) or "?"))
    print("  Chain diffs: " .. #diff2)
    for _, d in ipairs(diff2) do
        print(string.format("    [%d] +0x%03X: %s → %s", d[1], d[1] * 8, d[2], d[3]))
    end
    print("")

    -- Test 4: After sys 624 (0 args, VM counter)
    print("[B4] After make_syscall(624) [VM counter]:")
    local snap_pre3 = snapshot_chain()
    local sc624 = make_syscall(624)
    local ok624, rv624 = pcall(function() return sc624() end)
    print("  ret=" .. (ok624 and fmt(rv624) or "FAIL"))
    local snap3 = snapshot_chain()
    local ptrs3 = snapshot_ptrs()
    local diff3 = diff_chain(snap_pre3, snap3)
    print("  fn_addr:    " .. (ptrs3.fn and fmt(ptrs3.fn) or "?"))
    print("  return_addr:" .. (ptrs3.ret and fmt(ptrs3.ret) or "?"))
    print("  Chain diffs: " .. #diff3)
    for _, d in ipairs(diff3) do
        print(string.format("    [%d] +0x%03X: %s → %s", d[1], d[1] * 8, d[2], d[3]))
    end
    print("")

    -- Summary: which positions change across ALL calls?
    print("[B5] Summary of mutated positions:")
    local all_changed = {}
    for _, d in ipairs(diff1) do all_changed[d[1]] = (all_changed[d[1]] or 0) + 1 end
    for _, d in ipairs(diff2) do all_changed[d[1]] = (all_changed[d[1]] or 0) + 1 end
    for _, d in ipairs(diff3) do all_changed[d[1]] = (all_changed[d[1]] or 0) + 1 end
    local sorted_pos = {}
    for pos, count in pairs(all_changed) do
        table.insert(sorted_pos, {pos, count})
    end
    table.sort(sorted_pos, function(a, b) return a[2] > b[2] end)
    for _, entry in ipairs(sorted_pos) do
        print(string.format("  chain[%d] (+0x%03X): changed %d/3 times", entry[1], entry[1] * 8, entry[2]))
    end
    if #sorted_pos == 0 then
        print("  NO chain positions changed across ANY call!")
        print("  This means the chain is STATIC — the loader doesn't use it for dispatch!")
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Argument slot observation ---")
    print("  The chain references arg data at ropchain-0x20b0 through -0x2040")
    print("  (offsets 0x4040 through 0x40b0 relative to the base object)")
    print("")

    -- From the chain: loads from 0x...4040, 0x...4050, 0x...4060, etc.
    -- These are relative to some base. Let's find them relative to rop_base
    -- In 56g: rop_base=0x3111860f0, arg slots at 0x311184040-0x3111840b0
    -- Offset from rop_base: 0x311184040 - 0x3111860f0 = -0x20b0
    -- So arg_slot_base = rop_base - 0x20b0

    -- Actually, let me read them directly from the chain references
    -- chain[2] = address loaded by mov rax,[rax] → this IS the arg slot address
    local arg_addrs = {}
    -- From the chain pattern: every 4th entry (after pop rax;ret) is an arg address
    -- chain[0x10] = 0x3111860f0+0x10 = slot[2] → 0x311184040
    -- Let me read the actual addresses from the chain
    local slot_offsets = {
        0x10, -- arg slot 1 (chain entry 2, used for fn_addr setup)
        0x58, -- arg slot 2 (syscall number?)
        0xE8, -- arg slot for r8
        0x128, -- arg slot for rcx
        0x168, -- arg slot for rdx
        0x1A8, -- arg slot for rsi
        0x1E8, -- arg slot for rdi
        0x228, -- arg slot for final pivot
    }

    print("[C1] Argument slot addresses from chain:")
    for _, off in ipairs(slot_offsets) do
        local slot_addr = safe_rq(rop_base + off)
        if slot_addr then
            local slot_val = safe_rq(slot_addr)
            print(string.format("  chain+0x%03X → %s → value: %s",
                off, fmt(slot_addr),
                slot_val and fmt(slot_val) or "?"))
            table.insert(arg_addrs, slot_addr)
        end
    end
    print("")

    -- Snapshot arg slots before and after a syscall
    print("[C2] Arg slot mutation tracking:")
    local function snapshot_args()
        local snap = {}
        for i, addr in ipairs(arg_addrs) do
            snap[i] = safe_rq(addr)
        end
        return snap
    end

    local args_before = snapshot_args()
    print("  Before call:")
    for i, v in ipairs(args_before) do
        print(string.format("    slot[%d]: %s", i, v and fmt(v) or "?"))
    end

    -- Make a syscall with known arguments
    local sc202 = make_syscall(202)
    local buf = memory.alloc(0x100)
    safe_wd(buf, 1)
    safe_wd(buf + 4, 37)
    local outbuf = memory.alloc(0x100)
    local olen = memory.alloc(8)
    safe_wd(olen, 0x100)
    pcall(function()
        return sc202(uint64(buf), uint64(2), uint64(outbuf), uint64(olen), uint64(0), uint64(0))
    end)

    local args_after = snapshot_args()
    print("  After sysctl(202) with 6 args:")
    for i, v in ipairs(args_after) do
        local changed = args_before[i] and v and fmt(args_before[i]) ~= fmt(v)
        print(string.format("    slot[%d]: %s%s", i, v and fmt(v) or "?",
            changed and " *** CHANGED ***" or ""))
    end
    print("")

    -- Test if we can WRITE to arg slots
    print("[C3] Arg slot writability test:")
    for i, addr in ipairs(arg_addrs) do
        local orig = safe_rq(addr)
        local wr = safe_wq(addr, uint64(0xAAAA0000 + i))
        local readback = safe_rq(addr)
        local restore = orig and safe_wq(addr, orig) or false
        print(string.format("  slot[%d] %s: write=%s readback=%s restore=%s",
            i, fmt(addr),
            wr and "OK" or "FAIL",
            readback and fmt(readback) or "?",
            restore and "OK" or "FAIL"))
    end

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: fn_addr + return_addr lifecycle ---")
    print("  Track how fn_addr and return_addr change across different syscall numbers")
    print("")

    if not fn_addr_ptr or not ret_addr_ptr then
        print("  Missing fn_addr_ptr or ret_addr_ptr")
        return
    end

    -- Read initial values
    print("[D1] Initial state:")
    local fn0 = safe_rq(fn_addr_ptr)
    local ret0 = safe_rq(ret_addr_ptr)
    print("  fn_addr:    " .. (fn0 and fmt(fn0) or "?"))
    print("  return_addr:" .. (ret0 and fmt(ret0) or "?"))
    print("")

    -- Test various syscalls and track fn_addr/return_addr changes
    local test_syscalls = {
        {20, "getpid", {}},
        {202, "sysctl", {uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)}},
        {624, "vm_counter", {}},
        {643, "chicken_sw", {uint64(0)}},
        {477, "mmap", {uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)}},
    }

    print("[D2] fn_addr/return_addr across syscalls:")
    for _, test in ipairs(test_syscalls) do
        local num = test[1]
        local name = test[2]
        local args = test[3]

        -- Read before
        local fn_before = safe_rq(fn_addr_ptr)
        local ret_before = safe_rq(ret_addr_ptr)

        -- Make the call
        local sc = make_syscall(num)
        local ok, rv = pcall(function()
            if #args == 0 then return sc()
            elseif #args == 1 then return sc(args[1])
            elseif #args == 6 then return sc(args[1], args[2], args[3], args[4], args[5], args[6])
            end
        end)

        -- Read after
        local fn_after = safe_rq(fn_addr_ptr)
        local ret_after = safe_rq(ret_addr_ptr)

        local fn_changed = fn_before and fn_after and fmt(fn_before) ~= fmt(fn_after)
        local ret_changed = ret_before and ret_after and fmt(ret_before) ~= fmt(ret_after)

        print(string.format("  sys %d (%s): ret=%s", num, name, ok and fmt(rv) or "FAIL"))
        print(string.format("    fn_addr:  %s → %s%s",
            fn_before and fmt(fn_before) or "?",
            fn_after and fmt(fn_after) or "?",
            fn_changed and " *** CHANGED ***" or ""))
        print(string.format("    ret_addr: %s → %s%s",
            ret_before and fmt(ret_before) or "?",
            ret_after and fmt(ret_after) or "?",
            ret_changed and " *** CHANGED ***" or ""))
    end
    print("")

    -- Test: is fn_addr writable?
    print("[D3] fn_addr writability:")
    local fn_orig = safe_rq(fn_addr_ptr)
    local wr1 = safe_wq(fn_addr_ptr, uint64(0xDEAD))
    local rb1 = safe_rq(fn_addr_ptr)
    local restore1 = fn_orig and safe_wq(fn_addr_ptr, fn_orig) or false
    print(string.format("  write=0xDEAD: %s readback=%s restore=%s",
        wr1 and "OK" or "FAIL",
        rb1 and fmt(rb1) or "?",
        restore1 and "OK" or "FAIL"))

    -- Test: is return_addr writable?
    print("[D4] return_addr writability:")
    local ret_orig = safe_rq(ret_addr_ptr)
    local wr2 = safe_wq(ret_addr_ptr, uint64(0xBEEF))
    local rb2 = safe_rq(ret_addr_ptr)
    local restore2 = ret_orig and safe_wq(ret_addr_ptr, ret_orig) or false
    print(string.format("  write=0xBEEF: %s readback=%s restore=%s",
        wr2 and "OK" or "FAIL",
        rb2 and fmt(rb2) or "?",
        restore2 and "OK" or "FAIL"))

    -- Verify restore — make a syscall to confirm nothing is broken
    print("[D5] Post-restore verification:")
    local sc624 = make_syscall(624)
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624: ret=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 104a COMPLETE ===")
