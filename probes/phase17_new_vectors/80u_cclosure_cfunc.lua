-- CRASH_CLASS: LOW
-- PROBE 80u: Read __call CClosure C function pointer
-- Minimal probe: just find the dispatch function address

print("=== PROBE 80u: CCLOSURE C FUNCTION ===")

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

syscall.resolve({ sc_getpid = 20 })
local pid = syscall.sc_getpid():tonumber()
print("pid=" .. pid)

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eboot=" .. q(eboot))

-- Section A: __call CClosure
local mt = getmetatable(syscall.pipe)
if not mt then print("NO MT"); return end
if not mt.__call then print("NO __CALL"); return end
if pcall(string.dump, mt.__call) then
    print("__call is Lua bytecode; CClosure pointer interpretation does not apply")
    print("=== PROBE 80u COMPLETE ===")
    return
end

local call_str = tostring(mt.__call)
print("__call=" .. call_str)

-- Parse "function: HEXADDR" format (no 0x prefix)
local hex = call_str:match("function:%s*(0x%x+)")
    or call_str:match("function:%s*(%x+)")
if not hex then print("CANNOT PARSE: " .. call_str); return end

-- Add 0x prefix if needed
if not hex:match("^0x") then hex = "0x" .. hex end
local call_addr = uint64(hex)
print("CClosure=" .. q(call_addr))

-- Read C function pointer at +0x20
local cfunc = rq(call_addr + 0x20)
if not cfunc then print("CANNOT READ +0x20"); return end
print("cfunc_ptr=" .. q(cfunc))

-- Dump CClosure fields
for off = 0, 0x38, 8 do
    local v = rq(call_addr + off)
    if v then print(string.format("+0x%02X: %s", off, q(v))) end
end

-- Check if cfunc is in eboot
local cf_h, cf_l = 0, 0
if type(cfunc) == "table" and cfunc.h then cf_h = cfunc.h; cf_l = cfunc.l
else cf_l = to_num(cfunc) end
local eb_h, eb_l = 0, 0
if type(eboot) == "table" and eboot.h then eb_h = eboot.h; eb_l = eboot.l
else eb_l = to_num(eboot) end

if cf_h == eb_h and cf_l >= eb_l and cf_l < eb_l + 0x200000 then
    local off = cf_l - eb_l
    print(string.format("IN_EBOOT +0x%X", off))
    -- Dump 32 bytes at function entry
    local bytes = ""
    for i = 0, 31 do
        local b = rb(cfunc + i)
        if b then bytes = bytes .. string.format("%02X ", b)
        else bytes = bytes .. "?? " end
    end
    print("bytes: " .. bytes)
end

-- Section B: fn_addr/ropchain layout
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if fn_str then
    local fn_slot = uint64(fn_str)
    print("fn_addr_slot=" .. q(fn_slot))
    local fn_val = rq(fn_slot)
    if fn_val then print("fn_addr_val=" .. q(fn_val)) end
    -- Dump nearby slots
    for off = -0x10, 0x70, 8 do
        local v = rq(fn_slot + off)
        if v then print(string.format("fn%+d: %s", off, q(v))) end
    end
end

if rop_str then
    local rop = uint64(rop_str)
    print("ropchain=" .. q(rop))
    for off = 0, 0x38, 8 do
        local v = rq(rop + off)
        if v then print(string.format("rop+0x%02X: %s", off, q(v))) end
    end
end

-- Section C: Other metatable functions
if mt.__index then
    print("--- __index methods ---")
    for k, v in pairs(mt.__index) do
        if type(v) == "function" then
            local fs = tostring(v)
            local fh = fs:match("function:%s*(0x%x+)")
                or fs:match("function:%s*(%x+)")
            if fh then
                if not fh:match("^0x") then fh = "0x" .. fh end
                local fa = uint64(fh)
                local fp = rq(fa + 0x20)
                if fp then
                    print(k .. ": cfunc=" .. q(fp))
                end
            end
        end
    end
end

-- Section D: Quick call rax scan (first 0x20000 bytes only)
print("--- call_rax scan (first 128KB) ---")
local cr_count = 0
for off = 0, 0x1FFFE, 2 do
    local w = rd(eboot + off)
    if w then
        local lo = w % 0x10000
        if lo == 0xD0FF then
            local after = rb(eboot + off + 2) or 0
            if after == 0xC3 then
                print(string.format("CALL_RAX_RET eboot+0x%X", off))
            end
            cr_count = cr_count + 1
        end
    end
end
print("call_rax_in_128k=" .. cr_count)

print("=== PROBE 80u COMPLETE ===")
