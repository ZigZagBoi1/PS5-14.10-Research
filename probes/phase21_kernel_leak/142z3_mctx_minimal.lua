-- CRASH_CLASS: LOW
-- PROBE 142z3: Minimal mcontext scan — just getcontext + dump

print("=== PROBE 142z3 ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

local sc_gc = make_syscall(421)
local MC = 0x40

local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)

-- Scan for kernel pointers
print("--- Kernel pointer scan ---")
local found = false
for off = 0, 0x4F0, 8 do
    local q = safe_rq(ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
            print("KPTR +" .. string.format("%03X", off) .. "=" .. hex(q))
            found = true
        end
    end
end
if not found then print("No kernel ptrs") end

-- Dump all non-zero qwords
print("")
print("--- Full dump ---")
for off = 0, 0x1F0, 8 do
    local q = safe_rq(ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print("+" .. string.format("%03X", off) .. "=" .. hex(q))
        end
    end
end

print("")
print("=== DONE ===")
