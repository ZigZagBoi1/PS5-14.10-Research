-- CRASH_CLASS: MODERATE
-- PROBE 183a: sys 653 blockpool_open returns a handle, then 654/655/657 use it
--
-- Context: the 601-660 presence sweep is the first time 653 was called with zero
-- arguments, and it returned 0x16 rather than -1. Everything else in the family
-- (654 blockpool_map, 655 blockpool_unmap, 657 blockpool_batch) returned -1 with
-- zeros, which is what a call that wants that handle looks like. This asks 653 for
-- a handle, repeats it to see whether the values increment, then feeds the handle
-- into 654/655/657 across plausible layouts and prints every return.

print("=== PROBE 183a: SYS 653 blockpool_open -> 654/655/657 ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local function hx(v)
    return tostring(v)
end
local zero = u64(0)

local sc653 = make_syscall(653)
local sc654 = make_syscall(654)
local sc655 = make_syscall(655)
local sc657 = make_syscall(657)

local buf = memory.alloc(0x1000)
for off = 0, 0xFF8, 8 do
    pcall(function() memory.write_qword(buf + off, u64(0xC1C1C1C1)) end)
end

print("[0] 653 with zero arguments, four times")
local handles = {}
for i = 1, 4 do
    local ok, ret = pcall(function() return sc653(zero, zero, zero, zero, zero, zero) end)
    if not ok then
        print("[!] killed at call " .. i)
        break
    end
    handles[#handles + 1] = to_num(ret)
    print(string.format("[*] 653 #%d -> %s (as number %d)", i, hx(ret), to_num(ret)))
end
print("")

print("[0] 653 with arg1 = 0..4")
for a1 = 0, 4 do
    local ok, ret = pcall(function() return sc653(u64(a1), zero, zero, zero, zero, zero) end)
    if not ok then
        print("[!] killed at arg1=" .. a1)
        break
    end
    print(string.format("[*] 653(%d) -> %s", a1, hx(ret)))
end
print("")

local h = handles[1] or 22
local hu = u64(h % 0x100000000)

local function try(num, name, a1, a2, a3, a4, a5)
    local sc = make_syscall(num)
    local ok, ret = pcall(function() return sc(a1, a2, a3, a4 or zero, a5 or zero, zero) end)
    if not ok then
        print(string.format("[!] %s killed", name))
        return nil
    end
    print(string.format("[*] %s -> %s", name, hx(ret)))
    return to_num(ret)
end

print("[0] 654 blockpool_map with handle " .. tostring(h))
try(654, "654(h)", hu)
try(654, "654(h,0)", hu, zero)
try(654, "654(h,0x1000)", hu, u64(0x1000))
try(654, "654(h,buf)", hu, buf)
try(654, "654(h,0,buf)", hu, zero, buf)
try(654, "654(h,0x1000,buf)", hu, u64(0x1000), buf)
try(654, "654(h,0,0x1000,buf)", hu, zero, u64(0x1000), buf)
try(654, "654(0,h,0x1000)", zero, hu, u64(0x1000), buf)
print("")

print("[0] 655 blockpool_unmap")
try(655, "655(h)", hu)
try(655, "655(h,0)", hu, zero)
try(655, "655(h,buf)", hu, buf)
print("")

print("[0] 657 blockpool_batch")
try(657, "657(h,buf)", hu, buf)
try(657, "657(h,0,buf)", hu, zero, buf)
try(657, "657(buf,1)", buf, u64(1))
print("")

print("[0] buf state head: ")
for off = 0, 0x20, 8 do
    local ok, v = pcall(function() return memory.read_qword(buf + off) end)
    if ok then print(string.format("    +0x%02X = %s", off, hx(v))) else print("    fault") end
end

print("")
print("[*] done")
