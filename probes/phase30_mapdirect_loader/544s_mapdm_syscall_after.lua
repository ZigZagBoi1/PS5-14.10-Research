-- CRASH_CLASS: LOW
-- PROBE 544s: MapDirectMemory — test which primitives survive
--
-- 544r proved: memory.write_dword crashes after MapDM (not just reads)
-- 544n proved: pure Lua (print, string.format, math) works after MapDM
--
-- Key question: do SYSCALLS work after MapDM?
-- If syscall.getpid() works → we can use write(4) to send virt_out bytes to TCP
-- If make_syscall works → same
--
-- Test order (most important first, lightest first):
-- 1. Pure Lua ops (control — should work per 544n)
-- 2. syscall.getpid() — does the syscall mechanism survive?
-- 3. make_syscall(20)() — getpid via make_syscall
-- 4. tostring(virt_out) — can we print the uint64 address?
-- 5. type(virt_out) — Lua type check
-- 6. virt_out.h / virt_out.l — uint64 field access
-- 7. memory.alloc() — does alloc work? (C function but no native handler?)
-- 8. memory.write_dword — known to crash, confirm last

print("=== 544s: WHAT SURVIVES MapDM ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end

if not libkernel_base then print("FATAL"); return end

-- Pre-MapDM setup
local pid_pre = to_num(syscall.getpid())
print("pid=" .. pid_pre)

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)

-- AllocDM
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a or to_num(arv) ~= 0 then print("ALLOC FAIL"); return end
local phys = memory.read_qword(phys_out)
print("phys=" .. q(phys))

-- Prepare virt_out
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- Capture virt_out address as number BEFORE MapDM
local virt_out_addr = to_num(virt_out)
print("vo_addr=" .. string.format("0x%X", virt_out_addr))

-- ============ MapDM ============
print("MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- ============ POST-MapDM TESTS ============

-- T1: Pure Lua (control)
print("T1=" .. tostring(1+1))

-- T2: pcall result
print("T2:ok=" .. tostring(ok_m))

-- T3: Can we access mrv at all?
print("T3:type=" .. type(mrv))

-- T4: to_num on mrv (involves metatable __tonumber)
local ok4, n4 = pcall(function() return to_num(mrv) end)
print("T4:ok=" .. tostring(ok4))
if ok4 then print("T4:rv=" .. n4) end

-- T5: syscall.getpid (THIS IS THE KEY TEST)
print("T5:getpid")
local ok5, pid5 = pcall(function() return syscall.getpid() end)
print("T5:ok=" .. tostring(ok5))
if ok5 then print("T5:pid=" .. to_num(pid5)) end

-- T6: make_syscall(20) = getpid
print("T6:make_sc")
local ok6, pid6 = pcall(function()
    local sc = make_syscall(20)
    return sc()
end)
print("T6:ok=" .. tostring(ok6))
if ok6 then print("T6:pid=" .. to_num(pid6)) end

-- T7: tostring on virt_out (uint64 __tostring)
print("T7:tostr_vo")
local ok7, s7 = pcall(function() return tostring(virt_out) end)
print("T7:ok=" .. tostring(ok7))
if ok7 then print("T7:s=" .. s7) end

-- T8: virt_out.h and virt_out.l (uint64 field access)
print("T8:vo_fields")
local ok8h, vh = pcall(function() return virt_out.h end)
local ok8l, vl = pcall(function() return virt_out.l end)
print("T8:h_ok=" .. tostring(ok8h) .. " l_ok=" .. tostring(ok8l))
if ok8h and ok8l then
    local h = vh or 0
    local l = vl or 0
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    print(string.format("T8:vo=%08X%08X", h, l))
end

-- T9: uint64 constructor
print("T9:uint64")
local ok9, u9 = pcall(function() return uint64(42) end)
print("T9:ok=" .. tostring(ok9))

-- T10: memory.alloc (C function, might not use native handler)
print("T10:alloc")
local ok10, a10 = pcall(function() return memory.alloc(8) end)
print("T10:ok=" .. tostring(ok10))

-- T11: native.fcall_with_rax for getpid (the actual native handler)
print("T11:native_getpid")
local getpid_fn = libkernel_base + uint64(0x10A30)  -- typical getpid offset, may vary
local ok11, r11 = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64(0), uint64(0),
        uint64(0), uint64(0), uint64(0))
end)
print("T11:ok=" .. tostring(ok11))

-- T12: memory.write_dword (known to crash — last test)
print("T12:wd")
local test_addr = memory.alloc and ok10 and a10 or virt_out
local ok12 = pcall(function() memory.write_dword(test_addr, 0xAAAA) end)
print("T12:ok=" .. tostring(ok12))

-- T13: memory.read_dword (known to crash)
print("T13:rd")
local ok13, v13 = pcall(function() return memory.read_dword(test_addr) end)
print("T13:ok=" .. tostring(ok13))

print("=== DONE ===")
