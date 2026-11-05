-- CRASH_CLASS: LOW
-- PROBE 591d: Test native.fcall_with_rax for multi-arg syscalls
--
-- Verify that native.fcall_with_rax handles 4+ arg syscalls (mmap, sysctl, 674).
-- If it does, we can avoid make_syscall entirely and eliminate binary dumps.

print("=== PROBE 591d: NATIVE MULTI-ARG ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- TEST 1: mmap via native (6 args: addr, len, prot, flags, fd, offset)
print("")
print("--- TEST 1: mmap(477) via native ---")
local ok1, rv1 = pcall(function()
    return native.fcall_with_rax(stub, 477,
        uint64(0), uint64(0x200000), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("ok=" .. tostring(ok1))
if ok1 then
    local h, l = get_hi_lo(rv1)
    print("rv=" .. fmt64(rv1))
    if h > 0 or l > 0x10000 then
        print("PASS: got valid mmap address")
    else
        print("FAIL: mmap returned " .. fmt64(rv1))
    end
else
    print("ERR=" .. tostring(rv1))
end

-- TEST 2: dynlib_get_info(593) via native (2 args)
print("")
print("--- TEST 2: dynlib_get_info(593) via native ---")
local info = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
local ok2, rv2 = pcall(function()
    return native.fcall_with_rax(stub, 593, uint64(0), info)
end)
print("ok=" .. tostring(ok2) .. " rv=" .. (ok2 and N(rv2) or tostring(rv2)))
if ok2 then
    local tlo = rd(N(info) + 0x108) or 0
    local thi = rd(N(info) + 0x10C) or 0
    if tlo < 0 then tlo = tlo + 0x100000000 end
    if thi < 0 then thi = thi + 0x100000000 end
    if thi > 0 or tlo > 0 then
        print("eboot=" .. string.format("0x%X%08X", thi, tlo))
    else
        print("eboot=0 (593 failed silently)")
    end
end

-- TEST 3: sys 674 via native (5 args)
print("")
print("--- TEST 3: sys 674 via native ---")
local STRIDE = 72
local vmbuf = memory.alloc(STRIDE * 50 + 0x100)
local countp = memory.alloc(16)
wd(N(countp), 0); wd(N(countp) + 4, 0)
local ok3, rv3 = pcall(function()
    return native.fcall_with_rax(stub, 674,
        uint64(N(vmbuf)), uint64(STRIDE), uint64(50),
        uint64(N(countp)), uint64(0x40000000))
end)
print("ok=" .. tostring(ok3) .. " rv=" .. (ok3 and N(rv3) or tostring(rv3)))
if ok3 then
    local cnt = rd(N(countp)) or 0
    print("regions=" .. cnt)
end

print("")
print("canary=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid))
print("=== 591d COMPLETE ===")
