-- CRASH_CLASS: LOW
-- PROBE 66a: dlsym with real module handles from 593 handle space
--
-- 426a/427a tested 591 with handles 0/-1/-2 — all invalid per the 13.60
-- decode (handle 0 → NULL → error 3). The handler is UNGATED (no authid,
-- no bit-62). This probe tests handles 1-38 from dynlib_get_info(593)'s
-- handle space with multiple symbol name formats (C names, NID patterns).
-- Success = copyout of a resolved address → userland function addresses
-- in XO modules, possibly kernel addresses.
--
-- Convention: 591(handle: u32, name: char*, out_addr: u64*)

print("=== PROBE 66a: DLSYM REAL HANDLES ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Build C string in heap
local function cstr(s)
    local b = memory.alloc(#s + 8)
    for i = 1, #s do
        memory.write_byte(N(b) + i - 1, s:byte(i))
    end
    memory.write_byte(N(b) + #s, 0)
    return b
end

local out = memory.alloc(0x10)

-- [A] Identify valid module handles via 593
print("")
print("-- A: valid module handles from 593 --")
local valid_handles = {}
local info = memory.alloc(0x200)
for h = 0, 50 do
    wd(N(info), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info) + i, 0) end
    local ok, rv = pcall(function()
        return mk(593)(uint64(h), info)
    end)
    local ret = ok and N(rv) or -999
    if ret == 0 then
        local name_lo = rd(N(info) + 0x08) or 0
        local name_hi = rd(N(info) + 0x0C) or 0
        local text_lo = rd(N(info) + 0x108) or 0
        local text_hi = rd(N(info) + 0x10C) or 0
        valid_handles[#valid_handles + 1] = h
        if #valid_handles <= 10 then
            print(string.format("  h=%d text=%X_%08X", h, text_hi, text_lo))
        end
    end
end
print(string.format("  total valid handles: %d (range %d-%d)",
    #valid_handles,
    valid_handles[1] or -1,
    valid_handles[#valid_handles] or -1))

if #valid_handles == 0 then
    print("NO VALID HANDLES - abort")
    print("=== 66a DONE ===")
    return
end

-- [B] Test 591 with each valid handle + C function names
print("")
print("-- B: dlsym sweep (C names) --")

local names = {
    "sceKernelSleep",
    "sceKernelUsleep",
    "sceKernelGetCpuTemperature",
    "sceKernelDlSym",
    "sceKernelLoadStartModule",
    "sceKernelGetModuleInfo",
    "sceKernelJitCreateSharedMemory",
    "sceKernelMapFlexibleMemory",
    "sceKernelAllocateDirectMemory",
    "sceKernelMprotect",
    "sceKernelGetDirectMemorySize",
    "read", "write", "close", "socket",
    "getpid", "mmap", "mprotect",
    "module_start", "module_stop",
    "_init", "_fini",
    "malloc", "free", "printf",
    "sceKernelSendNotificationRequest",
    "scePthreadCreate",
    "scePthreadMutexLock",
}

local found = 0
local hi = 1
while hi <= #valid_handles do
    local h = valid_handles[hi]
    local ni = 1
    while ni <= #names do
        local np = cstr(names[ni])
        -- Zero the output pointer
        wq(out, uint64(0))
        wq(uint64(N(out) + 8), uint64(0))

        local ok, rv = pcall(function()
            return mk(591)(uint64(h), uint64(N(np)), uint64(N(out)))
        end)
        local ret = ok and N(rv) or -999
        local oh = rd(N(out) + 4) or 0
        local ol = rd(N(out)) or 0

        if ret == 0 or (oh ~= 0 and oh ~= 0xFFFFFFFF) or ol ~= 0 then
            found = found + 1
            print(string.format("  ★ h=%d %-34s rv=%d out=%X_%08X", h, names[ni], ret, oh, ol))
            -- Check if kernel pointer
            if oh >= 0xFFFF8000 and oh ~= 0xFFFFFFFF then
                print("    *** KERNEL POINTER! ***")
            end
        end
        ni = ni + 1
    end
    hi = hi + 1
end
print(string.format("  C-name results: %d found", found))

-- [C] Test with NID-like encoded names (base64 patterns seen in PS5 ELFs)
-- PS5 NID format: 11-char base64 + '#' + libname + '#' + libname
-- Without the exact hash, try a few well-known PS4/PS5 NIDs
print("")
print("-- C: dlsym sweep (NID patterns) --")

local nid_names = {
    "2OuxnbCefPQ#libkernel#libkernel",    -- approximate NID for sceKernelSleep
    "QcteRwbsnV0#libkernel#libkernel",    -- approximate NID for getpid
    "gQX3JSsnV0Q#libkernel#libkernel",    -- approximate NID pattern
    "libkernel",
    "libSceLibcInternal",
    "libSceNet",
    "libSceSysmodule",
}

local found2 = 0
local h2i = 1
while h2i <= #valid_handles and h2i <= 5 do
    local h = valid_handles[h2i]
    local ni = 1
    while ni <= #nid_names do
        local np = cstr(nid_names[ni])
        wq(out, uint64(0))

        local ok, rv = pcall(function()
            return mk(591)(uint64(h), uint64(N(np)), uint64(N(out)))
        end)
        local ret = ok and N(rv) or -999
        local oh = rd(N(out) + 4) or 0
        local ol = rd(N(out)) or 0

        if ret == 0 or (oh ~= 0 and oh ~= 0xFFFFFFFF) or ol ~= 0 then
            found2 = found2 + 1
            print(string.format("  ★ h=%d %-40s rv=%d out=%X_%08X", h, nid_names[ni], ret, oh, ol))
        end
        ni = ni + 1
    end
    h2i = h2i + 1
end
print(string.format("  NID results: %d found", found2))

-- [D] Test 591 error discrimination: capture errno via different returns
-- The 13.60 decode shows distinct error codes:
-- error 1 = no dynlib object, error 3 = bad handle or caller attribution
print("")
print("-- D: error code discrimination --")
local test_cases = {
    {0, "zero_handle"},
    {valid_handles[1], "first_valid"},
    {99, "out_of_range"},
    {0xFFFFFFFF, "minus_one"},
}
local ti = 1
while ti <= #test_cases do
    local h = test_cases[ti][1]
    local label = test_cases[ti][2]
    local np = cstr("getpid")
    wq(out, uint64(0xDEADBEEF))
    local ok, rv = pcall(function()
        return mk(591)(uint64(h), uint64(N(np)), uint64(N(out)))
    end)
    local ret = -999
    if ok then
        local rh, rl = get_hi_lo(rv)
        ret = rl
        if rh >= 0x80000000 then ret = rl - 4294967296 end
        if rh == 0xFFFFFFFF then ret = -1 end
    end
    local oh = rd(N(out) + 4) or 0
    local ol = rd(N(out)) or 0
    print(string.format("  h=%-12s rv=%-6d out=%X_%08X", label, ret, oh, ol))
    ti = ti + 1
end

-- [E] If we found nothing, try via native.fcall_with_rax on libkernel's dlsym
-- The loader resolves 0x24f as 'dlsym' — the wrapper may be accessible
print("")
print("-- E: alternate via native.fcall path --")
if found == 0 and found2 == 0 then
    -- Try calling 591 differently: via the raw stub with explicit arg placement
    -- native.fcall_with_rax(stub, syscall_num) only controls rax
    -- make_syscall is the only path available
    print("  All 591 attempts returned error - caller attribution may block")
    print("  The return address is in libkernel's syscall stub")
    print("  If libkernel isn't in [obj+0x18]/[obj+0x20], error 3 is expected")
else
    print(string.format("  Skipped (found %d results above)", found + found2))
end

print("")
print("=== 66a DONE ===")
