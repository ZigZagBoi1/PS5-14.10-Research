-- CRASH_CLASS: LOW
-- PROBE 69k: dynlib_dlsym(591) sweep with valid handles + real symbol names
--
-- 591 = dynlib_dlsym (confirmed 13.60 CSV, ungated).
-- 392a tested with zeros → -1. dlsym needs valid handle + symbol name.
-- Call: 591(handle, name_ptr, result_ptr) → 0 on success, -1 on failure
-- Handles 0-38 are valid modules (54k). Handle 0 = eboot.

print("=== PROBE 69k: dynlib_dlsym(591) SWEEP ===")
print("")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local pid = N(mk(20)())
print("pid=" .. pid)

local sc_dlsym = mk(591)
local sc_info = mk(593)

-- ============================================================
-- [A] Enumerate valid module handles via 593
-- ============================================================
print("[A] Valid module handles")
local valid_handles = {}
local info_buf = memory.alloc(0x200)
for h = 0, 50 do
    wd(N(info_buf), 0x160)
    for i = 4, 0x15C, 4 do wd(N(info_buf) + i, 0) end
    local ok, ret = pcall(function()
        return sc_info(uint64(h), uint64(N(info_buf)))
    end)
    if ok and N(ret) == 0 then
        valid_handles[#valid_handles + 1] = h
    end
end
print(string.format("  found %d valid handles (0-%d)", #valid_handles, valid_handles[#valid_handles] or -1))
print("")

-- ============================================================
-- [B] Symbol name table
-- ============================================================
local symbols = {
    -- Standard C / POSIX
    "printf", "malloc", "free", "memcpy", "memset",
    "mmap", "mprotect", "open", "close", "read", "write",
    "socket", "connect", "bind", "listen", "accept",
    -- FreeBSD internals
    "syscall", "sysctl", "__sys_read", "__sys_write",
    "__sys_open", "__sys_close", "__sys_mmap",
    -- PS5 / Sony SDK
    "sceKernelLoadStartModule", "sceKernelDlsym",
    "sceKernelGetModuleInfo", "sceKernelGetModuleList",
    "sceKernelJitCreateSharedMemory", "sceKernelJitCreateAliasOfSharedMemory",
    "sceKernelMapFlexibleMemory", "sceKernelMprotect",
    "sceKernelGetProcParam", "sceKernelUsleep",
    "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText", "sceKernelGetCpuFrequency",
    "sceKernelGetCpuTemperature", "sceKernelGetSocSensorTemperature",
    "sceKernelSetProcessName",
    -- Kernel symbols (long shot — dlsym resolves userland only, but test anyway)
    "kernel_base", "prison0", "allproc", "rootvnode",
    "kexec", "kread", "kwrite",
    -- Module lifecycle
    "module_start", "module_stop", "module_info",
    "_init", "_fini", "main",
    -- NID-style (PS5 uses obfuscated NIDs for exports)
    "sceKernelError", "scePthreadCreate", "scePthreadMutexLock",
    "sceKernelAllocateDirectMemory", "sceKernelMapDirectMemory",
    "sceKernelReleaseDirectMemory",
    "sceKernelOpen", "sceKernelClose", "sceKernelRead", "sceKernelWrite",
    "sceKernelMmap", "sceKernelMunmap",
    "sceKernelStat", "sceKernelFstat",
    "sceKernelSendMsg", "sceKernelReceiveMsg",
}

-- Pre-allocate name buffers
local name_ptrs = {}
for _, sym in ipairs(symbols) do
    name_ptrs[sym] = put_str(sym)
end

local result_ptr = memory.alloc(8)
local total_hits = 0
local kptr_hits = 0

-- ============================================================
-- [C] Sweep: all valid handles × all symbols
-- ============================================================
print("[C] dlsym sweep: " .. #valid_handles .. " handles x " .. #symbols .. " symbols")

for _, h in ipairs(valid_handles) do
    local hits_this_handle = 0
    local fails_this_handle = 0

    for _, sym in ipairs(symbols) do
        wq(N(result_ptr), uint64(0))
        local ok, ret = pcall(function()
            return sc_dlsym(uint64(h), uint64(N(name_ptrs[sym])), uint64(N(result_ptr)))
        end)

        if ok and N(ret) == 0 then
            local addr = rq(N(result_ptr))
            local ah, al = get_hi_lo(addr)
            total_hits = total_hits + 1
            hits_this_handle = hits_this_handle + 1

            local tag = ""
            if ah >= 0xFFFF8000 then
                tag = " *** KERNEL ***"
                kptr_hits = kptr_hits + 1
            end

            print(string.format("  h=%d %-40s -> %s%s", h, sym, fmt(addr), tag))
        else
            fails_this_handle = fails_this_handle + 1
        end
    end

    if hits_this_handle == 0 and (h == 0 or h == 1 or h == 2 or h == valid_handles[#valid_handles]) then
        print(string.format("  h=%d: 0/%d resolved", h, #symbols))
    end
end
print("")

-- ============================================================
-- [D] If zero hits with plain names, try NID-hashed names
-- Sony uses a hash of "library#NID" format. Try raw NID hex strings.
-- Known libkernel NIDs (from public PS4/PS5 databases):
-- ============================================================
if total_hits == 0 then
    print("[D] Zero plain hits — trying NID-style lookups")

    local nids = {
        -- libkernel known NIDs (11-char base64-like)
        {"2I+sIr32GcQ", "sceKernelDlsym"},
        {"6Z59AkpJ0jw", "sceKernelSleep"},
        {"QcteRwbsnV0", "sceKernelUsleep"},
        {"HoLVWNanBBc", "sceKernelDebugOutText"},
        {"gQhwrF3KZrc", "sceKernelAllocateDirectMemory"},
        {"MBuItvba6z8", "sceKernelMapDirectMemory"},
        {"cQke9UuBQOk", "sceKernelMunmap"},
        {"BPE9s9vQQXo", "sceKernelMmap"},
        {"UK2Tl2DWUns", "sceKernelOpen"},
        {"bY-PO6JhzhQ", "sceKernelClose"},
        {"Ny-MHKQQ8Zk", "sceKernelRead"},
        {"4wSze92BhLI", "sceKernelWrite"},
        {"eV9wAD2riIA", "sceKernelStat"},
        {"kBJzF8x4SyE", "sceKernelLoadStartModule"},
    }

    for _, h in ipairs({0, 1, 2}) do
        for _, nid_pair in ipairs(nids) do
            local nid = nid_pair[1]
            local desc = nid_pair[2]
            local nid_ptr = put_str(nid)
            wq(N(result_ptr), uint64(0))
            local ok, ret = pcall(function()
                return sc_dlsym(uint64(h), uint64(N(nid_ptr)), uint64(N(result_ptr)))
            end)
            if ok and N(ret) == 0 then
                local addr = rq(N(result_ptr))
                local ah, al = get_hi_lo(addr)
                local tag = (ah >= 0xFFFF8000) and " *** KERNEL ***" or ""
                print(string.format("  h=%d NID=%-20s (%s) -> %s%s", h, nid, desc, fmt(addr), tag))
                total_hits = total_hits + 1
                if ah >= 0xFFFF8000 then kptr_hits = kptr_hits + 1 end
            end
        end
    end

    if total_hits == 0 then
        print("  Zero NID hits — dlsym may need library-qualified NIDs")
    end
end
print("")

-- ============================================================
-- [E] Try alternate calling conventions
-- Some Sony dlsym variants: 591(handle, nid_ptr, result_ptr, flags)
-- ============================================================
if total_hits == 0 then
    print("[E] Trying 4-arg variant: 591(handle, name, result, flags)")
    local test_names = {"malloc", "printf", "sceKernelDlsym"}
    for _, h in ipairs({0, 1, 2}) do
        for _, sym in ipairs(test_names) do
            for _, flag in ipairs({0, 1, 2}) do
                wq(N(result_ptr), uint64(0))
                local ok, ret = pcall(function()
                    return sc_dlsym(uint64(h), uint64(N(name_ptrs[sym])), uint64(N(result_ptr)), uint64(flag))
                end)
                if ok and N(ret) == 0 then
                    local addr = rq(N(result_ptr))
                    print(string.format("  h=%d %-20s flag=%d -> %s", h, sym, flag, fmt(addr)))
                    total_hits = total_hits + 1
                end
            end
        end
    end
    if total_hits == 0 then
        print("  Zero hits with flags variant")
    end
end
print("")

print("[F] SUMMARY")
print(string.format("  valid handles: %d", #valid_handles))
print(string.format("  symbols tried: %d", #symbols))
print(string.format("  total hits:    %d", total_hits))
print(string.format("  kernel ptrs:   %d", kptr_hits))

if total_hits > 0 and kptr_hits > 0 then
    print("*** KERNEL SYMBOL RESOLUTION — KASLR DEFEAT ***")
elseif total_hits > 0 then
    print("Userland symbols resolved — no kernel pointers")
else
    print("No symbols resolved — 591 may need NID encoding or different args")
end

print("")
print("alive=YES")
print("=== PROBE 69k COMPLETE ===")
