-- CRASH_CLASS: LOW
-- PROBE 125j: Use native.fcall via the correct C function addresses
-- The fcall global is a callable table that wraps native.fcall.
-- Use it to call sceKernelGetModuleInfoFromAddr and other Sony functions
-- to try to leak kernel pointers.

print("=== PROBE 125j: FCALL VIA WRAPPER ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: Test the fcall global (callable table)
print("")
print("--- SECTION A: FCALL GLOBAL ---")
print("fcall type=" .. type(fcall))
if type(fcall) == "table" then
    local mt = getmetatable(fcall)
    if mt then
        for k, v in pairs(mt) do print("  mt." .. tostring(k) .. "=" .. type(v)) end
    end
end

-- Section B: Try calling getpid via the syscall wrapper table
print("")
print("--- SECTION B: SYSCALL WRAPPERS ---")
if syscall.syscall_wrapper then
    -- getpid = syscall 20
    local gp_addr = syscall.syscall_wrapper[20]
    print("syscall_wrapper[20]=" .. tostring(gp_addr))
    if gp_addr then
        local ok, ret = pcall(native.fcall, gp_addr)
        print("native.fcall(wrapper[20]): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
        if ok then
            print("  value=" .. to_num(ret))
        end
    end

    -- List some wrappers
    local count = 0
    for num, addr in pairs(syscall.syscall_wrapper) do
        count = count + 1
        if count <= 20 then
            print(string.format("  wrapper[%d] = %s", num, tostring(addr)))
        end
    end
    print("total_wrappers=" .. count)
end

-- Section C: Use the fcall() table call to wrap a function
print("")
print("--- SECTION C: FCALL TABLE CALL ---")
-- fcall(addr) returns a callable that invokes native.fcall(addr, ...)
-- sceKernelGetModuleInfoFromAddr is at libc_addrofs.sceKernelGetModuleInfoFromAddr
local ok1, getmodinfo = pcall(fcall, libc_addrofs.sceKernelGetModuleInfoFromAddr)
print("fcall(sceKernelGetModuleInfoFromAddr): ok=" .. tostring(ok1) .. " ret=" .. tostring(getmodinfo))

if ok1 and getmodinfo then
    -- Call it with libkernel_base to get module info
    local mod_info = memory.alloc(0x200)
    memory.write_dword(mod_info, 0x160)  -- sizeof
    local ok2, ret2 = pcall(getmodinfo, libkernel_base, 1, uint64(mod_info))
    print("getmodinfo(lk_base,1,buf): ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
    if ok2 then
        print("  retval=" .. tostring(ret2))
        -- Dump some interesting offsets
        for off = 0, 0x150, 8 do
            local q = memory.read_qword(mod_info + off)
            local h, l = get_hi_lo(q)
            if h ~= 0 or l ~= 0 then
                local tag = ""
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then tag = " *** KERNEL PTR ***" end
                print(string.format("  +0x%03X: 0x%08X%08X%s", off, h, l, tag))
            end
        end
    end
end

-- Section D: Try sceKernelGetProcParam
print("")
print("--- SECTION D: GETPROCPARAM ---")
local dlsym_func = _G.dlsym
if dlsym_func then
    print("dlsym exists, type=" .. type(dlsym_func))
    local ok_dl, gpp_addr = pcall(dlsym_func, 0x2001, "sceKernelGetProcParam")
    print("dlsym(LIBKERNEL, sceKernelGetProcParam)=" .. tostring(gpp_addr))
    if ok_dl and gpp_addr and to_num(gpp_addr) ~= 0 then
        local gpp = fcall(gpp_addr)
        local ok_gpp, ret_gpp = pcall(gpp)
        print("sceKernelGetProcParam(): ok=" .. tostring(ok_gpp) .. " ret=" .. tostring(ret_gpp))
        if ok_gpp then
            local h, l = get_hi_lo(ret_gpp)
            print(string.format("  value=0x%08X%08X", h, l))
        end
    end
end

print("=== PROBE 125j COMPLETE ===")
