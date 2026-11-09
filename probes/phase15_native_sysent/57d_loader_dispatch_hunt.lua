-- CRASH_CLASS: LOW
-- PROBE 57d: Hunt for the loader's C-level syscall dispatch implementation
--
-- Context: The Lua loader dispatches syscalls through an unknown C-level mechanism.
-- Probe 45c showed that tested calls persist after fn_addr/chain mutations, but we
-- still don't know HOW the loader actually invokes syscalls.
--
-- Strategy: Dump the CClosure structure for syscall.pipe and other syscall objects,
-- follow the function pointer chain to find the actual dispatch code, and look for
-- writable function pointers in the dispatch path.

print("=== PROBE 57d: LOADER DISPATCH HUNT ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

print("[*] Canary: probe 57d alive")

-- Step 1: Examine the pipe_str metadata
local pipe_str = tostring(syscall.pipe)
print("[*] syscall.pipe string repr:")
print("    " .. pipe_str)

-- Step 2: Get eboot base for reference
local info = memory.alloc(0x200)
local ok = pcall(function() memory.write_dword(info, 0x160) end)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
if eboot_lo and eboot_hi then
    print(string.format("[*] Eboot .text base: 0x%X%08X", eboot_hi, eboot_lo))
end

-- Step 3: Examine various syscall objects and their internal structure
print("")
print("[*] Examining syscall object types...")
local syscall_funcs = {
    {"syscall.pipe", syscall.pipe},
    {"syscall.read", syscall.read},
    {"syscall.write", syscall.write},
    {"syscall.close", syscall.close},
    {"syscall.getpid", syscall.getpid},
}

for _, pair in ipairs(syscall_funcs) do
    local name, func = pair[1], pair[2]
    if func then
        print("")
        print("[*] " .. name .. ":")
        print("    type: " .. type(func))
        print("    tostring: " .. tostring(func))

        -- Try to get the address of the function object itself
        local s = tostring(func)
        local addr_str = s:match("0x([0-9a-fA-F]+)")
        if addr_str then
            local addr = uint64("0x" .. addr_str)
            print("    Object at: 0x" .. addr_str)

            -- Dump first 64 bytes of the object
            print("    Raw dump (first 64 bytes):")
            for off = 0, 56, 8 do
                local val = safe_rq(addr + off)
                if val then
                    local h, l = get_hi_lo(val)
                    print(string.format("      +0x%02X: 0x%X%08X", off, h, l))
                end
            end
        end

        -- Check metatable
        local mt = getmetatable(func)
        if mt then
            print("    Has metatable: yes")
            print("    MT tostring: " .. tostring(mt))
            if mt.__call then
                print("    __call: " .. tostring(mt.__call))
            end
        else
            print("    Has metatable: no")
        end
    end
end

-- Step 4: Look at the resolve function itself
print("")
print("[*] Examining syscall.resolve...")
if syscall.resolve then
    print("    type: " .. type(syscall.resolve))
    print("    tostring: " .. tostring(syscall.resolve))
end

-- Step 5: Examine memory.* API objects
print("")
print("[*] Examining memory API...")
local mem_funcs = {"read_byte", "read_dword", "read_qword", "write_byte", "write_dword", "write_qword", "alloc"}
for _, name in ipairs(mem_funcs) do
    local f = memory[name]
    if f then
        print("    memory." .. name .. ": " .. tostring(f))
    end
end

-- Step 6: Scan the make_syscall object to find dispatch-related fields
print("")
print("[*] Examining make_syscall(202) object...")
local sc202 = make_syscall(202)
local s202 = tostring(sc202)
print("    tostring: " .. s202)
local addr202 = s202:match("0x([0-9a-fA-F]+)")
if addr202 then
    local a = uint64("0x" .. addr202)
    print("    Full dump (128 bytes):")
    for off = 0, 120, 8 do
        local val = safe_rq(a + off)
        if val then
            local h, l = get_hi_lo(val)
            local annotation = ""
            if h >= 0xFFFF8000 then
                annotation = " <-- KERNEL POINTER!"
            elseif eboot_hi and h == eboot_hi then
                annotation = " <-- eboot range"
            end
            print(string.format("      +0x%02X: 0x%X%08X%s", off, h, l, annotation))
        end
    end
end

-- Step 7: Check if there's a global registry of syscall handlers
print("")
print("[*] Checking global tables...")
for k, v in pairs(_G) do
    local t = type(v)
    if t == "table" and k ~= "_G" and k ~= "package" and k ~= "string" and k ~= "table"
       and k ~= "math" and k ~= "io" and k ~= "os" and k ~= "debug" and k ~= "coroutine" then
        print("    _G." .. k .. " = " .. t .. " (" .. tostring(v) .. ")")
    elseif t == "function" and k ~= "print" and k ~= "tostring" and k ~= "tonumber"
           and k ~= "type" and k ~= "pairs" and k ~= "ipairs" and k ~= "next"
           and k ~= "pcall" and k ~= "xpcall" and k ~= "error" and k ~= "require"
           and k ~= "rawget" and k ~= "rawset" and k ~= "rawequal" and k ~= "select"
           and k ~= "setmetatable" and k ~= "getmetatable" and k ~= "unpack"
           and k ~= "dofile" and k ~= "loadfile" and k ~= "loadstring" and k ~= "load"
           and k ~= "assert" and k ~= "collectgarbage" and k ~= "gcinfo"
           and k ~= "newproxy" and k ~= "setfenv" and k ~= "getfenv" then
        print("    _G." .. k .. " = " .. t .. " (" .. tostring(v) .. ")")
    end
end

print("")
print("=== PROBE 57d COMPLETE ===")
