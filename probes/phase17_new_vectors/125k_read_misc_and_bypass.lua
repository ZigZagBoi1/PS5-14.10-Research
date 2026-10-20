-- CRASH_CLASS: LOW
-- PROBE 125k: Read misc.lua to find jailbreak check, try to bypass it
-- Also try direct syscall via fcall with known patterns

print("=== PROBE 125k: MISC.LUA + JAILBREAK BYPASS ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Section A: Read misc.lua source
print("--- SECTION A: MISC.LUA ---")
local f = io.open("/savedata0/misc.lua", "r")
if f then
    local content = f:read("*a")
    f:close()
    print("size=" .. #content)
    print(content)
else
    print("MISSING")
end

-- Section B: Check storage for kernel_rw and jailbreak state
print("")
print("--- SECTION B: STORAGE STATE ---")
if storage then
    print("storage exists, type=" .. type(storage))
    local keys_to_check = {"kernel_rw", "jailbroken", "jailbreak", "exploit", "kbase", "kernel_base"}
    for _, k in ipairs(keys_to_check) do
        local ok, val = pcall(storage.get, k)
        if ok then
            print("  storage[" .. k .. "]=" .. tostring(val) .. " type=" .. type(val))
        else
            print("  storage[" .. k .. "]=ERROR: " .. tostring(val))
        end
    end
    -- Try listing all storage keys
    if storage.keys then
        local ok, keys = pcall(storage.keys)
        if ok then
            print("  ALL KEYS:")
            if type(keys) == "table" then
                for i, k in ipairs(keys) do print("    " .. tostring(k)) end
            else
                print("    " .. tostring(keys))
            end
        end
    end
    if storage.list then
        local ok, keys = pcall(storage.list)
        if ok and type(keys) == "table" then
            print("  storage.list():")
            for k, v in pairs(keys) do print("    " .. tostring(k) .. "=" .. tostring(v)) end
        end
    end
end

-- Section C: Check the jailbroken global/flag
print("")
print("--- SECTION C: JAILBREAK FLAG ---")
local jb_names = {"jailbroken", "is_jailbroken", "jailbreak_state", "exploit_done"}
for _, name in ipairs(jb_names) do
    if _G[name] ~= nil then
        print("  _G." .. name .. "=" .. tostring(_G[name]))
    end
end
-- Check if there's a process.jailbroken or similar
if process then
    print("  process table exists")
    for k, v in pairs(process) do print("    " .. tostring(k) .. "=" .. tostring(v)) end
end

-- Section D: Try to call getpid via fcall + libkernel offset
-- From FreeBSD, getpid is a simple syscall wrapper
-- libkernel_base is known; we need to find the getpid stub offset
print("")
print("--- SECTION D: FCALL GETPID ---")
print("libkernel_base=" .. tostring(libkernel_base))

-- Try reading the first bytes of known libc functions to find syscall patterns
-- libc_addrofs.memcpy is readable (in libc .text which is RX? or XO?)
local memcpy_addr = libc_addrofs.memcpy
print("memcpy addr=" .. tostring(memcpy_addr))

-- Try calling memcpy as a test - copy 8 bytes from one buffer to another
local src = memory.alloc(16)
local dst = memory.alloc(16)
memory.write_dword(src, 0xDEADBEEF)
memory.write_dword(src + 4, 0xCAFEBABE)

local memcpy_fn = fcall(libc_addrofs.memcpy)
local ok, ret = pcall(memcpy_fn, dst, src, uint64(8))
print("memcpy(dst,src,8): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok then
    local v1 = memory.read_dword(dst)
    local v2 = memory.read_dword(dst + 4)
    print(string.format("  dst: 0x%08X 0x%08X", to_num(v1), to_num(v2)))
end

-- Section E: Try calling sceKernelGetCurrentCpu (no args, returns cpu id)
print("")
print("--- SECTION E: KERNEL FUNCTIONS VIA FCALL ---")
-- These are in libc_addrofs - try each one
local test_fns = {}
for k, v in pairs(libc_addrofs) do
    test_fns[#test_fns + 1] = {name=k, addr=v}
end
table.sort(test_fns, function(a,b) return a.name < b.name end)
for _, fn in ipairs(test_fns) do
    print("  " .. fn.name .. " = " .. tostring(fn.addr))
end

-- Try Thrd_create to see if we can get thread creation working via libc
-- (thr_create panics but Thrd_create might use a different path)
-- Actually too risky - skip for now

-- Section F: Try pipe creation via fcall (create_pipe global exists)
print("")
print("--- SECTION F: PIPE CREATION ---")
if create_pipe then
    print("create_pipe exists, type=" .. type(create_pipe))
    local ok_p, pipe_result = pcall(create_pipe)
    print("create_pipe(): ok=" .. tostring(ok_p) .. " ret=" .. tostring(pipe_result))
    if ok_p and type(pipe_result) == "table" then
        for k, v in pairs(pipe_result) do print("  " .. tostring(k) .. "=" .. tostring(v)) end
    end
end

print("=== PROBE 125k COMPLETE ===")
