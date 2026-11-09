-- CRASH_CLASS: MODERATE
-- PROBE 84b: Call map_fixed_address directly, then try setup sequence
-- map_fixed_address uses syscall.resolve("mmap") - should work via Lua syscall path
-- Then manually set pivot_handler_rop.stack_base and try the init

print("=== PROBE 84b: MAP AND INIT ===")

-- Step 1: Test map_fixed_address with a safe address
print("--- MAP_FIXED_ADDRESS TEST ---")
local ok1, ret1 = pcall(function()
    -- Allocate at a specific address (0xF00000000)
    return map_fixed_address(uint64(0xF00000000), 0x4000)
end)
print("map_ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))

-- Step 2: Check if this is what pivot needs
-- setup_pivot_handler calls map_fixed_address for pivot_base
-- Then allocates stack with memory.alloc
-- Then calls fcall with setjmp to save return context

-- The problem is fcall() triggers native_invoke which does ROP pivot
-- But the ROP chain IS populated... the crash might be because
-- native_invoke tries to use pivot_handler_rop (not fcall.chain)

-- Let's check: does the loader have a simpler way to call functions?
print("")
print("--- SIMPLE CALLS ---")

-- Try using syscall.resolve to get mmap and call it
local ok2, mmap_fn = pcall(function()
    return syscall.resolve("mmap")
end)
print("resolve mmap ok=" .. tostring(ok2) .. " fn=" .. tostring(mmap_fn))

-- Try calling mmap directly through resolve
if ok2 and mmap_fn then
    local ok3, ret3 = pcall(function()
        return mmap_fn(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    print("mmap_call ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))
end

-- Try resolving setjmp
local ok4, setjmp_fn = pcall(function()
    return syscall.resolve("setjmp")
end)
print("resolve setjmp ok=" .. tostring(ok4) .. " fn=" .. tostring(setjmp_fn))

-- Try resolving other libc functions
local fns = {"getpid", "socket", "setsockopt", "close", "pipe", "read", "write"}
for _, name in ipairs(fns) do
    local ok, fn = pcall(function() return syscall.resolve(name) end)
    print("resolve " .. name .. " ok=" .. tostring(ok) .. " fn=" .. tostring(fn))
end

-- Check if syscall table has more we can use
print("")
print("--- SYSCALL TABLE ---")
if type(syscall) == "table" then
    local count = 0
    for k, v in pairs(syscall) do
        count = count + 1
        if count <= 30 then
            print("SC:" .. tostring(k) .. " " .. type(v))
        end
    end
    print("total=" .. count)
end

-- The key insight: if syscall.resolve gives us callable function objects,
-- we can call libc functions directly without the ROP chain!
-- This would let us:
-- 1. Call socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) directly
-- 2. Call setsockopt for IPV6_PKTINFO
-- 3. Set up the IPv6 overlapped sockets ourselves

print("=== PROBE 84b COMPLETE ===")
