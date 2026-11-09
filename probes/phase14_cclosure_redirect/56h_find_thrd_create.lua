-- CRASH_CLASS: LOW
-- Find Thrd_create, Thrd_join, Atomic_fetch_add_8 addresses
-- by scanning libkernel exports via dynlib_get_info

print("=== FIND THREADING ADDRESSES ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Get all module bases via dynlib_get_info (sys 593)
print("")
print("--- MODULE SCAN ---")

local info = memory.alloc(0x200)
local sc_info = make_syscall(593)

-- Scan module handles 0-50 looking for libkernel
for handle = 0, 50 do
    for i = 0, 0x1FF do
        pcall(function() memory.write_byte(info + i, 0) end)
    end
    pcall(function() memory.write_dword(info, 0x160) end)

    local ok, ret = pcall(function()
        return sc_info(uint64(handle), uint64(to_num(info)))
    end)
    if ok then
        local r = to_num(ret)
        if r == 0 then
            -- Read module name at offset +0x00 (after size field)
            -- Actually the struct has: size at +0, name at +4 (256 bytes)
            local name_bytes = {}
            for i = 0, 31 do
                local b = safe_rd(info + 4 + i)
                if b and b > 0 and b < 128 then
                    name_bytes[#name_bytes + 1] = string.char(b)
                else
                    break
                end
            end
            local name = table.concat(name_bytes)

            -- Read text base at +0x108
            local text_lo = safe_rd(info + 0x108)
            local text_hi = safe_rd(info + 0x10C)
            local text_addr = string.format("0x%08X_%08X", text_hi or 0, text_lo or 0)

            -- Read text size at +0x110
            local tsize_lo = safe_rd(info + 0x110)
            local tsize_hi = safe_rd(info + 0x114)

            print(string.format("  handle=%d name='%s' text=%s size=0x%X",
                handle, name, text_addr, tsize_lo or 0))
        end
    end
end

-- Check what native.addrofs would have — look at the pipe's existing addresses
print("")
print("--- PIPE/ROP ADDRESSES ---")
local pipe_str = tostring(syscall.pipe)
-- Extract a few key addresses
local fn_match = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
local rop_match = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("fn_addr=" .. tostring(fn_match))
print("rop_addr=" .. tostring(rop_match))

-- Check sys 649 for member addresses
print("")
print("--- SYS 649 MODULE MEMBERS ---")
local outbuf = memory.alloc(0x100)
for mtype = 1, 8 do
    for i = 0, 0xFF do
        pcall(function() memory.write_byte(outbuf + i, 0) end)
    end
    local ok, ret = pcall(function()
        return native.fcall_with_rax(stub, 649, 1, mtype, to_num(outbuf), 0x100)
    end)
    if ok then
        local r = to_num(ret)
        local val = safe_rq(outbuf)
        print(string.format("  handle=1 type=%d ret=%d val=%s", mtype, r, fmt_addr(val)))
    end
end

-- Look for Thrd_create in the native table's rop chain
-- The pivot_handler_rop output showed gadget addresses with labels like "Mtx_lock"
-- Let's check if native has any threading-related addresses stashed
print("")
print("--- NATIVE TABLE DEEP SCAN ---")
if native.addrofs then
    print("addrofs EXISTS (unexpected)")
    for k, v in pairs(native.addrofs) do
        print("  " .. tostring(k) .. " = " .. tostring(v))
    end
else
    print("addrofs=nil")
end

-- Check if there's a register function we can use to set up addrofs
print("")
print("native.register type=" .. type(native.register))
print("native.get_lua_opt type=" .. type(native.get_lua_opt))

-- Try calling native.register to see what it does
local ok, ret = pcall(function() return native.register() end)
print("register() => ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

local ok2, ret2 = pcall(function() return native.get_lua_opt("addrofs") end)
print("get_lua_opt('addrofs') => ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

local ok3, ret3 = pcall(function() return native.get_lua_opt("libc_addrofs") end)
print("get_lua_opt('libc_addrofs') => ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))

-- Look for known function signatures in module text
-- Thrd_create in PS5 libkernel is C11 thrd_create wrapper
-- Look at the ROP chain for clues - it has Mtx_lock at 0x9fb386f0
-- That's in a high address space, likely libkernel
print("")
print("--- LIBKERNEL BASE ESTIMATE ---")
-- From ROP chain: Mtx_lock = 0x9fb386f0
-- libkernel text base is typically Mtx_lock & ~0xFFFFF (round down to 1MB)
-- But we don't know the exact layout

-- Let's use dynlib_get_info with handle 1 (usually libkernel)
for i = 0, 0x1FF do
    pcall(function() memory.write_byte(info + i, 0) end)
end
pcall(function() memory.write_dword(info, 0x160) end)
local ok4, ret4 = pcall(function()
    return sc_info(uint64(1), uint64(to_num(info)))
end)
if ok4 and to_num(ret4) == 0 then
    local text_lo = safe_rd(info + 0x108)
    local text_hi = safe_rd(info + 0x10C)
    local text_size_lo = safe_rd(info + 0x110)
    print(string.format("handle=1 text=0x%08X_%08X size=0x%X",
        text_hi or 0, text_lo or 0, text_size_lo or 0))

    -- Read data base at +0x120
    local data_lo = safe_rd(info + 0x120)
    local data_hi = safe_rd(info + 0x124)
    local data_size_lo = safe_rd(info + 0x128)
    print(string.format("handle=1 data=0x%08X_%08X size=0x%X",
        data_hi or 0, data_lo or 0, data_size_lo or 0))
end

print("")
print("=== FIND COMPLETE ===")
