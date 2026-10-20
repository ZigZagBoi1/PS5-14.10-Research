-- CRASH_CLASS: LOW
-- PROBE 86b: Bootstrap kernel R/W by wiring native.read_buffer into kernel table
-- kernel.lua:30 fails because kernel.addr.read_buffer is nil
-- We need to understand what kernel.addr expects and wire it up

print("=== PROBE 86b ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Dump kernel.addr contents
print("--- KERNEL.ADDR ---")
if kernel and kernel.addr then
    local count = 0
    for k, v in pairs(kernel.addr) do
        count = count + 1
        print("kernel.addr." .. tostring(k) .. "=" .. type(v) .. " " .. tostring(v))
    end
    print("total=" .. count)
    if count == 0 then print("EMPTY") end
else
    print("nil")
end

-- Dump ipv6_kernel_rw.data contents
print("")
print("--- IPV6_KERNEL_RW.DATA ---")
if ipv6_kernel_rw and ipv6_kernel_rw.data then
    local count = 0
    for k, v in pairs(ipv6_kernel_rw.data) do
        count = count + 1
        print("data." .. tostring(k) .. "=" .. type(v) .. " " .. tostring(v))
    end
    print("total=" .. count)
    if count == 0 then print("EMPTY") end
end

-- What does kernel.read_qword look like?
print("")
print("--- KERNEL.READ_QWORD SOURCE ---")
if kernel and kernel.read_qword then
    local info = debug.getinfo(kernel.read_qword, "S")
    if info then
        print("source=" .. tostring(info.source))
        print("linedefined=" .. tostring(info.linedefined))
        print("lastlinedefined=" .. tostring(info.lastlinedefined))
    end
end

-- What does native.read_buffer look like? Is it C or Lua?
print("")
print("--- NATIVE.READ_BUFFER INFO ---")
if native and native.read_buffer then
    local ok, info = pcall(debug.getinfo, native.read_buffer, "S")
    if ok and info then
        print("source=" .. tostring(info.source))
        print("what=" .. tostring(info.what))
    end
    -- Try bytecode extraction
    local ok2, dump = pcall(string.dump, native.read_buffer)
    if ok2 then
        print("is_lua=true, bytecode_len=" .. #dump)
        -- Extract strings from bytecode
        local strs = {}
        for s in dump:gmatch("[%w_%.]+") do
            if #s > 2 then strs[s] = true end
        end
        for s, _ in pairs(strs) do print("  str: " .. s) end
    else
        print("is_C=true (not dumpable)")
    end
end

-- Can native.read_buffer read from kernel VA?
-- DON'T try this blindly - it might crash
-- Instead let's check what args it takes
print("")
print("--- NATIVE.READ_BUFFER SIGNATURE ---")
-- Try with just 1 arg
local ok1, r1 = pcall(native.read_buffer, uint64(0))
print("(0) ok=" .. tostring(ok1) .. " r=" .. tostring(r1))
-- Try with addr, size
local buf = memory.alloc(16)
memory.write_dword(buf, 0x41424344)
local ok2, r2 = pcall(native.read_buffer, buf, 4)
print("(buf,4) ok=" .. tostring(ok2) .. " r=" .. tostring(r2))
if ok2 and type(r2) == "string" then
    print("  len=" .. #r2 .. " bytes=" .. string.format("%02X %02X %02X %02X", r2:byte(1,4)))
end
-- Try with uint64 addr, size
local ok3, r3 = pcall(native.read_buffer, uint64(to_num(buf)), 4)
print("(u64buf,4) ok=" .. tostring(ok3) .. " r=" .. tostring(r3))

-- Check if it uses ROP or native_invoke
print("")
print("--- READ_BUFFER BYTECODE STRINGS ---")
local ok4, dump4 = pcall(string.dump, native.read_buffer)
if ok4 then
    -- More thorough string extraction
    local pos = 1
    local found = {}
    while pos <= #dump4 - 4 do
        local len = dump4:byte(pos) + dump4:byte(pos+1)*256 + dump4:byte(pos+2)*65536 + dump4:byte(pos+3)*16777216
        if len > 3 and len < 100 and pos + 4 + len <= #dump4 then
            local s = dump4:sub(pos+4, pos+3+len)
            if s:match("^[%w_%.%:%(%)%[%]%+%-%*%/%%]+$") then
                found[#found+1] = s
            end
        end
        pos = pos + 1
    end
    for _, s in ipairs(found) do print("  " .. s) end
end

-- Try to set kernel.addr.read_buffer to native.read_buffer
print("")
print("--- WIRE KERNEL.ADDR ---")
if kernel and kernel.addr and native then
    kernel.addr.read_buffer = native.read_buffer
    kernel.addr.write_buffer = native.write_buffer
    print("wired read_buffer and write_buffer")

    -- Now try kernel.read_qword on a known heap addr
    local test = memory.alloc(8)
    memory.write_qword(test, uint64(0x123456789ABCDEF0))
    local ok5, r5 = pcall(kernel.read_qword, test)
    print("kernel.read_qword(heap) ok=" .. tostring(ok5) .. " r=" .. tostring(r5))
    if ok5 then
        local h, l = get_hi_lo(r5)
        print(string.format("h=0x%08X l=0x%08X", h, l))
    end
end

print("=== PROBE 86b COMPLETE ===")
