-- CRASH_CLASS: MODERATE
-- PROBE 56j: Explore native table functions safely
--
-- Context: 56i revealed 14 functions in the native table including
-- gen_fcall_chain, setup_pivot_handler, read_buffer, write_buffer,
-- create_cmd_handler etc. These look like ROP framework primitives.
-- register() crashed the process. We need to explore what these do.

print("=== PROBE 56j: NATIVE FUNCTION EXPLORATION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- SECTION A: pivot_handler_rop table (it's a table, not function)
print("")
print("--- A: PIVOT_HANDLER_ROP ---")
if type(native.pivot_handler_rop) == "table" then
    for k, v in pairs(native.pivot_handler_rop) do
        local vstr = tostring(v)
        if type(v) == "table" then
            -- Try to get address-like values
            local h, l = get_hi_lo(v)
            vstr = fmt_addr(v)
        end
        print("  " .. tostring(k) .. " = " .. vstr .. " (" .. type(v) .. ")")
    end
else
    print("  type=" .. type(native.pivot_handler_rop))
end

-- SECTION B: get_lua_opt with various keys
print("")
print("--- B: GET_LUA_OPT ---")
local opt_keys = {
    "addrofs", "libc_addrofs", "config", "debug", "version",
    "loader", "pipe", "syscall", "memory", "native", "rop",
    "chain", "Thrd_create", "Thrd_join", "Atomic_fetch_add_8",
    "gadgets", "eboot", "libkernel", "pivot", "handler",
    "cmd", "buffer", "stack", "base", "fn_addr"
}
for _, k in ipairs(opt_keys) do
    local ok, ret = pcall(function() return native.get_lua_opt(k) end)
    if ok and ret ~= nil then
        print("  " .. k .. " = " .. tostring(ret) .. " (" .. type(ret) .. ")")
    end
end

-- Try with no args
local ok_n, rn = pcall(function() return native.get_lua_opt() end)
print("  () ok=" .. tostring(ok_n) .. " ret=" .. tostring(rn))

-- SECTION C: fcall — what does it expect?
print("")
print("--- C: FCALL SIGNATURE ---")
-- Try fcall with no args (pcall for safety)
local ok_f, rf = pcall(function() return native.fcall() end)
print("fcall() ok=" .. tostring(ok_f) .. " ret=" .. tostring(rf))

-- Try fcall_with_rax: confirmed getpid works
local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt_addr(stub))
local ok_g, rg = pcall(function() return native.fcall_with_rax(stub, 20) end)
print("fcall_with_rax(stub,20) ok=" .. tostring(ok_g) .. " ret=" .. tostring(rg))

-- SECTION D: gen_fcall_chain
print("")
print("--- D: GEN_FCALL_CHAIN ---")
-- This might generate a ROP chain for function calls
-- Try with getpid (syscall 20) as a simple test
local ok_gc, rgc = pcall(function() return native.gen_fcall_chain(stub, 20) end)
print("gen_fcall_chain(stub,20) ok=" .. tostring(ok_gc) .. " ret=" .. tostring(rgc) .. " type=" .. type(rgc))

if ok_gc and type(rgc) == "table" then
    for k, v in pairs(rgc) do
        print("  " .. tostring(k) .. " = " .. tostring(v))
    end
end

-- SECTION E: read_buffer / write_buffer
print("")
print("--- E: READ/WRITE BUFFER ---")
local buf = memory.alloc(0x100)
-- Write a known pattern
for i = 0, 15 do
    pcall(function() memory.write_byte(buf + i, 0x41 + i) end)
end

-- Try read_buffer
local ok_rb, rrb = pcall(function() return native.read_buffer(buf, 16) end)
print("read_buffer(buf,16) ok=" .. tostring(ok_rb) .. " ret=" .. tostring(rrb) .. " type=" .. type(rrb))

if ok_rb and rrb then
    if type(rrb) == "string" then
        print("  len=" .. #rrb)
        local hex = {}
        for i = 1, math.min(#rrb, 32) do
            hex[#hex + 1] = string.format("%02X", rrb:byte(i))
        end
        print("  hex=" .. table.concat(hex, " "))
    elseif type(rrb) == "table" then
        for k, v in pairs(rrb) do
            print("  " .. tostring(k) .. " = " .. tostring(v))
        end
    end
end

-- Try write_buffer
local ok_wb, rwb = pcall(function() return native.write_buffer(buf + 0x20, "HELLO") end)
print("write_buffer(buf,'HELLO') ok=" .. tostring(ok_wb) .. " ret=" .. tostring(rwb))

-- SECTION F: create_cmd_handler / setup_cmd_handler
print("")
print("--- F: CMD HANDLER ---")
local ok_cc, rcc = pcall(function() return native.create_cmd_handler() end)
print("create_cmd_handler() ok=" .. tostring(ok_cc) .. " ret=" .. tostring(rcc) .. " type=" .. type(rcc))

-- SECTION G: setup_native_handler
print("")
print("--- G: NATIVE HANDLER ---")
-- This might set up a handler for native code execution
-- DON'T call it yet — just check its existence
print("setup_native_handler type=" .. type(native.setup_native_handler))

-- SECTION H: gen_read_buffer_chain / gen_write_buffer_chain
print("")
print("--- H: BUFFER CHAINS ---")
local ok_rbc, rrbc = pcall(function() return native.gen_read_buffer_chain(buf, 8) end)
print("gen_read_buffer_chain(buf,8) ok=" .. tostring(ok_rbc) .. " ret=" .. tostring(rrbc) .. " type=" .. type(rrbc))

local ok_wbc, rwbc = pcall(function() return native.gen_write_buffer_chain(buf + 0x40, 8) end)
print("gen_write_buffer_chain(buf+0x40,8) ok=" .. tostring(ok_wbc) .. " ret=" .. tostring(rwbc) .. " type=" .. type(rwbc))

-- SECTION I: setup_pivot_handler
print("")
print("--- I: PIVOT HANDLER ---")
-- Don't call setup_pivot_handler yet — it might modify state dangerously
-- Just print the ROP table contents and function type
print("setup_pivot_handler type=" .. type(native.setup_pivot_handler))
print("pivot_handler_rop type=" .. type(native.pivot_handler_rop))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56j COMPLETE ===")
