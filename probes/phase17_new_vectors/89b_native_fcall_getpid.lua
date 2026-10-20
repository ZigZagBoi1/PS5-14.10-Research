-- CRASH_CLASS: MODERATE
-- PROBE 89b: Use native.fcall with real function addresses
-- 88e crashed when calling native.fcall(0, 20) (address 0).
-- We need to find the actual getpid stub address and call that.
-- The pipe_str shows the pipe syscall instruction address.
-- native.fcall(addr, syscall_no) should work if addr is a valid instruction.

print("=== PROBE 89b: NATIVE FCALL GETPID ===")

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

print("pid=" .. to_num(syscall.getpid()))

-- Get pipe address (syscall instruction in libkernel)
local pipe_str = tostring(syscall.pipe)
print("pipe_str length=" .. #pipe_str)

-- Extract key addresses
local pipe_addr = pipe_str:match("pipe @ (0x[0-9a-fA-F]+)")
local fn_addr = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("pipe=" .. tostring(pipe_addr))
print("fn_addr=" .. tostring(fn_addr))
print("rop=" .. tostring(rop_addr))

-- Get libkernel text base (the syscall instruction is here)
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local text_size = to_num(memory.read_dword(info + 0x110))
print(string.format("lk_text=0x%X%08X size=0x%X", text_hi, text_lo, text_size))

-- Examine native module
print("")
print("--- NATIVE MODULE ---")
local keys = {}
for k, v in pairs(native) do
    keys[#keys+1] = k .. "=" .. type(v)
end
table.sort(keys)
for _, kv in ipairs(keys) do print("  " .. kv) end

-- Check native.fcall signature by examining it
print("")
print("native.fcall type=" .. type(native.fcall))
print("native.invoke type=" .. type(native.invoke))

-- Try native.fcall with the pipe address (which is a valid syscall;ret gadget)
-- native.fcall(fn_addr_value, syscall_number) based on how the ROP works
if pipe_addr then
    local pa = uint64(pipe_addr)
    print("pipe_addr_uint64=" .. tostring(pa))

    -- Read bytes at pipe address to confirm it's a syscall instruction
    local ok, data = pcall(native.read_buffer, pa, 4)
    if ok and data then
        local bytes = ""
        for i = 1, #data do
            bytes = bytes .. string.format("%02X ", data:byte(i))
        end
        print("pipe_bytes: " .. bytes)
    else
        print("pipe_bytes: unreadable (XO)")
    end
end

-- Try native.fcall with getpid (syscall 20)
-- The fn_addr from pipe_str points to the pipe impl
-- We need to understand what native.fcall expects
print("")
print("--- FCALL TEST ---")
if fn_addr then
    local fa = uint64(fn_addr)
    print("testing native.fcall with fn_addr=" .. tostring(fa))

    -- First try: native.fcall(fn_addr, 20) for getpid
    local ok1, ret1 = pcall(native.fcall, fa, 20)
    print("fcall(fn_addr,20) ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))

    if ok1 then
        print("  ret_type=" .. type(ret1))
        if type(ret1) == "table" then
            for k,v in pairs(ret1) do print("  ." .. tostring(k) .. "=" .. tostring(v)) end
        end
    end
end

print("=== PROBE 89b COMPLETE ===")
