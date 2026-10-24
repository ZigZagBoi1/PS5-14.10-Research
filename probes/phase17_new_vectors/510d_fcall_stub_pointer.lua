-- CRASH_CLASS: LOW
-- PROBE 510d: what function does the loader's fcall_stub call?
--
-- 510c dumped the loader's ROP chain: it only contains eboot gadgets (pop rax,
-- pop rdi, mov [rdi],rax, pop rsp, ...) and no `syscall` instruction.  So the
-- chain must finish by jumping to a function pointer stored in the heap.
-- tostring(syscall.pipe) names two heap slots: fcall_stub.fn_addr and
-- fcall_stub.return_addr.  This reads them, plus the slots the chain copies
-- from, to recover the libkernel entry the loader uses.

print("=== PROBE 510d: fcall stub pointer ===")
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
local function q(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if not ok then return "unreadable" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end
local function rd(a)
    local ok, v = pcall(function() memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rb(a)
    local ok, v = pcall(function() memory.read_byte(a) end)
    if ok then return to_num(v) end
    return nil
end
local function bhex(a, n)
    local s = ""
    for i = 0, n - 1 do
        local b = rb(a + i)
        s = s .. (b and string.format("%02X ", b) or "-- ")
    end
    return s
end

local sc_getpid = make_syscall(20)
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")
print("[0] rop=" .. tostring(rop_str) .. " fn_slot=" .. tostring(fn_str) .. " ret_slot=" .. tostring(ret_str))
if not fn_str then print("=== DONE ==="); return end

-- prime the chain so the stub holds the current function
pcall(function() return sc_getpid() end)

local fn_slot = uint64(fn_str)
local ret_slot = ret_str and uint64(ret_str) or nil
print("[1] fn_addr slot  " .. q(fn_slot) .. "  bytes " .. bhex(fn_slot, 16))
if ret_slot then print("[1] return_addr   " .. q(ret_slot)) end

-- the code the stub points at
local target = nil
do
    local ok, v = pcall(function() return memory.read_qword(fn_slot) end)
    if ok then
        local h, l = get_hi_lo(v)
        target = l
        print(string.format("[2] fn pointer = 0x%08X_%08X", h, l))
        if h == 0 then
            print("[2] target bytes " .. bhex(target, 32))
        end
    end
end

-- dump the heap region the chain touches, both sides of the stub
print("[3] heap around fn slot:")
for off = -0x40, 0x40, 8 do
    print(string.format("    %+04X %s", off, q(fn_slot + off)))
end

-- and the source slots the chain copies from
local rop = rop_str and uint64(rop_str) or nil
if rop then
    for off = 0, 0xF8, 8 do
        local v = q(rop + off)
        print(string.format("  chain+0x%03X %s", off, v))
    end
end
print("=== DONE ===")
