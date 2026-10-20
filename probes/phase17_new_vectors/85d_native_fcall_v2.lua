-- CRASH_CLASS: MODERATE
-- PROBE 85d: Try native function calling through the existing ROP chain
-- The __call path works for syscalls. native.fcall_with_rax crashed.
-- From bytecode: fcall_with_rax uses native_invoke + native_cmd "fcall"
-- while __call uses execute_through_coroutine.
-- Let's try calling through the ropchain's execute_through_coroutine directly.

print("=== PROBE 85d ===")
print("pid=" .. tostring(syscall.getpid()))

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

-- The fcall chain has arg addresses. Let's write a function address
-- and use the same __call path as syscalls but with fn_addr set to a libc function

-- First, get the current values
print("--- CURRENT STATE ---")
local orig_fn = memory.read_qword(fcall.arg_addr.fn_addr)
local orig_sn = memory.read_qword(fcall.arg_addr.syscall_no)
print("fn_addr=" .. tostring(orig_fn))
print("syscall_no=" .. tostring(orig_sn))

-- The pipe's __call path writes args to arg_addr then triggers the chain
-- The chain reads fn_addr and syscall_no from arg_addr
-- If we change fn_addr and syscall_no we can call arbitrary functions

-- Test: Can we call getpid through fn_addr instead of syscall_no?
-- The chain structure from 84c shows it ends with:
-- pop rsp -> fcall_stub.fn_addr (pivot to function)
-- This means it calls whatever is at fn_addr

-- Let's try calling dlsym to resolve a function
-- dlsym = syscall 591 on PS5
print("")
print("--- DLSYM TEST ---")
-- First try via make_syscall
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

-- dynlib_dlsym = 591
-- Args: handle, nid_hash, result_addr
-- handle 0 = self
local result_addr = memory.alloc(8)
memory.write_qword(result_addr, uint64(0))

-- Try to get getpid address
local ok1, ret1 = pcall(function()
    return make_syscall(591)(uint64(0), uint64(0), uint64(result_addr))
end)
print("dlsym ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))

-- Try sys 593 to get more module info
-- dynlib_get_info = 593, we already know this works
-- Let's get info for handle 0 (self/eboot)
print("")
print("--- SELF INFO ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local ok2, ret2 = pcall(function()
    return make_syscall(593)(uint64(0), uint64(info))
end)
print("info ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
if ok2 and to_num(ret2) == 0 then
    -- Read some fields
    for off = 0, 0x15F, 8 do
        local q = memory.read_qword(info + off)
        local h, l = 0, 0
        if type(q) == "table" and q.h then h = q.h; l = q.l
        else l = to_num(q) end
        if h >= 0xFFFF8000 then
            print(string.format("KPTR +0x%03X: %s", off, tostring(q)))
        end
    end
end

-- Try getting libkernel text section entry point
-- From syscall.init bytecode: it uses find_pattern in libkernel_text
-- to find the syscall wrapper instruction (48 c7 c0 ? ? ? ? 49 89 ca 0f 05)
-- That pattern is: mov rax, <syscall_no>; mov r10, rcx; syscall

-- The syscall_address table should have the address of the syscall instruction
print("")
print("--- SYSCALL_ADDRESS ---")
if type(syscall.syscall_address) == "table" then
    for k, v in pairs(syscall.syscall_address) do
        print("SA:" .. tostring(k) .. "=" .. tostring(v))
    end
end

print("=== PROBE 85d COMPLETE ===")
