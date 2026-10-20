-- CRASH_CLASS: LOW
-- PROBE 85e: Isolate what crashes - step by step

print("=== PROBE 85e ===")
print("S1")
print("pid=" .. tostring(syscall.getpid()))

print("S2")
-- Read arg_addr
local fn = memory.read_qword(fcall.arg_addr.fn_addr)
print("fn=" .. tostring(fn))

print("S3")
local sn = memory.read_qword(fcall.arg_addr.syscall_no)
print("sn=" .. tostring(sn))

print("S4")
-- Try make_syscall with a safe syscall
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
print("made_sc")

print("S5")
-- Try getpid via make_syscall
local ok, ret = pcall(function()
    return make_syscall(20)()
end)
print("ms_getpid ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

print("S6")
-- Try syscall 593 via make_syscall (this worked in many earlier probes)
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local ok2, ret2 = pcall(function()
    return make_syscall(593)(uint64(1), uint64(info))
end)
print("ms_593 ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

print("S7")
-- Check syscall_address table
if syscall.syscall_address then
    local count = 0
    for k, v in pairs(syscall.syscall_address) do
        count = count + 1
        if count <= 10 then
            print("SA:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("sa_total=" .. count)
end

print("=== PROBE 85e COMPLETE ===")
