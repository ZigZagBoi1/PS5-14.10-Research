-- CRASH_CLASS: HIGH (the number under test has killed the process twice)
-- PROBE 169a: does 668 kill only when given zero arguments?
--
-- The isolation sweep called 668 with six zero uint64 values and the process
-- died inside the call. Both lethal numbers in 661-670 (665 and 668) are the
-- ones the 13.60 capture labels nosys stubs jumping to 0x265760, and every
-- non-stub number in the range returns -1 and survives.
--
-- This probe passes a valid user page in RDI and RSI instead of zeros. If the
-- process still dies, the stub is lethal regardless of the argument shape and
-- the reason lives in the handler. If it returns, zero arguments were the
-- trigger and the stub is only lethal for that shape.
--
-- Everything before the call is printed and flushed by the loader, so a kill
-- still leaves the sentinel in the capture.

print("=== PROBE 169a: SYS 668 ARGUMENT SHAPE ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
print("[0] canary pid=" .. tostring(sc_getpid():tonumber()))

local page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
for off = 0, 0x38, 8 do safe_wq(page + off, uint64(0x4141414141414141)) end
print("[1] page=" .. string.format("0x%X", page:tonumber()))

local sc_668 = make_syscall(668)
print("[2] BEFORE sys 668 with valid pointers")
local ok, rv = pcall(function()
    return sc_668(uint64(page), uint64(page + 0x20), uint64(1),
        uint64(0), uint64(0), uint64(0))
end)
print("[2] AFTER sys 668 ok=" .. tostring(ok) .. " rv=" .. tostring(rv) ..
    " num=" .. tostring(to_num(rv)))
print("[2] page[0]=" .. tostring(page:tonumber()) ..
    " first_qword=" .. string.format("0x%X", safe_wd and 0 or 0))
print("=== PROBE 169a DONE ===")
