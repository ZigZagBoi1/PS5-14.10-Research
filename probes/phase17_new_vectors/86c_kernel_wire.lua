-- CRASH_CLASS: LOW
-- PROBE 86c: Wire native.read/write_buffer into kernel.addr, test kernel.read_qword

print("=== PROBE 86c ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

print("pid=" .. to_num(syscall.getpid()))

-- Step 1: Dump kernel.addr (should be empty)
print("--- kernel.addr ---")
local count = 0
for k, v in pairs(kernel.addr) do
    count = count + 1
    print(tostring(k) .. "=" .. type(v))
end
print("count=" .. count)

-- Step 2: Wire native.read_buffer/write_buffer into kernel.addr
print("")
print("--- WIRING ---")
kernel.addr.read_buffer = native.read_buffer
kernel.addr.write_buffer = native.write_buffer
print("done")

-- Step 3: Test kernel.read_qword on heap
print("")
print("--- TEST HEAP READ ---")
local test = memory.alloc(8)
memory.write_qword(test, uint64(0x0BADCAFE))
local ok1, r1 = pcall(kernel.read_qword, test)
print("ok=" .. tostring(ok1))
if ok1 then
    print("val=" .. tostring(r1))
elseif type(r1) == "string" then
    print("err=" .. r1:sub(1, 200))
end

-- Step 4: Test kernel.read_dword
print("")
print("--- TEST HEAP DWORD ---")
memory.write_dword(test, 0xDEADBEEF)
local ok2, r2 = pcall(kernel.read_dword, test)
print("ok=" .. tostring(ok2))
if ok2 then
    print("val=" .. tostring(r2))
elseif type(r2) == "string" then
    print("err=" .. r2:sub(1, 200))
end

-- Step 5: Test kernel.write_qword
print("")
print("--- TEST HEAP WRITE ---")
local ok3, r3 = pcall(kernel.write_qword, test, uint64(0xCAFEBABE))
print("ok=" .. tostring(ok3))
if ok3 then
    local readback = memory.read_qword(test)
    print("readback=" .. tostring(readback))
elseif type(r3) == "string" then
    print("err=" .. r3:sub(1, 200))
end

-- Step 6: If kernel R/W works, try to init kernel offsets
print("")
print("--- KERNEL_OFFSET ---")
if kernel_offset then
    for k, v in pairs(kernel_offset) do
        print(tostring(k) .. "=" .. tostring(v))
    end
else
    print("nil")
end

print("=== PROBE 86c COMPLETE ===")
