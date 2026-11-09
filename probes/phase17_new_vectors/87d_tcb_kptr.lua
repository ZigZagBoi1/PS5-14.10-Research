-- CRASH_CLASS: LOW
-- PROBE 87d: Extract kernel pointers from TCB/TLS area
-- FreeBSD stores thread info at FS base. On PS5, TCB is at 0x88xxxxxxxx
-- The TCB itself might contain kernel pointers (pcb, thread struct, etc.)

print("=== PROBE 87d ===")

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

-- Step 1: Get FS base via sysarch (130 = AMD64_GET_FSBASE)
print("--- FS BASE ---")
local fsbase_buf = memory.alloc(8)
memory.write_qword(fsbase_buf, uint64(0))
local ok1, ret1 = pcall(function()
    return make_syscall(165)(uint64(130), uint64(fsbase_buf))
end)
print("sysarch ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
local fsbase = memory.read_qword(fsbase_buf)
print("fsbase=" .. tostring(fsbase))

-- Step 2: If we have a valid FS base, scan it with native.read_buffer
local fh, fl = get_hi_lo(fsbase)
if fh ~= 0 or fl ~= 0 then
    print("")
    print("--- TCB SCAN ---")
    -- Read 512 bytes from FS base
    local ok2, data = pcall(native.read_buffer, fsbase, 512)
    if ok2 and data then
        print("read " .. #data .. " bytes")
        local kcount = 0
        for i = 1, #data - 7, 8 do
            local b1, b2, b3, b4, b5, b6, b7, b8 = data:byte(i, i+7)
            local lo = b1 + b2*256 + b3*65536 + b4*16777216
            local hi = b5 + b6*256 + b7*65536 + b8*16777216
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                kcount = kcount + 1
                print(string.format("  +0x%03X: KPTR 0x%08X%08X", i-1, hi, lo))
            end
            -- Also print non-zero values for context
            if (hi ~= 0 or lo ~= 0) and kcount == 0 and i <= 65 then
                print(string.format("  +0x%03X: 0x%08X%08X", i-1, hi, lo))
            end
        end
        print("kptr_count=" .. kcount)
    else
        print("read fail: " .. tostring(data))
    end

    -- Also scan negative offsets (before TCB)
    print("")
    print("--- TCB NEGATIVE ---")
    local tcb_minus = uint64(string.format("0x%X%08X", fh, fl - 256))
    local ok3, data3 = pcall(native.read_buffer, tcb_minus, 256)
    if ok3 and data3 then
        for i = 1, #data3 - 7, 8 do
            local b1, b2, b3, b4, b5, b6, b7, b8 = data3:byte(i, i+7)
            local lo = b1 + b2*256 + b3*65536 + b4*16777216
            local hi = b5 + b6*256 + b7*65536 + b8*16777216
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("  -0x%03X: KPTR 0x%08X%08X", 256-(i-1), hi, lo))
            end
        end
    end
end

-- Step 3: Also try GS base (AMD64_GET_GSBASE = 131)
print("")
print("--- GS BASE ---")
memory.write_qword(fsbase_buf, uint64(0))
local ok4, ret4 = pcall(function()
    return make_syscall(165)(uint64(131), uint64(fsbase_buf))
end)
print("sysarch ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))
local gsbase = memory.read_qword(fsbase_buf)
print("gsbase=" .. tostring(gsbase))

-- Step 4: Scan VM regions from sys 674 for any with kernel-adjacent addresses
print("")
print("--- SYS 674 FIRST REGION ---")
local outbuf = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do memory.write_dword(outbuf + i, 0) end
local ok5, ret5 = pcall(function()
    return make_syscall(674)(uint64(0), uint64(0), uint64(outbuf), uint64(0x200))
end)
print("674 ok=" .. tostring(ok5) .. " ret=" .. tostring(ret5))
if ok5 then
    -- First region: read start/end/protection
    local start_addr = memory.read_qword(outbuf)
    local end_addr = memory.read_qword(outbuf + 8)
    local prot = to_num(memory.read_dword(outbuf + 0x18))
    print("start=" .. tostring(start_addr))
    print("end=" .. tostring(end_addr))
    print(string.format("prot=0x%X", prot))
end

print("=== PROBE 87d COMPLETE ===")
