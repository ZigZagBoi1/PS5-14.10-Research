-- CRASH_CLASS: LOW
-- PROBE 86a: Test native.read_buffer and explore kernel R/W init path
-- The loader has native.read_buffer/write_buffer - can we call them?

print("=== PROBE 86a ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Check what native has
print("--- NATIVE TABLE ---")
if native then
    for k, v in pairs(native) do
        print("native." .. tostring(k) .. "=" .. type(v))
    end
else
    print("native=nil")
end

-- Check if read_buffer exists
print("")
print("--- READ_BUFFER ---")
if native and native.read_buffer then
    print("type=" .. type(native.read_buffer))
    -- Try reading from a known userland address (our heap)
    local buf = memory.alloc(16)
    memory.write_dword(buf, 0xDEADCAFE)
    memory.write_dword(buf + 4, 0x12345678)

    local ok, result = pcall(function()
        return native.read_buffer(buf, 8)
    end)
    print("read_heap ok=" .. tostring(ok) .. " result=" .. tostring(result))
    if ok and result then
        print("type=" .. type(result))
        if type(result) == "string" then
            print("len=" .. #result)
            for i = 1, math.min(#result, 16) do
                print(string.format("byte%d=0x%02X", i, result:byte(i)))
            end
        end
    end
else
    print("read_buffer=nil")
end

-- Check write_buffer
print("")
print("--- WRITE_BUFFER ---")
if native and native.write_buffer then
    print("type=" .. type(native.write_buffer))
else
    print("write_buffer=nil")
end

-- Check native.fcall
print("")
print("--- NATIVE.FCALL ---")
if native and native.fcall then
    print("type=" .. type(native.fcall))
    -- Don't call it - we know it crashes due to uninitialized pivot
end

-- Check kernel table
print("")
print("--- KERNEL TABLE ---")
if kernel then
    for k, v in pairs(kernel) do
        print("kernel." .. tostring(k) .. "=" .. type(v))
    end
else
    print("kernel=nil")
end

-- Check if kernel.read_qword works (it needs kernel R/W init)
if kernel and kernel.read_qword then
    print("")
    print("--- KERNEL.READ_QWORD ---")
    local ok, ret = pcall(function()
        return kernel.read_qword(memory.alloc(8))
    end)
    print("ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
end

-- Check ipv6_kernel_rw
print("")
print("--- IPV6_KERNEL_RW ---")
if ipv6_kernel_rw then
    for k, v in pairs(ipv6_kernel_rw) do
        local vs = tostring(v)
        if #vs > 80 then vs = vs:sub(1, 80) .. "..." end
        print("ipv6." .. tostring(k) .. "=" .. type(v) .. " " .. vs)
    end
end

-- Check get_fd_data_addr - needed for IPv6 exploit
print("")
print("--- GET_FD_DATA_ADDR ---")
if ipv6_kernel_rw and ipv6_kernel_rw.get_fd_data_addr then
    print("exists, type=" .. type(ipv6_kernel_rw.get_fd_data_addr))
    -- This needs kernel read, so it won't work yet
end

-- Try to find our proc struct address via sysctl
-- On FreeBSD, kinfo_proc has ki_paddr at offset 0x00 which IS the kernel proc pointer
-- But PS5 14.10 sanitizes it. Let's check the exact value.
print("")
print("--- KINFO_PROC ki_paddr ---")
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local mib = memory.alloc(16)
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 1)
memory.write_dword(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
memory.write_qword(oldlenp, uint64(0x800))
local ret = make_syscall(202)(uint64(mib), uint64(4), uint64(outbuf),
    uint64(oldlenp), uint64(0), uint64(0))
print("sysctl ret=" .. tostring(ret))
-- ki_paddr should be at offset 0 in kinfo_proc (FreeBSD)
local paddr = memory.read_qword(outbuf)
print("ki_paddr=" .. tostring(paddr))
local h, l = get_hi_lo(paddr)
print(string.format("h=0x%08X l=0x%08X", h, l))
-- Check first 64 bytes for anything interesting
for off = 0, 56, 8 do
    local q = memory.read_qword(outbuf + off)
    local qh, ql = get_hi_lo(q)
    print(string.format("+0x%02X: h=0x%08X l=0x%08X %s", off, qh, ql, tostring(q)))
end

print("=== PROBE 86a COMPLETE ===")
