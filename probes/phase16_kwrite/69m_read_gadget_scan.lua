-- CRASH_CLASS: LOW
-- PROBE 69m: Eboot read-gadget scan for kernel exploitation
--
-- Scans eboot .text (RX, safe to read) for memory-read gadgets:
--   mov rax,[rdi]; mov eax,[rdi]; mov rax,[rdi+N]; mov eax,[rdi+N]
--   mov rax,[rsi]; mov rax,[rax]; xchg rax,[rdi]
--   movzx eax,byte/word [rdi]; mov rdi,[rdi] (pointer chase)
--
-- These are essential for reading kernel pointers after spray reclaim
-- and chasing pointer chains in kernel structures.

print("=== PROBE 69m: READ GADGET SCAN ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot_base=" .. fmt(eb))

-- Get text size from info struct (+0x110 = text_size)
local tslo = rd(N(ib) + 0x110) or 0
local tshi = rd(N(ib) + 0x114) or 0
if tslo < 0 then tslo = tslo + 0x100000000 end
if tshi < 0 then tshi = tshi + 0x100000000 end
local text_size = tshi * 0x100000000 + tslo
print(string.format("text_size=0x%X (%d bytes)", text_size, text_size))

-- Cap scan at 8MB to avoid runaway
if text_size == 0 or text_size > 0x800000 then
    print("text_size suspect, capping at 4.6MB (0x4A0000)")
    text_size = 0x4A0000
end

-- Byte extraction helpers (little-endian dword)
local function b0(d) return d % 256 end
local function b1(d) return math.floor(d / 256) % 256 end
local function b2(d) return math.floor(d / 65536) % 256 end
local function b3(d) return math.floor(d / 16777216) % 256 end

-- We scan by reading consecutive dwords and maintaining a sliding window
-- of 8 bytes (two dwords: cur, nxt) to match patterns up to 5 bytes.

local hits = {}
local function record(name, offset, bytes_str)
    hits[#hits + 1] = {name = name, offset = offset, bytes = bytes_str}
    print(string.format("  +0x%06X: %s [%s]", offset, name, bytes_str))
end

print("")
print("Scanning " .. string.format("0x%X", text_size) .. " bytes...")
print("")

local scan_end = text_size - 8
local prev = nil
local checked = 0
local chunk_report = 0x80000  -- report progress every 512KB

for off = 0, scan_end, 4 do
    local cur = rd(N(eb) + off)
    if cur == nil then
        -- Hit unreadable region, stop
        print(string.format("  unreadable at +0x%X, stopping scan", off))
        break
    end

    -- Normalize to unsigned
    if cur < 0 then cur = cur + 0x100000000 end

    if prev ~= nil then
        -- We have 8 bytes: prev (off-4..off-1) and cur (off..off+3)
        -- Bytes at positions: prev_b0(off-4) prev_b1(off-3) prev_b2(off-2) prev_b3(off-1) cur_b0(off) cur_b1(off+1) cur_b2(off+2) cur_b3(off+3)

        -- Check 4-byte patterns starting at each byte position within prev
        -- Position off-4: bytes are prev_b0, prev_b1, prev_b2, prev_b3
        local p0, p1, p2, p3 = b0(prev), b1(prev), b2(prev), b3(prev)
        local c0, c1, c2, c3 = b0(cur), b1(cur), b2(cur), b3(cur)

        -- ===== Patterns at offset (off - 4) =====
        -- 4-byte: p0 p1 p2 p3

        -- Pattern 1: 48 8B 07 C3 = mov rax, [rdi]; ret
        if p0 == 0x48 and p1 == 0x8B and p2 == 0x07 and p3 == 0xC3 then
            record("mov rax,[rdi]; ret", off - 4, "48 8B 07 C3")
        end
        -- Pattern 5: 48 8B 06 C3 = mov rax, [rsi]; ret
        if p0 == 0x48 and p1 == 0x8B and p2 == 0x06 and p3 == 0xC3 then
            record("mov rax,[rsi]; ret", off - 4, "48 8B 06 C3")
        end
        -- Pattern 6: 48 8B 00 C3 = mov rax, [rax]; ret
        if p0 == 0x48 and p1 == 0x8B and p2 == 0x00 and p3 == 0xC3 then
            record("mov rax,[rax]; ret", off - 4, "48 8B 00 C3")
        end
        -- Pattern 7: 48 87 07 C3 = xchg rax, [rdi]; ret
        if p0 == 0x48 and p1 == 0x87 and p2 == 0x07 and p3 == 0xC3 then
            record("xchg rax,[rdi]; ret", off - 4, "48 87 07 C3")
        end
        -- Pattern 8: 0F B6 07 C3 = movzx eax, byte [rdi]; ret
        if p0 == 0x0F and p1 == 0xB6 and p2 == 0x07 and p3 == 0xC3 then
            record("movzx eax,byte[rdi]; ret", off - 4, "0F B6 07 C3")
        end
        -- Pattern 9: 0F B7 07 C3 = movzx eax, word [rdi]; ret
        if p0 == 0x0F and p1 == 0xB7 and p2 == 0x07 and p3 == 0xC3 then
            record("movzx eax,word[rdi]; ret", off - 4, "0F B7 07 C3")
        end
        -- Pattern 10: 48 8B 3F C3 = mov rdi, [rdi]; ret
        if p0 == 0x48 and p1 == 0x8B and p2 == 0x3F and p3 == 0xC3 then
            record("mov rdi,[rdi]; ret", off - 4, "48 8B 3F C3")
        end

        -- Pattern 2: 3-byte at off-4: 8B 07 C3 = mov eax, [rdi]; ret
        -- Only if p0 != 0x48 (to avoid double-counting REX prefix patterns)
        if p0 == 0x8B and p1 == 0x07 and p2 == 0xC3 then
            record("mov eax,[rdi]; ret", off - 4, "8B 07 C3")
        end

        -- Pattern 4: 4-byte at off-4: 8B 47 XX C3 = mov eax, [rdi+disp8]; ret
        if p0 == 0x8B and p1 == 0x47 and p3 == 0xC3 then
            record(string.format("mov eax,[rdi+0x%02X]; ret", p2), off - 4,
                string.format("8B 47 %02X C3", p2))
        end

        -- ===== 5-byte pattern at off-4: p0 p1 p2 p3 c0 =====
        -- Pattern 3: 48 8B 47 XX C3 = mov rax, [rdi+disp8]; ret
        if p0 == 0x48 and p1 == 0x8B and p2 == 0x47 and c0 == 0xC3 then
            record(string.format("mov rax,[rdi+0x%02X]; ret", p3), off - 4,
                string.format("48 8B 47 %02X C3", p3))
        end

        -- ===== Patterns at offset (off - 3) =====
        -- 4-byte: p1 p2 p3 c0

        -- Pattern 1 at off-3
        if p1 == 0x48 and p2 == 0x8B and p3 == 0x07 and c0 == 0xC3 then
            record("mov rax,[rdi]; ret", off - 3, "48 8B 07 C3")
        end
        if p1 == 0x48 and p2 == 0x8B and p3 == 0x06 and c0 == 0xC3 then
            record("mov rax,[rsi]; ret", off - 3, "48 8B 06 C3")
        end
        if p1 == 0x48 and p2 == 0x8B and p3 == 0x00 and c0 == 0xC3 then
            record("mov rax,[rax]; ret", off - 3, "48 8B 00 C3")
        end
        if p1 == 0x48 and p2 == 0x87 and p3 == 0x07 and c0 == 0xC3 then
            record("xchg rax,[rdi]; ret", off - 3, "48 87 07 C3")
        end
        if p1 == 0x0F and p2 == 0xB6 and p3 == 0x07 and c0 == 0xC3 then
            record("movzx eax,byte[rdi]; ret", off - 3, "0F B6 07 C3")
        end
        if p1 == 0x0F and p2 == 0xB7 and p3 == 0x07 and c0 == 0xC3 then
            record("movzx eax,word[rdi]; ret", off - 3, "0F B7 07 C3")
        end
        if p1 == 0x48 and p2 == 0x8B and p3 == 0x3F and c0 == 0xC3 then
            record("mov rdi,[rdi]; ret", off - 3, "48 8B 3F C3")
        end
        if p1 == 0x8B and p2 == 0x07 and p3 == 0xC3 then
            record("mov eax,[rdi]; ret", off - 3, "8B 07 C3")
        end
        if p1 == 0x8B and p2 == 0x47 and c0 == 0xC3 then
            record(string.format("mov eax,[rdi+0x%02X]; ret", p3), off - 3,
                string.format("8B 47 %02X C3", p3))
        end

        -- 5-byte at off-3: p1 p2 p3 c0 c1
        if p1 == 0x48 and p2 == 0x8B and p3 == 0x47 and c1 == 0xC3 then
            record(string.format("mov rax,[rdi+0x%02X]; ret", c0), off - 3,
                string.format("48 8B 47 %02X C3", c0))
        end

        -- ===== Patterns at offset (off - 2) =====
        -- 4-byte: p2 p3 c0 c1
        if p2 == 0x48 and p3 == 0x8B and c0 == 0x07 and c1 == 0xC3 then
            record("mov rax,[rdi]; ret", off - 2, "48 8B 07 C3")
        end
        if p2 == 0x48 and p3 == 0x8B and c0 == 0x06 and c1 == 0xC3 then
            record("mov rax,[rsi]; ret", off - 2, "48 8B 06 C3")
        end
        if p2 == 0x48 and p3 == 0x8B and c0 == 0x00 and c1 == 0xC3 then
            record("mov rax,[rax]; ret", off - 2, "48 8B 00 C3")
        end
        if p2 == 0x48 and p3 == 0x87 and c0 == 0x07 and c1 == 0xC3 then
            record("xchg rax,[rdi]; ret", off - 2, "48 87 07 C3")
        end
        if p2 == 0x0F and p3 == 0xB6 and c0 == 0x07 and c1 == 0xC3 then
            record("movzx eax,byte[rdi]; ret", off - 2, "0F B6 07 C3")
        end
        if p2 == 0x0F and p3 == 0xB7 and c0 == 0x07 and c1 == 0xC3 then
            record("movzx eax,word[rdi]; ret", off - 2, "0F B7 07 C3")
        end
        if p2 == 0x48 and p3 == 0x8B and c0 == 0x3F and c1 == 0xC3 then
            record("mov rdi,[rdi]; ret", off - 2, "48 8B 3F C3")
        end
        if p2 == 0x8B and p3 == 0x07 and c0 == 0xC3 then
            record("mov eax,[rdi]; ret", off - 2, "8B 07 C3")
        end
        if p2 == 0x8B and p3 == 0x47 and c1 == 0xC3 then
            record(string.format("mov eax,[rdi+0x%02X]; ret", c0), off - 2,
                string.format("8B 47 %02X C3", c0))
        end

        -- 5-byte at off-2: p2 p3 c0 c1 c2
        if p2 == 0x48 and p3 == 0x8B and c0 == 0x47 and c2 == 0xC3 then
            record(string.format("mov rax,[rdi+0x%02X]; ret", c1), off - 2,
                string.format("48 8B 47 %02X C3", c1))
        end

        -- ===== Patterns at offset (off - 1) =====
        -- 4-byte: p3 c0 c1 c2
        if p3 == 0x48 and c0 == 0x8B and c1 == 0x07 and c2 == 0xC3 then
            record("mov rax,[rdi]; ret", off - 1, "48 8B 07 C3")
        end
        if p3 == 0x48 and c0 == 0x8B and c1 == 0x06 and c2 == 0xC3 then
            record("mov rax,[rsi]; ret", off - 1, "48 8B 06 C3")
        end
        if p3 == 0x48 and c0 == 0x8B and c1 == 0x00 and c2 == 0xC3 then
            record("mov rax,[rax]; ret", off - 1, "48 8B 00 C3")
        end
        if p3 == 0x48 and c0 == 0x87 and c1 == 0x07 and c2 == 0xC3 then
            record("xchg rax,[rdi]; ret", off - 1, "48 87 07 C3")
        end
        if p3 == 0x0F and c0 == 0xB6 and c1 == 0x07 and c2 == 0xC3 then
            record("movzx eax,byte[rdi]; ret", off - 1, "0F B6 07 C3")
        end
        if p3 == 0x0F and c0 == 0xB7 and c1 == 0x07 and c2 == 0xC3 then
            record("movzx eax,word[rdi]; ret", off - 1, "0F B7 07 C3")
        end
        if p3 == 0x48 and c0 == 0x8B and c1 == 0x3F and c2 == 0xC3 then
            record("mov rdi,[rdi]; ret", off - 1, "48 8B 3F C3")
        end
        if p3 == 0x8B and c0 == 0x07 and c1 == 0xC3 then
            record("mov eax,[rdi]; ret", off - 1, "8B 07 C3")
        end
        if p3 == 0x8B and c0 == 0x47 and c2 == 0xC3 then
            record(string.format("mov eax,[rdi+0x%02X]; ret", c1), off - 1,
                string.format("8B 47 %02X C3", c1))
        end

        -- 5-byte at off-1: p3 c0 c1 c2 c3
        if p3 == 0x48 and c0 == 0x8B and c1 == 0x47 and c3 == 0xC3 then
            record(string.format("mov rax,[rdi+0x%02X]; ret", c2), off - 1,
                string.format("48 8B 47 %02X C3", c2))
        end
    end

    prev = cur
    checked = checked + 4

    -- Progress report
    if off > 0 and off % chunk_report == 0 then
        print(string.format("  ... scanned 0x%X / 0x%X (%d hits so far)",
            off, text_size, #hits))
    end
end

-- Also scan for additional useful gadgets
print("")
print("=== ADDITIONAL WRITE GADGETS ===")
-- Already confirmed: mov [rdi],rax;ret at +0x92C67
-- Look for: mov [rdi],eax;ret (89 07 C3)
--           mov [rsi],rax;ret (48 89 06 C3)
--           add [rdi],eax;ret (01 07 C3)

prev = nil
for off = 0, scan_end, 4 do
    local cur = rd(N(eb) + off)
    if cur == nil then break end
    if cur < 0 then cur = cur + 0x100000000 end

    if prev ~= nil then
        local p0, p1, p2, p3 = b0(prev), b1(prev), b2(prev), b3(prev)
        local c0, c1, c2, c3 = b0(cur), b1(cur), b2(cur), b3(cur)

        -- Check all 4 byte-aligned positions for 3/4 byte write patterns
        local positions = {
            {off - 4, p0, p1, p2, p3, c0},
            {off - 3, p1, p2, p3, c0, c1},
            {off - 2, p2, p3, c0, c1, c2},
            {off - 1, p3, c0, c1, c2, c3},
        }
        for _, pos in ipairs(positions) do
            local o2, a, b2v, c, d, e = pos[1], pos[2], pos[3], pos[4], pos[5], pos[6]
            -- mov [rsi],rax;ret = 48 89 06 C3
            if a == 0x48 and b2v == 0x89 and c == 0x06 and d == 0xC3 then
                record("mov [rsi],rax; ret", o2, "48 89 06 C3")
            end
            -- mov [rdx],rax;ret = 48 89 02 C3
            if a == 0x48 and b2v == 0x89 and c == 0x02 and d == 0xC3 then
                record("mov [rdx],rax; ret", o2, "48 89 02 C3")
            end
            -- add [rdi],eax;ret = 01 07 C3
            if a == 0x01 and b2v == 0x07 and c == 0xC3 then
                record("add [rdi],eax; ret", o2, "01 07 C3")
            end
            -- sub [rdi],eax;ret = 29 07 C3
            if a == 0x29 and b2v == 0x07 and c == 0xC3 then
                record("sub [rdi],eax; ret", o2, "29 07 C3")
            end
            -- push rax; pop rdi; ret = 50 5F C3
            if a == 0x50 and b2v == 0x5F and c == 0xC3 then
                record("push rax; pop rdi; ret", o2, "50 5F C3")
            end
            -- xchg rax, rdi; ret = 48 97 C3
            if a == 0x48 and b2v == 0x97 and c == 0xC3 then
                record("xchg rax,rdi; ret", o2, "48 97 C3")
            end
            -- mov rdi, rax; ret = 48 89 C7 C3
            if a == 0x48 and b2v == 0x89 and c == 0xC7 and d == 0xC3 then
                record("mov rdi,rax; ret", o2, "48 89 C7 C3")
            end
            -- mov rsi, rax; ret = 48 89 C6 C3
            if a == 0x48 and b2v == 0x89 and c == 0xC6 and d == 0xC3 then
                record("mov rsi,rax; ret", o2, "48 89 C6 C3")
            end
        end
    end
    prev = cur
end

-- Summary
print("")
print("=== SUMMARY ===")
print(string.format("Total hits: %d", #hits))
print(string.format("Scanned: 0x%X bytes", checked))
print("")

-- Categorize
local cats = {}
for _, h in ipairs(hits) do
    cats[h.name] = (cats[h.name] or 0) + 1
end
local sorted = {}
for name, count in pairs(cats) do
    sorted[#sorted + 1] = {name = name, count = count}
end
table.sort(sorted, function(a, b) return a.count > b.count end)
for _, s in ipairs(sorted) do
    print(string.format("  %3d x %s", s.count, s.name))
end

-- List unique offsets for the most critical gadgets
print("")
print("=== CRITICAL GADGETS (for kernel R/W) ===")
local critical = {
    "mov rax,[rdi]; ret",
    "mov eax,[rdi]; ret",
    "mov rax,[rax]; ret",
    "mov rdi,[rdi]; ret",
    "xchg rax,[rdi]; ret",
    "push rax; pop rdi; ret",
    "xchg rax,rdi; ret",
    "mov rdi,rax; ret",
}
for _, cname in ipairs(critical) do
    local found = false
    for _, h in ipairs(hits) do
        if h.name == cname then
            if not found then
                print(string.format("  %s:", cname))
                found = true
            end
            print(string.format("    eboot+0x%06X", h.offset))
        end
    end
    if not found then
        print(string.format("  %s: NOT FOUND", cname))
    end
end

print("")
print("=== PROBE 69m COMPLETE ===")
