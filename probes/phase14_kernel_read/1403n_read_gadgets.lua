-- CRASH_CLASS: LOW
-- PROBE 1403n: search for memory read gadgets in eboot
--
-- Need: mov rax,[reg]; ret (or variant) for ROP chains
-- Patterns:
--   48 8B 07 C3 = mov rax,[rdi]; ret
--   48 8B 06 C3 = mov rax,[rsi]; ret
--   48 8B 01 C3 = mov rax,[rcx]; ret
--   48 8B 03 C3 = mov rax,[rbx]; ret
--   8B 07 C3    = mov eax,[rdi]; ret (32-bit)
--   8B 06 C3    = mov eax,[rsi]; ret
--   48 8B 3F C3 = mov rdi,[rdi]; ret
--   48 8B 37 C3 = mov rsi,[rdi]; ret
--   48 8B 0F C3 = mov rcx,[rdi]; ret
--
-- Also: mov rax,[rdi]; pop rbp; ret (common frame epilogue)
--   48 8B 07 5D C3
--
-- And xchg variants for counter reads:
--   48 87 07 C3 = xchg rax,[rdi]; ret

print("=== 1403n: read gadget search ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local ebn = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

local MAX = 0x494000

-- Pattern definitions: {name, bytes_array}
-- We check 3-byte and 4-byte patterns
local results = {}
local function add_hit(name, off)
    if not results[name] then results[name] = {} end
    local t = results[name]
    t[#t+1] = off
end

local scanned = 0
local prev = nil
for page = 0, MAX - 0x1000, 0x1000 do
    local test = rd(ebn + page)
    if test then
    for off = page, page + 0x1000 - 4, 4 do
        local d = rd(ebn + off)
        if not d then break end

        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- 4-byte patterns at position 0 within this dword
        -- 48 8B 07 C3 = mov rax,[rdi]; ret
        if b0==0x48 and b1==0x8B and b2==0x07 and b3==0xC3 then add_hit("mov_rax_rdi_ret", off) end
        -- 48 8B 06 C3 = mov rax,[rsi]; ret
        if b0==0x48 and b1==0x8B and b2==0x06 and b3==0xC3 then add_hit("mov_rax_rsi_ret", off) end
        -- 48 8B 01 C3 = mov rax,[rcx]; ret
        if b0==0x48 and b1==0x8B and b2==0x01 and b3==0xC3 then add_hit("mov_rax_rcx_ret", off) end
        -- 48 8B 03 C3 = mov rax,[rbx]; ret
        if b0==0x48 and b1==0x8B and b2==0x03 and b3==0xC3 then add_hit("mov_rax_rbx_ret", off) end
        -- 48 8B 3F C3 = mov rdi,[rdi]; ret
        if b0==0x48 and b1==0x8B and b2==0x3F and b3==0xC3 then add_hit("mov_rdi_rdi_ret", off) end
        -- 48 8B 37 C3 = mov rsi,[rdi]; ret
        if b0==0x48 and b1==0x8B and b2==0x37 and b3==0xC3 then add_hit("mov_rsi_rdi_ret", off) end
        -- 48 87 07 C3 = xchg rax,[rdi]; ret
        if b0==0x48 and b1==0x87 and b2==0x07 and b3==0xC3 then add_hit("xchg_rax_rdi_ret", off) end
        -- 48 8B 0F C3 = mov rcx,[rdi]; ret
        if b0==0x48 and b1==0x8B and b2==0x0F and b3==0xC3 then add_hit("mov_rcx_rdi_ret", off) end

        -- 3-byte patterns at position 0: 8B XX C3
        -- 8B 07 C3 = mov eax,[rdi]; ret (32-bit)
        if b0==0x8B and b1==0x07 and b2==0xC3 then add_hit("mov_eax_rdi_ret", off) end
        -- 8B 06 C3 = mov eax,[rsi]; ret
        if b0==0x8B and b1==0x06 and b2==0xC3 then add_hit("mov_eax_rsi_ret", off) end
        -- 8B 01 C3 = mov eax,[ecx]; ret
        if b0==0x8B and b1==0x01 and b2==0xC3 then add_hit("mov_eax_rcx_ret", off) end

        -- 3-byte at pos 1
        if b1==0x8B and b2==0x07 and b3==0xC3 then add_hit("mov_eax_rdi_ret", off+1) end
        if b1==0x8B and b2==0x06 and b3==0xC3 then add_hit("mov_eax_rsi_ret", off+1) end
        if b1==0x8B and b2==0x01 and b3==0xC3 then add_hit("mov_eax_rcx_ret", off+1) end

        -- Cross boundary with prev dword
        if prev then
            local p1 = math.floor(prev / 256) % 256
            local p2 = math.floor(prev / 65536) % 256
            local p3 = math.floor(prev / 16777216) % 256

            -- 4-byte starting at prev+1
            if p1==0x48 and p2==0x8B and p3==0x07 and b0==0xC3 then add_hit("mov_rax_rdi_ret", off-3) end
            if p1==0x48 and p2==0x8B and p3==0x06 and b0==0xC3 then add_hit("mov_rax_rsi_ret", off-3) end
            if p1==0x48 and p2==0x8B and p3==0x01 and b0==0xC3 then add_hit("mov_rax_rcx_ret", off-3) end
            if p1==0x48 and p2==0x8B and p3==0x03 and b0==0xC3 then add_hit("mov_rax_rbx_ret", off-3) end
            if p1==0x48 and p2==0x8B and p3==0x3F and b0==0xC3 then add_hit("mov_rdi_rdi_ret", off-3) end
            if p1==0x48 and p2==0x8B and p3==0x37 and b0==0xC3 then add_hit("mov_rsi_rdi_ret", off-3) end
            if p1==0x48 and p2==0x87 and p3==0x07 and b0==0xC3 then add_hit("xchg_rax_rdi_ret", off-3) end

            -- 4-byte starting at prev+2
            if p2==0x48 and p3==0x8B and b0==0x07 and b1==0xC3 then add_hit("mov_rax_rdi_ret", off-2) end
            if p2==0x48 and p3==0x8B and b0==0x06 and b1==0xC3 then add_hit("mov_rax_rsi_ret", off-2) end
            if p2==0x48 and p3==0x8B and b0==0x01 and b1==0xC3 then add_hit("mov_rax_rcx_ret", off-2) end
            if p2==0x48 and p3==0x8B and b0==0x03 and b1==0xC3 then add_hit("mov_rax_rbx_ret", off-2) end
            if p2==0x48 and p3==0x8B and b0==0x3F and b1==0xC3 then add_hit("mov_rdi_rdi_ret", off-2) end
            if p2==0x48 and p3==0x8B and b0==0x37 and b1==0xC3 then add_hit("mov_rsi_rdi_ret", off-2) end
            if p2==0x48 and p3==0x87 and b0==0x07 and b1==0xC3 then add_hit("xchg_rax_rdi_ret", off-2) end

            -- 4-byte starting at prev+3
            if p3==0x48 and b0==0x8B and b1==0x07 and b2==0xC3 then add_hit("mov_rax_rdi_ret", off-1) end
            if p3==0x48 and b0==0x8B and b1==0x06 and b2==0xC3 then add_hit("mov_rax_rsi_ret", off-1) end
            if p3==0x48 and b0==0x8B and b1==0x01 and b2==0xC3 then add_hit("mov_rax_rcx_ret", off-1) end
            if p3==0x48 and b0==0x8B and b1==0x03 and b2==0xC3 then add_hit("mov_rax_rbx_ret", off-1) end
            if p3==0x48 and b0==0x8B and b1==0x3F and b2==0xC3 then add_hit("mov_rdi_rdi_ret", off-1) end
            if p3==0x48 and b0==0x8B and b1==0x37 and b2==0xC3 then add_hit("mov_rsi_rdi_ret", off-1) end
            if p3==0x48 and b0==0x87 and b1==0x07 and b2==0xC3 then add_hit("xchg_rax_rdi_ret", off-1) end

            -- 3-byte cross boundary
            if p2==0x8B and p3==0x07 and b0==0xC3 then add_hit("mov_eax_rdi_ret", off-2) end
            if p3==0x8B and b0==0x07 and b1==0xC3 then add_hit("mov_eax_rdi_ret", off-1) end
            if p2==0x8B and p3==0x06 and b0==0xC3 then add_hit("mov_eax_rsi_ret", off-2) end
            if p3==0x8B and b0==0x06 and b1==0xC3 then add_hit("mov_eax_rsi_ret", off-1) end
        end
        prev = d
    end
    scanned = scanned + 0x1000
    end -- if test
end

-- ============================================================
-- Results
-- ============================================================
print(string.format("scanned: %d KB", scanned / 1024))
print("")

local names = {
    "mov_rax_rdi_ret", "mov_rax_rsi_ret", "mov_rax_rcx_ret", "mov_rax_rbx_ret",
    "mov_rdi_rdi_ret", "mov_rsi_rdi_ret", "mov_rcx_rdi_ret",
    "xchg_rax_rdi_ret",
    "mov_eax_rdi_ret", "mov_eax_rsi_ret", "mov_eax_rcx_ret",
}

for _, name in ipairs(names) do
    local hits = results[name] or {}
    print(string.format("%s: %d", name, #hits))
    for i = 1, math.min(#hits, 3) do
        print(string.format("  +0x%06X", hits[i]))
    end
end

print("")
print("=== 1403n DONE ===")
