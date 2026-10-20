-- CRASH_CLASS: LOW
-- PROBE 123o: Find ALL xor eax,eax;ret (31 C0 C3) in eboot + preceding context
--
-- 123n showed pop rbp compound crashes (rbp is callee-saved, dispatcher needs it).
-- New approach: find every 31 C0 C3 in eboot, print 8 bytes before each.
-- Some may have useful instructions before xor eax,eax;ret that don't
-- clobber callee-saved regs (rbp, rbx, r12-r15).
-- Useful prefixes: nop(90), pop rax(58), pop rcx(59), pop rdx(5A),
-- pop rsi(5E), pop rdi(5F), mov reg,reg, add/sub, etc.

print("=== PROBE 123o: XOR EAX,EAX;RET CONTEXT SCAN ===")
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
print(string.format("[*] eboot: 0x%08X_%08X", eboot_hi, eboot_lo))
if not eboot_base then print("ABORT") return end

local function ea(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Scan for 31 C0 C3 at any byte offset using aligned dword reads
-- Pattern crosses dword boundaries, so check all positions

print("--- Scanning full eboot for 31 C0 C3 ---")
print("")

local hit_count = 0
local SCAN_END = 0x480000

for off = 0, SCAN_END - 8, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then
        print(string.format("[!] Read failed at +0x%X", off))
        break
    end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Check 31 C0 C3 starting at each byte position
    local positions = {}

    -- At b0,b1,b2
    if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
        positions[#positions+1] = off
    end
    -- At b1,b2,b3
    if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then
        positions[#positions+1] = off + 1
    end

    -- Cross-boundary: b2,b3,next_b0 and b3,next_b0,next_b1
    if b2 == 0x31 and b3 == 0xC0 then
        local nxt = safe_rd(ea(off + 4))
        if nxt and (nxt % 256) == 0xC3 then
            positions[#positions+1] = off + 2
        end
    end
    if b3 == 0x31 then
        local nxt = safe_rd(ea(off + 4))
        if nxt then
            local nb0 = nxt % 256
            local nb1 = math.floor(nxt / 256) % 256
            if nb0 == 0xC0 and nb1 == 0xC3 then
                positions[#positions+1] = off + 3
            end
        end
    end

    for _, pos in ipairs(positions) do
        hit_count = hit_count + 1
        -- Read 8 bytes before this position for context
        local ctx1 = safe_rd(ea(pos - 8)) or 0
        local ctx2 = safe_rd(ea(pos - 4)) or 0

        -- Extract the 8 context bytes
        local bytes = {}
        for i = 0, 3 do
            bytes[i+1] = math.floor(ctx1 / (256^i)) % 256
        end
        for i = 0, 3 do
            bytes[i+5] = math.floor(ctx2 / (256^i)) % 256
        end

        -- The byte immediately before 31 C0 C3 is bytes[8]
        local prev = bytes[8]
        local prev2 = bytes[7]

        -- Flag interesting predecessors (caller-saved pop, useful ops)
        local tag = ""
        if prev == 0x58 then tag = " *** pop rax"
        elseif prev == 0x59 then tag = " *** pop rcx"
        elseif prev == 0x5A then tag = " *** pop rdx"
        elseif prev == 0x5E then tag = " *** pop rsi"
        elseif prev == 0x5F then tag = " *** pop rdi"
        elseif prev == 0x90 then tag = " nop"
        elseif prev == 0xC3 then tag = " ret (separate)"
        elseif prev == 0x5D then tag = " pop rbp (UNSAFE)"
        elseif prev == 0x5B then tag = " pop rbx (UNSAFE)"
        end

        local ctx_str = ""
        for i = 1, 8 do
            ctx_str = ctx_str .. string.format("%02X ", bytes[i])
        end

        if hit_count <= 60 then
            print(string.format("  [%d] +0x%06X prev8=[%s] prev=%02X%s",
                hit_count, pos, ctx_str, prev, tag))
        end
    end
end

print("")
print(string.format("=== Found %d instances of 31 C0 C3 ===", hit_count))
print("")
print("=== PROBE 123o COMPLETE ===")
