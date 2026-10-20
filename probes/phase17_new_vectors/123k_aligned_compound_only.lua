-- CRASH_CLASS: LOW
-- PROBE 123k: Aligned-only compound scan — print results immediately
--
-- 123j found 1 aligned compound in 1MB but timed out on cross-boundary.
-- This probe does ONLY the aligned dword scan (fast) and prints
-- results immediately. Also scans leave;ret and pop rbp;ret.

print("=== PROBE 123k: ALIGNED COMPOUND SCAN ===")
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

local pop_names = {
    [0x58] = "pop_rax", [0x59] = "pop_rcx", [0x5A] = "pop_rdx",
    [0x5B] = "pop_rbx", [0x5D] = "pop_rbp", [0x5E] = "pop_rsi",
    [0x5F] = "pop_rdi",
}

-- Single pass: aligned dword scan for compounds, leave;ret, pop rbp;ret
-- Print each hit IMMEDIATELY so we don't lose to timeout

print("--- Scanning (print hits live) ---")

local compound_count = 0
local leave_count = 0
local pop_rbp_first = nil
local read_fail_off = nil

for off = 0, 0x200000 - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then
        read_fail_off = off
        break
    end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Compound: pop XX; 31 C0 C3 at aligned position (XX 31 C0 C3)
    if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 and pop_names[b0] then
        compound_count = compound_count + 1
        print(string.format("  COMPOUND: eboot+0x%06X %s; xor eax,eax; ret", off, pop_names[b0]))
    end

    -- Also check shifted: dw has 31 C0 C3 XX pattern = compound at off-1
    -- That means: b0=31, b1=C0, b2=C3 → xor eax,eax;ret starts at off
    -- Check byte at off-1 for pop opcode
    if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 and off > 0 then
        local prev_dw = safe_rd(ea(off - 4))
        if prev_dw then
            local prev_b3 = math.floor(prev_dw / 16777216) % 256
            if pop_names[prev_b3] then
                compound_count = compound_count + 1
                print(string.format("  COMPOUND: eboot+0x%06X %s; xor eax,eax; ret [unaligned-1]",
                    off - 1, pop_names[prev_b3]))
            end
        end
    end

    -- leave;ret (C9 C3) — just count, print first 5
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then
            print(string.format("  LEAVE_RET: eboot+0x%06X", off))
        end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then
            print(string.format("  LEAVE_RET: eboot+0x%06X", off+1))
        end
    end

    -- pop rbp;ret (5D C3) first only
    if not pop_rbp_first then
        if b0 == 0x5D and b1 == 0xC3 then
            pop_rbp_first = off
            print(string.format("  POP_RBP_RET: eboot+0x%06X", off))
        end
        if b1 == 0x5D and b2 == 0xC3 then
            pop_rbp_first = off+1
            print(string.format("  POP_RBP_RET: eboot+0x%06X", off+1))
        end
    end
end

print("")
print("=== SUMMARY ===")
if read_fail_off then
    print(string.format("[*] Read failed at eboot+0x%X (scanned %dKB)", read_fail_off, read_fail_off/1024))
else
    print("[*] Scanned full 2MB")
end
print(string.format("[*] Compound gadgets: %d", compound_count))
print(string.format("[*] leave;ret: %d", leave_count))
print(string.format("[*] pop rbp;ret: %s",
    pop_rbp_first and string.format("eboot+0x%X", pop_rbp_first) or "NOT FOUND"))

if compound_count > 0 then
    print("")
    print("[*] *** COMPOUND GADGETS EXIST ***")
    print("[*] These allow clean CClosure redirect with register control!")
    print("[*] Next: test each compound gadget via CClosure redirect")
end

if leave_count > 0 and pop_rbp_first then
    print("")
    print("[*] *** STACK PIVOT PRIMITIVES AVAILABLE ***")
end

print("")
print("=== PROBE 123k COMPLETE ===")
