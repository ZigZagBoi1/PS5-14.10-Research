-- CRASH_CLASS: LOW
-- PROBE 123l: Upper eboot scan (2MB-4.6MB) for leave;ret, compounds, syscall
--
-- 123k found pop_rbp compound at +0xDBF40 and no leave;ret in first 2MB.
-- This scans 0x200000-0x480000 for leave;ret, compounds, and syscall (0F 05).
-- Prints hits live to survive timeout.

print("=== PROBE 123l: UPPER EBOOT SCAN ===")
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

local START = 0x200000
local STOP = 0x480000

print(string.format("--- Scanning eboot+0x%X to eboot+0x%X ---", START, STOP))

local compounds = 0
local leaves = 0
local syscalls = 0
local read_fail = nil

for off = START, STOP - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then
        read_fail = off
        break
    end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Compound: XX 31 C0 C3 (aligned)
    if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 and pop_names[b0] then
        compounds = compounds + 1
        print(string.format("  COMPOUND: +0x%06X %s; xor eax,eax; ret", off, pop_names[b0]))
    end

    -- Compound unaligned: check if 31 C0 C3 starts at b0 and prev byte is pop
    if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 and off > START then
        local prev = safe_rd(ea(off - 4))
        if prev then
            local pb3 = math.floor(prev / 16777216) % 256
            if pop_names[pb3] then
                compounds = compounds + 1
                print(string.format("  COMPOUND: +0x%06X %s; xor eax,eax; ret [u]", off-1, pop_names[pb3]))
            end
        end
    end

    -- leave;ret C9 C3
    if b0 == 0xC9 and b1 == 0xC3 then
        leaves = leaves + 1
        if leaves <= 10 then
            print(string.format("  LEAVE_RET: +0x%06X", off))
        end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leaves = leaves + 1
        if leaves <= 10 then
            print(string.format("  LEAVE_RET: +0x%06X", off+1))
        end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leaves = leaves + 1
        if leaves <= 10 then
            print(string.format("  LEAVE_RET: +0x%06X", off+2))
        end
    end

    -- syscall 0F 05
    if b0 == 0x0F and b1 == 0x05 then
        syscalls = syscalls + 1
        print(string.format("  SYSCALL: +0x%06X (next: %02X %02X)", off, b2, b3))
    end
    if b1 == 0x0F and b2 == 0x05 then
        syscalls = syscalls + 1
        print(string.format("  SYSCALL: +0x%06X (next: %02X)", off+1, b3))
    end
    if b2 == 0x0F and b3 == 0x05 then
        syscalls = syscalls + 1
        local nxt = safe_rd(ea(off + 4))
        local nb0 = nxt and (nxt % 256) or -1
        print(string.format("  SYSCALL: +0x%06X (next: %02X)", off+2, nb0))
    end
end

print("")
print("=== SUMMARY ===")
if read_fail then
    print(string.format("[!] Read failed at +0x%X (scanned %dKB)", read_fail, (read_fail - START)/1024))
else
    print(string.format("[*] Scanned %dKB", (STOP - START)/1024))
end
print(string.format("[*] Compounds: %d", compounds))
print(string.format("[*] leave;ret: %d", leaves))
print(string.format("[*] syscall (0F05): %d", syscalls))

print("")
print("=== PROBE 123l COMPLETE ===")
