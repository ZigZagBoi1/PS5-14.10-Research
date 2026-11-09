-- CRASH_CLASS: LOW
-- PROBE 80s: Hunt for syscall invocation paths in eboot
--
-- 80l found 4 syscall instructions but none followed by ret.
-- We need a way for threads to invoke syscalls. Options:
--   1. syscall; ... ; ret (with cleanup between)
--   2. A wrapper function: mov eax,NUM; syscall; ... ; ret
--   3. call [reg] gadget pointing to libkernel syscall stub
--   4. jmp [reg] to a syscall wrapper
--   5. The loader's own make_syscall dispatch (if we can find/call it)
--
-- Strategy: scan eboot .text for:
--   A) All 4 syscall locations + their surrounding bytes (what's after?)
--   B) "mov eax, IMM; syscall" patterns (syscall wrapper functions)
--   C) "call rax/call [rax]" gadgets (indirect call primitives)
--   D) Scan for int 0x80 (legacy syscall, 2 bytes: CD 80)
--   E) Look for the loader's syscall dispatch function

print("=== PROBE 80s: SYSCALL GADGET HUNT ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108) or 0
local text_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))

-- Get text size from dynlib_get_info
local text_size = rd(info + 0x110) or 0
print("[*] eboot=" .. q(eboot) .. " text_size=0x" .. string.format("%X", text_size))

-- Limit scan to 2MB max (eboot .text)
if text_size == 0 or text_size > 0x200000 then text_size = 0x200000 end

-- =================================================================
-- SECTION A: Find all syscall instructions and dump context
-- syscall = 0F 05 (2 bytes)
-- Scan using dword reads for speed, then verify with byte reads
-- =================================================================
print("")
print("=== [A] SYSCALL INSTRUCTION CONTEXT ===")

local syscall_locs = {}

-- Scan for 0F 05 using dword reads
-- 0x050F appears in dword as part of the pattern
for off = 0, text_size - 4, 4 do
    local dw = rd(eboot + off)
    if dw then
        -- Check all 3 possible alignments within the dword
        -- Byte 0-1: (dw & 0xFFFF) == 0x050F
        if (dw % 0x10000) == 0x050F then
            table.insert(syscall_locs, off)
        end
        -- Byte 1-2: ((dw >> 8) & 0xFFFF) == 0x050F
        local mid = math.floor(dw / 256) % 0x10000
        if mid == 0x050F then
            table.insert(syscall_locs, off + 1)
        end
        -- Byte 2-3: ((dw >> 16) & 0xFFFF) == 0x050F
        local hi = math.floor(dw / 65536) % 0x10000
        if hi == 0x050F then
            table.insert(syscall_locs, off + 2)
        end
    end

    if off % 0x80000 == 0 and off > 0 then
        print("[*] scanned 0x" .. string.format("%X", off) .. "...")
    end
end

print("[A] Found " .. #syscall_locs .. " syscall instructions")

-- For each syscall, dump 32 bytes before and 32 bytes after
for i, loc in ipairs(syscall_locs) do
    -- Verify it's really 0F 05
    local b0 = rb(eboot + loc)
    local b1 = rb(eboot + loc + 1)
    if b0 == 0x0F and b1 == 0x05 then
        print("")
        print(string.format("  SYSCALL #%d at eboot+0x%X:", i, loc))

        -- Dump 16 bytes before
        local before = ""
        for j = -16, -1 do
            local b = rb(eboot + loc + j)
            if b then before = before .. string.format("%02X ", b)
            else before = before .. "?? " end
        end
        print("    before: " .. before)

        -- Dump 16 bytes after (starting from 0F 05)
        local after = ""
        for j = 0, 15 do
            local b = rb(eboot + loc + j)
            if b then after = after .. string.format("%02X ", b)
            else after = after .. "?? " end
        end
        print("    bytes:  " .. after)

        -- Check what's after syscall (loc+2)
        local b2 = rb(eboot + loc + 2) or 0
        local b3 = rb(eboot + loc + 3) or 0

        if b2 == 0xC3 then
            print("    *** SYSCALL;RET FOUND! ***")
        elseif b2 == 0x48 and b3 == 0x89 then
            print("    → mov r64,r64 (result save)")
            -- Check if ret follows within 10 bytes
            for k = 2, 16 do
                if rb(eboot + loc + k) == 0xC3 then
                    print("    → ret at +" .. k .. " — USABLE WRAPPER (syscall+" .. k .. " bytes to ret)")
                    break
                end
            end
        elseif b2 == 0x73 or b2 == 0x72 then
            -- jnb/jb (carry flag check = error check after syscall)
            print("    → conditional jump (error check)")
            -- This is a typical syscall wrapper: syscall; jnb .ok; neg eax; .ok: ret
            for k = 2, 20 do
                if rb(eboot + loc + k) == 0xC3 then
                    print("    → ret at +" .. k .. " — SYSCALL WRAPPER!")
                    break
                end
            end
        elseif b2 == 0x89 then
            print("    → mov (32-bit result save)")
        elseif b2 == 0x0F and b3 == 0x82 then
            print("    → jb rel32 (long error branch)")
        elseif b2 == 0x0F and b3 == 0x83 then
            print("    → jnb rel32 (long ok branch)")
        else
            print(string.format("    → next bytes: %02X %02X", b2, b3))
        end

        -- Scan backward for mov eax,IMM (B8 xx xx xx xx) — syscall number
        for k = 2, 20 do
            local bk = rb(eboot + loc - k) or 0
            if bk == 0xB8 then
                -- mov eax, imm32
                local num = rd(eboot + loc - k + 1) or 0
                if num > 0 and num < 1000 then
                    print(string.format("    → mov eax, %d (syscall number) at -%d", num, k))
                    break
                end
            end
        end
    end
end

-- =================================================================
-- SECTION B: Scan for int 0x80 (CD 80) — legacy syscall
-- =================================================================
print("")
print("=== [B] INT 0x80 SCAN ===")

local int80_count = 0
for off = 0, text_size - 4, 4 do
    local dw = rd(eboot + off)
    if dw then
        if (dw % 0x10000) == 0x80CD then
            int80_count = int80_count + 1
            if int80_count <= 5 then
                print(string.format("  int 0x80 at eboot+0x%X", off))
            end
        end
        local mid = math.floor(dw / 256) % 0x10000
        if mid == 0x80CD then
            int80_count = int80_count + 1
            if int80_count <= 5 then
                print(string.format("  int 0x80 at eboot+0x%X", off + 1))
            end
        end
        local hi = math.floor(dw / 65536) % 0x10000
        if hi == 0x80CD then
            int80_count = int80_count + 1
            if int80_count <= 5 then
                print(string.format("  int 0x80 at eboot+0x%X", off + 2))
            end
        end
    end
end
print("[B] Found " .. int80_count .. " int 0x80 instructions")

-- =================================================================
-- SECTION C: Scan for call rax (FF D0) and jmp rax (FF E0)
-- These let us redirect to any function pointer
-- =================================================================
print("")
print("=== [C] INDIRECT CALL/JMP GADGETS ===")

local call_rax = {}
local jmp_rax = {}
local call_r = {}

for off = 0, text_size - 4, 4 do
    local dw = rd(eboot + off)
    if dw then
        -- Check all alignments
        for shift = 0, 2 do
            local w = math.floor(dw / (256 ^ shift)) % 0x10000
            local pos = off + shift

            if w == 0xD0FF then -- call rax
                table.insert(call_rax, pos)
            elseif w == 0xE0FF then -- jmp rax
                table.insert(jmp_rax, pos)
            elseif w == 0xD1FF then -- call rcx
                table.insert(call_r, {pos, "rcx"})
            elseif w == 0xD2FF then -- call rdx
                table.insert(call_r, {pos, "rdx"})
            elseif w == 0xD6FF then -- call rsi
                table.insert(call_r, {pos, "rsi"})
            elseif w == 0xD7FF then -- call rdi
                table.insert(call_r, {pos, "rdi"})
            end
        end
    end
end

print("[C] call rax: " .. #call_rax .. " found")
if #call_rax > 0 and #call_rax <= 20 then
    for _, loc in ipairs(call_rax) do
        -- Check what's after call rax
        local after = rb(eboot + loc + 2) or 0
        local suffix = ""
        if after == 0xC3 then suffix = " → RET (call rax;ret!)"
        elseif after == 0x48 then suffix = " → mov/cleanup"
        elseif after == 0x89 then suffix = " → mov" end
        print(string.format("  eboot+0x%X%s", loc, suffix))
    end
end

print("[C] jmp rax: " .. #jmp_rax .. " found")
if #jmp_rax > 0 and #jmp_rax <= 10 then
    for _, loc in ipairs(jmp_rax) do
        print(string.format("  eboot+0x%X", loc))
    end
end

print("[C] call rcx/rdx/rsi/rdi: " .. #call_r .. " found")
for _, r in ipairs(call_r) do
    if #call_r <= 10 then
        print(string.format("  eboot+0x%X: call %s", r[1], r[2]))
    end
end

-- =================================================================
-- SECTION D: Find libkernel syscall stub addresses
-- If we can get libkernel .text base (it's XO, can't read it, but
-- we know its base from dynlib_get_info), we might find the stub
-- address via exported symbol tables or relocation entries.
-- The loader must have a syscall dispatch — find it in eboot data.
-- =================================================================
print("")
print("=== [D] LIBKERNEL + LOADER DISPATCH ===")

-- Get libkernel base
local sc_info = make_syscall(593)
local libkernel_base = nil

-- Try handle 1 (usually libkernel)
for handle = 0, 5 do
    local hinfo = memory.alloc(0x200)
    wd(hinfo, 0x160)
    local ok_i = pcall(function() sc_info(uint64(handle), hinfo) end)
    if ok_i then
        local tlo = rd(hinfo + 0x108) or 0
        local thi = rd(hinfo + 0x10C) or 0
        if thi > 0 or tlo > 0 then
            local base = uint64(string.format("0x%X%08X", thi, tlo))
            print(string.format("  handle=%d: base=%s", handle, q(base)))
            if handle == 1 then
                libkernel_base = base
            end
        end
    end
end

-- Scan eboot .data/.rodata for pointers to libkernel
-- These could be import table entries pointing to syscall stubs
-- Eboot data is after .text; scan a range after text
print("")
print("  Scanning eboot data for libkernel pointers...")
local lk_ptrs = 0

-- Get data segment info from dynlib_get_info
local data_lo = rd(info + 0x128) or 0
local data_hi = rd(info + 0x12C) or 0
local data_size = rd(info + 0x130) or 0
print(string.format("  data segment: 0x%X%08X size=0x%X", data_hi, data_lo, data_size))

if data_size > 0 and data_size < 0x200000 then
    local data_base = uint64(string.format("0x%X%08X", data_hi, data_lo))
    for off = 0, data_size - 8, 8 do
        local v = rq(data_base + off)
        if v then
            local h, l = 0, 0
            if type(v) == "table" and v.h then h = v.h; l = v.l
            else l = to_num(v) end

            -- Check if this points to libkernel range
            if libkernel_base then
                local lk_h, lk_l = 0, 0
                if type(libkernel_base) == "table" and libkernel_base.h then
                    lk_h = libkernel_base.h; lk_l = libkernel_base.l
                end
                if h == lk_h and l >= lk_l and l < lk_l + 0x100000 then
                    lk_ptrs = lk_ptrs + 1
                    if lk_ptrs <= 10 then
                        print(string.format("  [D] data+0x%X → %s (libkernel+0x%X)",
                            off, q(v), l - lk_l))
                    end
                end
            end
        end

        if off % 0x40000 == 0 and off > 0 then
            print("[*] data scan: 0x" .. string.format("%X", off) .. "...")
        end
    end
end
print("[D] libkernel pointers in data: " .. lk_ptrs)

-- =================================================================
-- SECTION E: Look at the pipe_str dispatch info
-- The loader prints fn_addr and ropchain — those ARE the dispatch
-- =================================================================
print("")
print("=== [E] LOADER DISPATCH INFO ===")
local pipe_str = tostring(syscall.pipe)
-- Print first 200 chars
if #pipe_str > 200 then
    print("  pipe_str (first 200): " .. pipe_str:sub(1, 200))
else
    print("  pipe_str: " .. pipe_str)
end

local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if fn_str then print("  fn_addr: " .. fn_str) end
if rop_str then print("  ropchain: " .. rop_str) end

print("")
print("=== PROBE 80s COMPLETE ===")
