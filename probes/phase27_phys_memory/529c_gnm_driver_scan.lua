-- CRASH_CLASS: LOW
-- PROBE 529c: Scan libSceGnmDriverForNeoMode.sprx text section
--
-- 528z found GnmDriver at text=0x82B660000, size=0xC000 (48 KB).
-- This module handles GPU command submission.
-- Scan for:
-- 1. syscall instructions (0F 05) — find which syscalls it uses
-- 2. Function prologues (55 48 89 E5) — identify functions
-- 3. References to interesting constants
-- 4. The submit function signature
--
-- eboot text is RX (readable), system libs are XO (not readable).
-- GnmDriver text — need to verify if it's RX or XO.

print("=== PROBE 529c: GNM DRIVER TEXT SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- GnmDriver text base
local GNM_TEXT = uint64("0x82B660000")
local GNM_SIZE = 0xC000  -- 48 KB

-- ============================================================
-- [A] Test if GnmDriver text is readable (RX) or XO
-- ============================================================
print("[A] GnmDriver text readability test")

local test_val = rd(N(GNM_TEXT))
if test_val then
    if test_val < 0 then test_val = test_val + 0x100000000 end
    print(string.format("  [+0x00] = 0x%08X — READABLE (RX)", test_val))
else
    print("  FAULT — XO (not readable)")
    print("  Cannot scan text section directly.")

    -- Try reading the .data section instead (always readable)
    print("")
    print("[A2] Try .data section (type=3 from 649)")
    local data_base = uint64("0x82B66C000")
    local dval = rd(N(data_base))
    if dval then
        if dval < 0 then dval = dval + 0x100000000 end
        print(string.format("  .data[+0x00] = 0x%08X — readable", dval))

        -- Scan .data for function pointers back to text
        print("  Scanning .data for pointers...")
        local ptrs = {}
        for off = 0, 0x2000 - 8, 8 do
            local v = rq(N(data_base) + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                -- Pointer into GnmDriver text?
                if vh == 8 and vl >= 0x2B660000 and vl < 0x2B66C000 then
                    local text_off = vl - 0x2B660000
                    table.insert(ptrs, {off, text_off, vh, vl})
                end
            end
        end
        print(string.format("  text pointers in .data: %d", #ptrs))
        for i, p in ipairs(ptrs) do
            if i > 40 then break end
            print(string.format("    .data[+0x%04X] -> text+0x%X", p[1], p[2]))
        end
    else
        print("  .data also faulted")
    end

    -- Also try through the export table (type=2 from 649)
    print("")
    print("[A3] Export table scan (type=2 = 0x82B668820)")
    local exp_base = uint64("0x82B668820")
    local exp_val = rd(N(exp_base))
    if exp_val then
        if exp_val < 0 then exp_val = exp_val + 0x100000000 end
        print(string.format("  export table[+0] = 0x%08X", exp_val))

        -- Export table format: array of { nid(8), func_ptr(8) } or similar
        for off = 0, 0x400 - 8, 8 do
            local v = rq(N(exp_base) + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                if vh == 8 and vl >= 0x2B660000 and vl < 0x2B66C000 then
                    local text_off = vl - 0x2B660000
                    print(string.format("    [+0x%03X] func at text+0x%04X (0x%X%08X)",
                        off, text_off, vh, vl))
                end
            end
        end
    else
        print("  export table faulted")
    end

    print("")
    print("=== 529c DONE (XO) ===")
    return
end

-- Text IS readable — full scan
print("")
print("[B] Full text section scan (48 KB)")

-- ============================================================
-- [B1] Find all syscall instructions (0F 05)
-- ============================================================
print("[B1] syscall (0F 05) locations")
local syscalls = {}
for off = 0, GNM_SIZE - 2 do
    local b1 = rd(N(GNM_TEXT) + off)
    if b1 then
        -- Check byte at offset: need individual byte reads
        -- rd gives dword, extract bytes
        if b1 < 0 then b1 = b1 + 0x100000000 end
        local byte0 = b1 % 256
        local byte1 = math.floor(b1 / 256) % 256
        local byte2 = math.floor(b1 / 65536) % 256
        local byte3 = math.floor(b1 / 16777216) % 256

        -- Check for 0F 05 at each position within the dword
        if byte0 == 0x0F and byte1 == 0x05 then
            table.insert(syscalls, off)
        end
        if byte1 == 0x0F and byte2 == 0x05 then
            table.insert(syscalls, off + 1)
        end
        if byte2 == 0x0F and byte3 == 0x05 then
            table.insert(syscalls, off + 2)
        end
    end
    -- Skip 3 bytes since we checked all 3 positions in dword
    off = off + 3
end

print(string.format("  syscall instructions: %d", #syscalls))
for i, s in ipairs(syscalls) do
    if i > 50 then break end
    -- Read surrounding context (the rax value loaded before syscall)
    -- Look backwards for "mov eax, imm32" (B8 xx xx xx xx)
    local context = ""
    for back = 1, 10 do
        local prev = rd(N(GNM_TEXT) + s - back * 4)
        if prev then
            if prev < 0 then prev = prev + 0x100000000 end
            -- Check for mov eax pattern
            local p0 = prev % 256
            if p0 == 0xB8 then -- mov eax, imm32
                local imm = math.floor(prev / 256) % 16777216
                -- Read next byte for full imm32
                local next_d = rd(N(GNM_TEXT) + s - back * 4 + 4)
                if next_d then
                    if next_d < 0 then next_d = next_d + 0x100000000 end
                    local extra = next_d % 256
                    imm = imm + extra * 16777216
                end
                context = string.format(" ← syscall %d (0x%X)", imm, imm)
                break
            end
        end
    end
    print(string.format("  text+0x%04X%s", s, context))
end

-- ============================================================
-- [B2] Function prologues (push rbp = 55 48 89 E5)
-- ============================================================
print("")
print("[B2] Function prologues")
local funcs = {}
for off = 0, GNM_SIZE - 4, 4 do
    local d = rd(N(GNM_TEXT) + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        -- 55 48 89 E5 = push rbp; mov rbp, rsp
        if d == 0xE5894855 then
            table.insert(funcs, off)
        end
        -- Also check offset by 1,2,3
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        if b1 == 0x55 then
            local next_d = rd(N(GNM_TEXT) + off + 4)
            if next_d then
                if next_d < 0 then next_d = next_d + 0x100000000 end
                local n0 = next_d % 256
                local n1 = math.floor(next_d / 256) % 256
                local n2 = math.floor(next_d / 65536) % 256
                if b2 == 0x48 and b3 == 0x89 and n0 == 0xE5 then
                    table.insert(funcs, off + 1)
                end
            end
        end
    end
end

print(string.format("  functions: %d", #funcs))
for i, f in ipairs(funcs) do
    if i > 40 then break end
    print(string.format("  text+0x%04X", f))
end

print("")
print("=== 529c DONE ===")
