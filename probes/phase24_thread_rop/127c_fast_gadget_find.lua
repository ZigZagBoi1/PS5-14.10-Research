-- CRASH_CLASS: LOW
-- PROBE 127c: Fast gadget search using read_buffer + string.find
--
-- The dword-by-dword scan of 4.6MB eboot times out.
-- Try memory.read_buffer for bulk reads, then string ops to find patterns.
-- Fallback: qword reads in a tight loop with early-exit.
--
-- ONLY searches for:
-- 1. syscall;ret = "\x0F\x05\xC3"
-- 2. mov [rdi],rax;ret = "\x48\x89\x07\xC3"
-- 3. Also verify +0x9EC67 (alternate offset for mov gadget)

print("=== PROBE 127c: FAST GADGET FIND ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local text_size = rd(N(info) + 0x110) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
if text_size < 0 then text_size = text_size + 0x100000000 end

local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
local E = N(eboot)
print(string.format("eboot base=0x%X%08X size=0x%X", text_hi, text_lo, text_size))

-- [A] Check alternate mov [rdi],rax;ret offsets
print("")
print("[A] Checking known offsets")

local offsets_to_check = {
    {0x98C67, "mov_rdi_rax_ret (156d report)"},
    {0x9EC67, "mov_rdi_rax_ret (alt report)"},
}

for _, item in ipairs(offsets_to_check) do
    local off, label = item[1], item[2]
    if off < text_size then
        local d = rd(E + off) or 0
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256
        local match = (b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3)
        print(string.format("  +0x%X %-30s: %02X %02X %02X %02X %s",
            off, label, b0, b1, b2, b3, match and "MATCH!" or "no"))
    end
end

-- [B] Try memory.read_buffer
print("")
print("[B] Testing memory.read_buffer")
local has_read_buffer = false
local rb_ok, rb_val = pcall(function()
    return memory.read_buffer(eboot, 16)
end)
if rb_ok and type(rb_val) == "string" then
    has_read_buffer = true
    print(string.format("  read_buffer works! Got %d bytes", #rb_val))
    -- Show first bytes
    local hex = ""
    for i = 1, math.min(16, #rb_val) do
        hex = hex .. string.format("%02X ", string.byte(rb_val, i))
    end
    print("  bytes: " .. hex)
else
    print("  read_buffer failed: " .. tostring(rb_val))
    -- Try with number address
    rb_ok, rb_val = pcall(function()
        return memory.read_buffer(E, 16)
    end)
    if rb_ok and type(rb_val) == "string" then
        has_read_buffer = true
        print("  read_buffer(num) works! " .. #rb_val .. " bytes")
    else
        print("  read_buffer(num) also failed: " .. tostring(rb_val))
    end
end

-- [C] Fast search using read_buffer OR optimized dword scan
print("")
print("[C] Searching for syscall;ret and mov[rdi],rax;ret")

local syscall_ret_offsets = {}
local mov_store_offsets = {}

if has_read_buffer then
    -- FAST PATH: read_buffer + string.find
    local CHUNK = 0x10000  -- 64KB chunks
    local pat_sc = "\x0F\x05\xC3"
    local pat_mv = "\x48\x89\x07\xC3"

    for base_off = 0, text_size - CHUNK, CHUNK do
        local ok, chunk = pcall(function()
            return memory.read_buffer(uint64(string.format("0x%X%08X",
                text_hi, text_lo + base_off)), CHUNK)
        end)
        if not ok or type(chunk) ~= "string" then break end

        -- Search for syscall;ret
        local pos = 1
        while #syscall_ret_offsets < 10 do
            local found = string.find(chunk, pat_sc, pos, true)
            if not found then break end
            syscall_ret_offsets[#syscall_ret_offsets + 1] = base_off + found - 1
            pos = found + 1
        end

        -- Search for mov [rdi],rax;ret
        pos = 1
        while #mov_store_offsets < 10 do
            local found = string.find(chunk, pat_mv, pos, true)
            if not found then break end
            mov_store_offsets[#mov_store_offsets + 1] = base_off + found - 1
            pos = found + 1
        end

        if base_off % 0x80000 == 0 then
            print(string.format("  scanned 0x%X / 0x%X", base_off, text_size))
        end
    end
else
    -- SLOW PATH: optimized qword scan
    -- Only read every OTHER qword for speed (halving reads)
    -- Check all 8 byte positions for 3-byte and 4-byte patterns
    print("  using qword scan (slower)...")

    for off = 0, text_size - 8, 8 do
        local lo = rd(E + off) or 0
        local hi = rd(E + off + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end

        -- Extract all 8 bytes
        local b = {}
        b[0] = lo % 256
        b[1] = math.floor(lo / 256) % 256
        b[2] = math.floor(lo / 65536) % 256
        b[3] = math.floor(lo / 16777216) % 256
        b[4] = hi % 256
        b[5] = math.floor(hi / 256) % 256
        b[6] = math.floor(hi / 65536) % 256
        b[7] = math.floor(hi / 16777216) % 256

        -- Search for 0F 05 C3 in all positions
        if #syscall_ret_offsets < 10 then
            for i = 0, 5 do  -- positions 0-5 (need 3 bytes)
                if b[i] == 0x0F and b[i+1] == 0x05 and b[i+2] == 0xC3 then
                    syscall_ret_offsets[#syscall_ret_offsets + 1] = off + i
                end
            end
        end

        -- Search for 48 89 07 C3 in all positions
        if #mov_store_offsets < 10 then
            for i = 0, 4 do  -- positions 0-4 (need 4 bytes)
                if b[i] == 0x48 and b[i+1] == 0x89 and b[i+2] == 0x07 and b[i+3] == 0xC3 then
                    mov_store_offsets[#mov_store_offsets + 1] = off + i
                end
            end
        end

        -- Early exit
        if #syscall_ret_offsets >= 3 and #mov_store_offsets >= 3 then break end

        -- Progress + alive check every 512KB
        if off % 0x80000 == 0 and off > 0 then
            if not alive() then print("DIED!") return end
            print(string.format("  scanned 0x%X / 0x%X  sc=%d mv=%d",
                off, text_size, #syscall_ret_offsets, #mov_store_offsets))
        end
    end
end

-- Report
print("")
print("=== GADGET RESULTS ===")

local function report_list(name, list)
    if #list == 0 then
        print(string.format("  %-25s NOT FOUND", name))
    else
        local parts = {}
        for _, off in ipairs(list) do
            parts[#parts + 1] = string.format("+0x%X", off)
        end
        print(string.format("  %-25s [%d] %s", name, #list, table.concat(parts, " ")))
    end
end

report_list("syscall;ret", syscall_ret_offsets)
report_list("mov[rdi],rax;ret", mov_store_offsets)

-- [D] Verify first found gadgets
print("")
print("[D] Verification")

if #syscall_ret_offsets > 0 then
    local off = syscall_ret_offsets[1]
    local d = rd(E + off) or 0
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    print(string.format("  syscall;ret +0x%X: %02X %02X %02X %s",
        off, b0, b1, b2,
        (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "CONFIRMED" or "BAD"))
end

if #mov_store_offsets > 0 then
    local off = mov_store_offsets[1]
    local d = rd(E + off) or 0
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    print(string.format("  mov[rdi],rax;ret +0x%X: %02X %02X %02X %02X %s",
        off, b0, b1, b2, b3,
        (b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3) and "CONFIRMED" or "BAD"))
end

-- [E] Also check what fn_addr points to
print("")
print("[E] fn_addr stub")
local pipe_str = tostring(syscall.pipe)
print("  pipe: " .. pipe_str:sub(1, 200))

local fn_str = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
if fn_str then
    print("  fn_addr = " .. fn_str)
    -- Try reading bytes at fn_addr
    local fn_addr = uint64(fn_str)
    local fn_ok, fn_d = pcall(function() return memory.read_dword(fn_addr) end)
    if fn_ok then
        local d = N(fn_d)
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256
        print(string.format("  fn_addr bytes: %02X %02X %02X %02X (readable!)", b0, b1, b2, b3))
        -- Read more bytes
        for off = 0, 0x30, 4 do
            local v = rd(N(fn_addr) + off) or 0
            if v < 0 then v = v + 0x100000000 end
            local bb0 = v % 256
            local bb1 = math.floor(v / 256) % 256
            local bb2 = math.floor(v / 65536) % 256
            local bb3 = math.floor(v / 16777216) % 256
            print(string.format("    +%02X: %02X %02X %02X %02X", off, bb0, bb1, bb2, bb3))
            -- Check for syscall (0F 05)
            if bb0 == 0x0F and bb1 == 0x05 then
                print(string.format("    *** SYSCALL at fn_addr+0x%X ***", off))
            end
            if bb1 == 0x0F and bb2 == 0x05 then
                print(string.format("    *** SYSCALL at fn_addr+0x%X ***", off + 1))
            end
            if bb2 == 0x0F and bb3 == 0x05 then
                print(string.format("    *** SYSCALL at fn_addr+0x%X ***", off + 2))
            end
        end
    else
        print("  fn_addr NOT readable (XO)")
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127c COMPLETE ===")
