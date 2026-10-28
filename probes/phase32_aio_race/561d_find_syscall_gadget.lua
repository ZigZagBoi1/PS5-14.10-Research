-- CRASH_CLASS: LOW
-- PROBE 561d: Find syscall;ret gadget in eboot
--
-- 561c couldn't find 0F 05 C3 in first 1MB.
-- Try: 1) read from ropchain metadata, 2) wider scan, 3) check loader code

print("=== PROBE 561d: FIND SYSCALL;RET ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n-4, 4 do
        pcall(function() memory.write_dword(buf + off, 0) end)
    end
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local Z = uint64(0)
local sc20 = mk(20)
local sc593 = mk(593)

local pid = N(sc20())
print("pid=" .. pid)

-- Get eboot base + size
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(Z, info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local eb_size_lo = rd(info + 0x110) or 0
if eb_size_lo < 0 then eb_size_lo = eb_size_lo + 0x100000000 end
print(string.format("eboot=0x%X%08X size=0x%X", eb_hi, eb_lo, eb_size_lo))

-- Method 1: Extract gadget addresses from the ropchain metadata
print("")
print("--- Method 1: ropchain metadata ---")
io.flush()

local pipe_str = tostring(syscall.pipe)
print("pipe_str: " .. pipe_str:sub(1, 200))

-- Parse ropchain address
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if rop_addr_str then
    print("ropchain addr: " .. rop_addr_str)
    local rop_addr = uint64(rop_addr_str)

    -- Dump ropchain contents — the chain contains gadget addresses
    print("ropchain dump (first 64 qwords):")
    for qi = 0, 63 do
        local lo = rb(rop_addr + qi * 8) or 0
        local hi = rb(rop_addr + qi * 8 + 4) or 0
        if lo ~= 0 or hi ~= 0 then
            print(string.format("  [%2d] 0x%08X%08X", qi, hi, lo))
        end
    end
    io.flush()

    -- Look for syscall;ret: any address that when we read 3 bytes shows 0F 05 C3
    print("")
    print("checking chain entries for syscall;ret:")
    for qi = 0, 63 do
        local lo = rb(rop_addr + qi * 8) or 0
        local hi = rb(rop_addr + qi * 8 + 4) or 0
        if hi == eb_hi and lo >= eb_lo then
            -- This is an eboot address — check what instruction is there
            local addr = uint64(string.format("0x%X%08X", hi, lo))
            local inst = rb(addr)
            if inst ~= nil then
                local b0 = inst % 256
                local b1 = math.floor(inst / 256) % 256
                local b2 = math.floor(inst / 65536) % 256
                if b0 == 0x0F and b1 == 0x05 then
                    print(string.format("  [%d] 0x%08X%08X: SYSCALL! (0x%08X) b2=0x%02X",
                        qi, hi, lo, inst, b2))
                end
            end
        end
    end
end
io.flush()

-- Method 2: Check fn_addr metadata
print("")
print("--- Method 2: fn_addr ---")
io.flush()

local fn_addr_str = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
if fn_addr_str then
    print("fn_addr: " .. fn_addr_str)
    local fn_addr = uint64(fn_addr_str)
    -- Read the value at fn_addr
    local fn_lo = rb(fn_addr) or 0
    local fn_hi = rb(fn_addr + 4) or 0
    print(string.format("  *fn_addr = 0x%08X%08X", fn_hi, fn_lo))
end

-- Method 3: Scan eboot for 0F 05 in wider range, reading bytes properly
print("")
print("--- Method 3: byte scan ---")
io.flush()

-- Read 2 bytes at a time by extracting from dwords
-- Scan in 64KB chunks, check each byte pair
local found = {}
local scan_max = math.min(eb_size_lo, 0x480000)  -- 4.5MB max

-- Read dwords and check all 4 byte positions for 0F 05
local prev_byte3 = 0
for off = 0, scan_max - 4, 4 do
    local dw = rb(eboot + off)
    if dw == nil then break end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Check: prev_byte3 + b0 = 0F 05
    if prev_byte3 == 0x0F and b0 == 0x05 then
        -- syscall at off-1, check if off+1 is C3 (ret)
        if b1 == 0xC3 then
            found[#found + 1] = off - 1
            if #found <= 10 then
                print(string.format("  FOUND: eboot+0x%X (syscall;ret)", off - 1))
            end
        end
    end

    -- Check: b0 + b1 = 0F 05
    if b0 == 0x0F and b1 == 0x05 then
        if b2 == 0xC3 then
            found[#found + 1] = off
            if #found <= 10 then
                print(string.format("  FOUND: eboot+0x%X (syscall;ret)", off))
            end
        end
    end

    -- Check: b1 + b2 = 0F 05
    if b1 == 0x0F and b2 == 0x05 then
        if b3 == 0xC3 then
            found[#found + 1] = off + 1
            if #found <= 10 then
                print(string.format("  FOUND: eboot+0x%X (syscall;ret)", off + 1))
            end
        end
    end

    -- Check: b2 + b3 = 0F 05 (C3 would be in next dword)
    if b2 == 0x0F and b3 == 0x05 then
        local next_dw = rb(eboot + off + 4)
        if next_dw and (next_dw % 256) == 0xC3 then
            found[#found + 1] = off + 2
            if #found <= 10 then
                print(string.format("  FOUND: eboot+0x%X (syscall;ret)", off + 2))
            end
        end
    end

    prev_byte3 = b3

    if off > 0 and off % 0x100000 == 0 then
        print(string.format("  ...scanned %dMB, %d found", off / 0x100000, #found))
        io.flush()
    end
end

print(string.format("\nTOTAL: %d syscall;ret gadgets in %dMB",
    #found, scan_max / 0x100000))

-- Also look for just "syscall" (0F 05) without ret
-- In case the chain uses a different post-syscall gadget
if #found == 0 then
    print("\nno syscall;ret — looking for bare syscall (0F 05):")
    local bare = {}
    for off = 0, math.min(scan_max, 0x100000) - 4, 4 do
        local dw = rb(eboot + off)
        if dw == nil then break end
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        if b0 == 0x0F and b1 == 0x05 then
            bare[#bare + 1] = {off, b2}
            if #bare <= 5 then
                print(string.format("  eboot+0x%X: syscall; next=0x%02X", off, b2))
            end
        end
        if b1 == 0x0F and b2 == 0x05 then
            bare[#bare + 1] = {off + 1, b3}
            if #bare <= 5 then
                print(string.format("  eboot+0x%X: syscall; next=0x%02X", off + 1, b3))
            end
        end
    end
    print(string.format("  bare syscall in first 1MB: %d", #bare))
end

io.flush()
print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " DEAD"))
print("=== 561d DONE ===")
