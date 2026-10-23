-- CRASH_CLASS: LOW
-- PROBE 56g2: List all modules with full name extraction
--
-- 56g only found 6 modules and missed libkernel.
-- This probe lists all 40 handles with improved name reading.

print("=== PROBE 56g2: MODULE LIST ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function rb(buf, off)
    local dw = rd(N(buf) + (off - off % 4))
    if not dw then return 0 end
    local shift = (off % 4) * 8
    return math.floor(dw / (2 ^ shift)) % 256
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc593 = mk(593)
local info = memory.alloc(0x200)

-- Try handles 0-50
for handle = 0, 50 do
    for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
    wd(N(info), 0x160)
    local ok, ret = pcall(function() return sc593(uint64(handle), info) end)
    if ok and N(ret) == 0 then
        -- Read name from offset 0x08, up to 256 bytes
        local name_bytes = {}
        for j = 0, 255 do
            local b = rb(info, 0x08 + j)
            if b == 0 then break end
            name_bytes[#name_bytes + 1] = string.char(b)
        end
        local name = table.concat(name_bytes)

        -- Read text base
        local tlo = rd(N(info) + 0x108) or 0
        local thi = rd(N(info) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end

        -- Read text size
        local slo = rd(N(info) + 0x110) or 0
        local shi = rd(N(info) + 0x114) or 0
        if slo < 0 then slo = slo + 0x100000000 end

        -- Read data base
        local dlo = rd(N(info) + 0x118) or 0
        local dhi = rd(N(info) + 0x11C) or 0
        if dlo < 0 then dlo = dlo + 0x100000000 end
        if dhi < 0 then dhi = dhi + 0x100000000 end

        print(string.format("[%2d] %-40s text=0x%X%08X size=0x%X data=0x%X%08X",
            handle, name, thi, tlo, slo, dhi, dlo))
    end
end

-- Also dump the first 0x160 bytes of info struct for handle 0 (eboot)
-- to see the full layout
print("")
print("--- info struct layout for eboot (handle 0) ---")
for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
wd(N(info), 0x160)
pcall(function() sc593(uint64(0), info) end)

for row = 0x100, 0x15F, 16 do
    local hex = {}
    for j = 0, 15 do
        local b = rb(info, row + j)
        hex[#hex + 1] = string.format("%02X", b)
    end
    print(string.format("  +%03X: %s", row, table.concat(hex, " ")))
end

print("")
print("=== 56g2 COMPLETE ===")
