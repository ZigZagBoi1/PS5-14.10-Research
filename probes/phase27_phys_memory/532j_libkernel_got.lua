-- CRASH_CLASS: LOW
-- PROBE 532j: Read libkernel GOT/PLT and data sections
--
-- libkernel .text is XO (can't read). But .data/.bss should be RW.
-- The GOT (Global Offset Table) contains resolved function pointers.
-- If MapDirectMemory calls a syscall stub through the GOT, we can
-- find which syscall number it uses.
--
-- Also: read the libkernel module info to find section boundaries.
-- dynlib_get_info(593) gives us text, data, relro base+size.

print("=== PROBE 532j: LIBKERNEL GOT ===")
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
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

-- Get libkernel info
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)

-- Parse dynlib_get_info results
-- Structure: see PS5 SDK headers
-- +0x000: size (4 bytes = 0x160)
-- +0x008: name (256 bytes)
-- +0x108: text base (8 bytes)
-- +0x110: text size (4 bytes)
-- +0x118: data base (8 bytes)
-- +0x120: data size (4 bytes)
-- (These offsets may vary — let's dump more fields)

local text_lo = rd(info + 0x108) or 0
local text_hi = rd(info + 0x10C) or 0
local text_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
local text_size_lo = rd(info + 0x110) or 0

local data_lo = rd(info + 0x118) or 0
local data_hi = rd(info + 0x11C) or 0
local data_base = uint64(string.format("0x%X%08X", data_hi, data_lo))
local data_size_lo = rd(info + 0x120) or 0

print("text=" .. q(text_base) .. " size=" .. string.format("0x%X", text_size_lo))
print("data=" .. q(data_base) .. " size=" .. string.format("0x%X", data_size_lo))

-- Also dump raw info buffer to see all fields
print("")
print("[RAW INFO] (first 0x160 bytes):")
local info_n = to_num(info)
for off = 0x100, 0x15C, 4 do
    local v = rd(info_n + off)
    if v then
        if v < 0 then v = v + 0x100000000 end
        if v ~= 0 then
            print(string.format("  [+0x%03X] = 0x%08X", off, v))
        end
    end
end

-- Try to read data section
print("")
print("[DATA] First 256 bytes of data section:")
local data_n = to_num(data_base)
if data_n == 0 then
    -- Try another approach: data is usually after text
    data_n = to_num(text_base) + text_size_lo
    print("  (inferred data_base = text_end = " .. string.format("0x%X", data_n) .. ")")
end

local data_readable = false
for off = 0, 0xFC, 4 do
    local v = rd(data_n + off)
    if v then
        data_readable = true
        if v < 0 then v = v + 0x100000000 end
        if v ~= 0 then
            print(string.format("  [data+0x%04X] = 0x%08X", off, v))
        end
    else
        print(string.format("  [data+0x%04X] = FAULT", off))
        break
    end
end

if not data_readable then
    print("  Data section not readable at inferred address")
end

-- Scan data section for pointers into text section (GOT entries)
-- GOT entries point to functions in .text
print("")
print("[GOT SCAN] Looking for text pointers in data section:")
local text_n = to_num(text_base)
local got_count = 0
local scan_size = math.min(data_size_lo, 0x10000)
if scan_size == 0 then scan_size = 0x10000 end  -- default

for off = 0, scan_size - 8, 8 do
    local v = rq(data_n + off)
    if v then
        local vh, vl = 0, 0
        if type(v) == "table" and v.h then
            vh = v.h; if vh < 0 then vh = vh + 0x100000000 end
            vl = v.l; if vl < 0 then vl = vl + 0x100000000 end
        else
            vl = to_num(v); if vl < 0 then vl = vl + 0x100000000 end
        end
        local vn = vh * 0x100000000 + vl
        -- Is this a pointer into libkernel text?
        if vn >= text_n and vn < text_n + text_size_lo then
            local fn_off = vn - text_n
            print(string.format("  [data+0x%04X] → text+0x%05X", off, fn_off))
            got_count = got_count + 1
            if got_count >= 40 then
                print("  (truncated at 40 entries)")
                break
            end
        end
    end
end
print("  Total GOT-like entries: " .. got_count)

-- Specifically: what's near offset 0x15020 in GOT?
-- MapDirectMemory is at text+0x15020.
-- If there's a GOT entry pointing to text+0x15020, it confirms the wrapper location.
-- But more importantly: we want to find what SYSCALL NUMBER the wrapper uses.
-- For that, we'd need to read the function bytes — which we can't (XO).
--
-- Alternative: check the PLT stubs. PLT stubs in libkernel are small
-- sequences that load from GOT and jump. They might be in the relro section.

print("")
print("=== 532j DONE ===")
