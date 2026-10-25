-- CRASH_CLASS: LOW
-- PROBE 532k: Read libkernel relro/GOT section
--
-- From 532j:
--   text = 0x812478000, size 0x48000
--   data = 0x8124C0000, size 0x20000
--   sec3 = 0x8124E0000, size 0x4000 (likely .got / .relro)
--   sec4 = 0x8124E4000, size 0x38000 (likely .bss)
--
-- GOT entries should be in sec3 (.relro / .got).
-- Scan sec3 for pointers into text section.
-- Also: read the GOT-adjacent memory more carefully.
--
-- Key: if we find a GOT entry for MapDirectMemory (text+0x15020),
-- and can trace what wrapper function addresses are nearby,
-- we might identify the pattern.

print("=== PROBE 532k: LIBKERNEL RELRO ===")
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
local function get_hi_lo(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return h, l
    end
    local n = to_num(v); if n < 0 then n = n + 0x100000000 end
    return 0, n
end

-- Get libkernel info
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)

local text_base = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local text_size = rd(info + 0x110) or 0
local relro_base = uint64(string.format("0x%X%08X", rd(info + 0x12C) or 0, rd(info + 0x128) or 0))
local relro_size = rd(info + 0x130) or 0

print("text=" .. q(text_base) .. " size=0x" .. string.format("%X", text_size))
print("relro=" .. q(relro_base) .. " size=0x" .. string.format("%X", relro_size))

local text_n_hi, text_n_lo = get_hi_lo(text_base)
local text_start = text_n_hi * 0x100000000 + text_n_lo
local text_end = text_start + text_size

-- Scan relro section for text pointers (GOT entries)
print("")
print("[GOT] Scanning relro for text pointers:")
local relro_n_hi, relro_n_lo = get_hi_lo(relro_base)
local got_entries = {}
local scan_end = relro_size
if scan_end == 0 then scan_end = 0x4000 end

for off = 0, scan_end - 8, 8 do
    local v = rq(relro_base + uint64(off))
    if v then
        local vh, vl = get_hi_lo(v)
        local vn = vh * 0x100000000 + vl
        if vn >= text_start and vn < text_end then
            local fn_off = vn - text_start
            table.insert(got_entries, { relro_off = off, fn_off = fn_off })
        end
    end
end

print("  Found " .. #got_entries .. " GOT entries pointing into text")
print("")

-- Print all GOT entries with their function offsets
for i, e in ipairs(got_entries) do
    local marker = ""
    if e.fn_off == 0x15020 then marker = " *** MapDirectMemory ***" end
    if e.fn_off == 0x17EF0 then marker = " *** AllocateDirectMemory ***" end
    if e.fn_off == 0x17810 then marker = " *** GetDirectMemorySize ***" end
    print(string.format("  [relro+0x%04X] → text+0x%05X%s", e.relro_off, e.fn_off, marker))
end

-- Also scan the data section (0x20000 bytes) for text pointers
print("")
print("[DATA GOT] Scanning data section:")
local data_base = uint64(string.format("0x%X%08X", rd(info + 0x11C) or 0, rd(info + 0x118) or 0))
local data_size = rd(info + 0x120) or 0
local data_got = {}

for off = 0, math.min(data_size, 0x20000) - 8, 8 do
    local v = rq(data_base + uint64(off))
    if v then
        local vh, vl = get_hi_lo(v)
        local vn = vh * 0x100000000 + vl
        if vn >= text_start and vn < text_end then
            local fn_off = vn - text_start
            table.insert(data_got, { data_off = off, fn_off = fn_off })
        end
    end
end

print("  Found " .. #data_got .. " entries pointing into text")
for i, e in ipairs(data_got) do
    local marker = ""
    if e.fn_off == 0x15020 then marker = " *** MapDirectMemory ***" end
    if e.fn_off == 0x17EF0 then marker = " *** AllocateDirectMemory ***" end
    print(string.format("  [data+0x%05X] → text+0x%05X%s", e.data_off, e.fn_off, marker))
    if i >= 50 then print("  (truncated)"); break end
end

print("")
print("=== 532k DONE ===")
