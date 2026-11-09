-- CRASH_CLASS: LOW
-- PROBE 80l: Eboot .text ROP gadget scan
--
-- Context: We have arbitrary thread code execution via thr_create(430) with ROP.
-- We need more gadgets, especially syscall;ret (0F 05 C3) for kernel calls
-- from thread ROP chains with full register control.
--
-- Strategy: Scan eboot .text in 64KB chunks, printing progress to avoid
-- 30-second idle timeout. Only reads RX memory (safe).

print("=== PROBE 80l: EBOOT GADGET SCAN ===")
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

-- Read one byte safely
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- [A] Get eboot base via dynlib_get_info(593), handle 0
print("[A] Getting eboot base...")
local info = memory.alloc(0x200)
safe_rd(info) -- touch
for i = 0, 0x1FF, 4 do
    pcall(function() memory.write_dword(info + i, 0) end)
end
pcall(function() memory.write_dword(info, 0x160) end)

local sc_info = make_syscall(593)
local ret = nil
pcall(function() ret = sc_info(uint64(0), info) end)
print("dynlib_get_info ret: " .. tostring(ret))

local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_size_lo = safe_rd(info + 0x110)
local text_size_hi = safe_rd(info + 0x114)

if not text_lo or not text_hi then
    print("FAILED to get eboot base")
    return
end

local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
local text_size = text_size_lo or 0
if text_size_hi and text_size_hi > 0 then
    text_size = 0x200000 -- cap at 2MB
end
if text_size == 0 then text_size = 0x200000 end
-- Cap scan to 2MB to be safe
if text_size > 0x200000 then text_size = 0x200000 end

print(string.format("eboot .text base: 0x%X%08X", text_hi, text_lo))
print(string.format("eboot .text size: 0x%X", text_size))
print("")

-- [B] Gadget definitions
-- Each entry: {name, bytes_table, context_bytes_after}
-- context_bytes_after: how many bytes after the match to print for context
local gadgets = {
    {"syscall;ret",        {0x0F, 0x05, 0xC3}, 0},
    {"syscall",            {0x0F, 0x05},        4},  -- print 4 bytes after for context
    {"int80;ret",          {0xCD, 0x80, 0xC3}, 0},
    {"mov rax,[rdi];ret",  {0x48, 0x8B, 0x07, 0xC3}, 0},
    {"mov rax,[rsi];ret",  {0x48, 0x8B, 0x06, 0xC3}, 0},
    {"mov rax,[rdx];ret",  {0x48, 0x8B, 0x02, 0xC3}, 0},
    {"mov [rsi],rax;ret",  {0x48, 0x89, 0x06, 0xC3}, 0},
    {"mov [rdx],rax;ret",  {0x48, 0x89, 0x02, 0xC3}, 0},
    {"mov [rsi],edi;ret",  {0x89, 0x3E, 0xC3}, 0},
    {"mov rdi,rax;ret",    {0x48, 0x89, 0xC7, 0xC3}, 0},
    {"mov rsi,rax;ret",    {0x48, 0x89, 0xC6, 0xC3}, 0},
    {"mov rdx,rax;ret",    {0x48, 0x89, 0xC2, 0xC3}, 0},
    {"xchg rax,rdi;ret",   {0x48, 0x97, 0xC3}, 0},
    {"xchg rax,rsi;ret",   {0x48, 0x96, 0xC3}, 0},
    {"xchg rax,rdx;ret",   {0x48, 0x92, 0xC3}, 0},
    {"xchg rax,rcx;ret",   {0x48, 0x91, 0xC3}, 0},
    {"xchg rax,rsp;ret",   {0x48, 0x94, 0xC3}, 0},  -- stack pivot!
    {"push rax;ret",       {0x50, 0xC3}, 0},
    {"push rdi;ret",       {0x57, 0xC3}, 0},
    {"push rsp;ret",       {0x54, 0xC3}, 0},
    {"pop rdx;ret",        {0x5A, 0xC3}, 0},
    {"pop rbx;ret",        {0x5B, 0xC3}, 0},
    {"pop rbp;ret",        {0x5D, 0xC3}, 0},
    {"pop r8;ret",         {0x41, 0x58, 0xC3}, 0},
    {"pop r9;ret",         {0x41, 0x59, 0xC3}, 0},
    {"pop r10;ret",        {0x41, 0x5A, 0xC3}, 0},
    {"pop rdi;pop rsi;ret",{0x5F, 0x5E, 0xC3}, 0},
    {"pop rsi;pop rdi;ret",{0x5E, 0x5F, 0xC3}, 0},
    {"pop rdi;pop rsi;pop rdx;ret", {0x5F, 0x5E, 0x5A, 0xC3}, 0},
    {"mov rax,rdi;ret",    {0x48, 0x89, 0xF8, 0xC3}, 0},
    {"add rsp,8;ret",      {0x48, 0x83, 0xC4, 0x08, 0xC3}, 0},
    {"add rsp,0x10;ret",   {0x48, 0x83, 0xC4, 0x10, 0xC3}, 0},
    {"add rsp,0x18;ret",   {0x48, 0x83, 0xC4, 0x18, 0xC3}, 0},
    {"add rsp,0x20;ret",   {0x48, 0x83, 0xC4, 0x20, 0xC3}, 0},
    {"add rsp,0x28;ret",   {0x48, 0x83, 0xC4, 0x28, 0xC3}, 0},
    {"add rsp,0x30;ret",   {0x48, 0x83, 0xC4, 0x30, 0xC3}, 0},
    {"add rsp,0x38;ret",   {0x48, 0x83, 0xC4, 0x38, 0xC3}, 0},
    {"add rsp,0x40;ret",   {0x48, 0x83, 0xC4, 0x40, 0xC3}, 0},
    {"add rsp,0x48;ret",   {0x48, 0x83, 0xC4, 0x48, 0xC3}, 0},
    {"add rsp,0x50;ret",   {0x48, 0x83, 0xC4, 0x50, 0xC3}, 0},
    {"add rsp,0x58;ret",   {0x48, 0x83, 0xC4, 0x58, 0xC3}, 0},
    {"add rsp,0x60;ret",   {0x48, 0x83, 0xC4, 0x60, 0xC3}, 0},
    {"add rsp,0x68;ret",   {0x48, 0x83, 0xC4, 0x68, 0xC3}, 0},
    {"add rsp,0x78;ret",   {0x48, 0x83, 0xC4, 0x78, 0xC3}, 0},
    {"lea rax,[rdi+N];ret",{0x48, 0x8D, 0x47}, 1},  -- +1 byte offset + C3
    {"mov eax,edi;ret",    {0x89, 0xF8, 0xC3}, 0},
    {"mov eax,[rdi];ret",  {0x8B, 0x07, 0xC3}, 0},
    {"mov [rdi],esi;ret",  {0x89, 0x37, 0xC3}, 0},
    {"mov [rdi],rsi;ret",  {0x48, 0x89, 0x37, 0xC3}, 0},
}

-- [C] Scan using dword reads for speed, byte-check on matches
print("[B] Scanning eboot .text for gadgets...")
print(string.format("Scanning 0x%X bytes in 64KB chunks", text_size))
print("")

local CHUNK = 0x10000  -- 64KB
local found_count = 0
local found_map = {} -- gadget_name -> list of offsets

-- For speed: read dwords and check bytes within them
-- But we need byte-level alignment, so read dwords overlapping
-- Actually, let's use read_dword for speed: read 4 bytes at a time,
-- extract individual bytes, and slide a window

for chunk_start = 0, text_size - 1, CHUNK do
    local chunk_end = chunk_start + CHUNK
    if chunk_end > text_size then chunk_end = text_size end

    -- Progress heartbeat
    print(string.format("[SCAN] chunk 0x%X - 0x%X (%d%% done, %d gadgets found)",
        chunk_start, chunk_end, math.floor(chunk_start * 100 / text_size), found_count))

    -- Read chunk using dwords for speed
    -- We'll read dwords and extract bytes
    local bytes_cache = {}
    local cache_start = chunk_start
    local cache_size = chunk_end - chunk_start

    -- Read dwords, 4 bytes each
    for off = 0, cache_size - 1, 4 do
        local addr = eboot_base + uint64(chunk_start + off)
        local dw = safe_rd(addr)
        if dw then
            bytes_cache[off] = dw % 256
            bytes_cache[off+1] = math.floor(dw / 256) % 256
            bytes_cache[off+2] = math.floor(dw / 65536) % 256
            bytes_cache[off+3] = math.floor(dw / 16777216) % 256
        end
    end

    -- Now scan the cached bytes for each gadget pattern
    for _, gdef in ipairs(gadgets) do
        local gname = gdef[1]
        local gbytes = gdef[2]
        local ctx = gdef[3]
        local glen = #gbytes

        for off = 0, cache_size - glen do
            local match = true
            for i = 1, glen do
                local b = bytes_cache[off + i - 1]
                if b ~= gbytes[i] then
                    match = false
                    break
                end
            end
            if match then
                local abs_off = chunk_start + off
                found_count = found_count + 1
                if not found_map[gname] then found_map[gname] = {} end

                -- For "syscall" (not syscall;ret), get context bytes after
                local ctx_str = ""
                if ctx > 0 then
                    local parts = {}
                    for ci = 0, ctx - 1 do
                        local cb = bytes_cache[off + glen + ci]
                        if cb then
                            parts[#parts+1] = string.format("%02X", cb)
                        end
                    end
                    ctx_str = " [+" .. table.concat(parts, " ") .. "]"
                end

                -- Only store first 5 per gadget to avoid flooding
                if #found_map[gname] < 5 then
                    found_map[gname][#found_map[gname]+1] = {abs_off, ctx_str}
                    print(string.format("  FOUND: %-30s at eboot+0x%X%s",
                        gname, abs_off, ctx_str))
                elseif #found_map[gname] == 5 then
                    found_map[gname][#found_map[gname]+1] = {abs_off, ctx_str}
                    print(string.format("  FOUND: %-30s at eboot+0x%X (more exist, limiting output)",
                        gname, abs_off))
                else
                    found_map[gname][#found_map[gname]+1] = {abs_off, ""}
                end
            end
        end
    end
end

-- [D] Summary
print("")
print("=== GADGET SCAN SUMMARY ===")
print(string.format("Total gadget instances found: %d", found_count))
print("")

-- Print summary table
for _, gdef in ipairs(gadgets) do
    local gname = gdef[1]
    local list = found_map[gname]
    if list and #list > 0 then
        local first = list[1]
        local extra = ""
        if #list > 1 then extra = string.format(" (+%d more)", #list - 1) end
        print(string.format("  %-35s: FIRST at eboot+0x%X, count=%d%s",
            gname, first[1], #list, extra))
    end
end

-- Highlight critical finds
print("")
print("=== CRITICAL GADGETS ===")
local critical = {"syscall;ret", "syscall", "int80;ret", "xchg rax,rsp;ret",
    "pop rdi;pop rsi;pop rdx;ret", "mov rax,[rdi];ret"}
for _, name in ipairs(critical) do
    local list = found_map[name]
    if list and #list > 0 then
        print(string.format("  [YES] %s: %d found, first at eboot+0x%X", name, #list, list[1][1]))
        -- Print all stored offsets for critical gadgets
        for i, entry in ipairs(list) do
            if i <= 5 then
                print(string.format("         #%d: eboot+0x%X%s", i, entry[1], entry[2]))
            end
        end
    else
        print(string.format("  [NO]  %s: NOT FOUND", name))
    end
end

print("")
print("=== PROBE 80l COMPLETE ===")
