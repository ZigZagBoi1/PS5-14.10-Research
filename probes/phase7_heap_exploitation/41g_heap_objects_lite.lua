-- CRASH_CLASS: SAFE
-- PROBE 41g: lighter heap object scan (41f crashed from too many reads)
-- Strategy: only scan non-zero pages, sample 4 qwords per page

print("=== PROBE 41g: HEAP OBJECT SCAN (LITE) ===")
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
-- Pass 1: find non-zero pages (one read per page)
--------------------------------------------------------------------
print("--- PASS 1: FIND NON-ZERO PAGES ---")
local nz_pages = {}
for i = 1, 256 do
    local addr = base - i * 0x1000
    if addr <= 0 then break end
    local v = safe_rd(addr)
    if v == nil then break end
    if v ~= 0 then
        nz_pages[#nz_pages + 1] = addr
    end
end
print("non-zero pages: " .. #nz_pages)
print("")

--------------------------------------------------------------------
-- Pass 2: scan each non-zero page — read 16 qword pairs (every 0x100)
--------------------------------------------------------------------
print("--- PASS 2: OBJECT PATTERNS ---")

local text_ptrs = {}
local fptr_tables = {}
local vtable_cands = {}
local list_nodes = {}
local rc_ptrs = {}
local kptrs = {}

for _, pg in ipairs(nz_pages) do
    for off = 0, 0xF00, 0x100 do
        local a = pg + off
        local q0 = safe_rq(a)
        local q1 = safe_rq(a + 8)
        if q0 and q1 then
            local h0, l0 = get_hi_lo(q0)
            local h1, l1 = get_hi_lo(q1)

            -- kernel ptr
            if h0 >= 0xFFFFFF80 and #kptrs < 32 then
                kptrs[#kptrs + 1] = string.format("%s +%03X: %s", hex(pg), off, dump_qword(q0))
            end
            if h1 >= 0xFFFFFF80 and #kptrs < 32 then
                kptrs[#kptrs + 1] = string.format("%s +%03X: %s", hex(pg), off + 8, dump_qword(q1))
            end

            -- text ptr (0x8xxxxxxx)
            local c0_text = (h0 == 0 and l0 >= 0x80000000 and l0 < 0x90000000)
            local c1_text = (h1 == 0 and l1 >= 0x80000000 and l1 < 0x90000000)

            -- heap ptr (0x3_1xxxxxxx)
            local c0_heap = (h0 == 3 and l0 >= 0x10000000)
            local c1_heap = (h1 == 3 and l1 >= 0x10000000)

            -- small value
            local c0_small = (h0 == 0 and l0 >= 1 and l0 <= 16)

            if c0_text and #text_ptrs < 48 then
                text_ptrs[#text_ptrs + 1] = string.format("%s +%03X: %s", hex(pg), off, dump_qword(q0))
            end

            if c0_text and c1_text and #fptr_tables < 24 then
                fptr_tables[#fptr_tables + 1] = string.format("%s +%03X: %s %s", hex(pg), off, dump_qword(q0), dump_qword(q1))
            end

            if c0_heap and c1_text and #vtable_cands < 24 then
                vtable_cands[#vtable_cands + 1] = string.format("%s +%03X: heap=%s text=%s", hex(pg), off, dump_qword(q0), dump_qword(q1))
            end

            if c0_heap and c1_heap and #list_nodes < 24 then
                list_nodes[#list_nodes + 1] = string.format("%s +%03X: %s -> %s", hex(pg), off, dump_qword(q0), dump_qword(q1))
            end

            if c0_small and c1_heap and #rc_ptrs < 24 then
                rc_ptrs[#rc_ptrs + 1] = string.format("%s +%03X: rc=%d ptr=%s", hex(pg), off, l0, dump_qword(q1))
            end
        end
    end
end

print("")
print("--- KERNEL POINTERS: " .. #kptrs .. " ---")
for _, s in ipairs(kptrs) do print("  " .. s) end

print("")
print("--- TEXT POINTERS: " .. #text_ptrs .. " ---")
for j, s in ipairs(text_ptrs) do
    if j > 24 then print("  ..." .. (#text_ptrs - 24) .. " more"); break end
    print("  " .. s)
end

print("")
print("--- FUNCTION TABLES (text+text): " .. #fptr_tables .. " ---")
for j, s in ipairs(fptr_tables) do
    if j > 16 then print("  ..." .. (#fptr_tables - 16) .. " more"); break end
    print("  " .. s)
end

print("")
print("--- VTABLE CANDS (heap+text): " .. #vtable_cands .. " ---")
for j, s in ipairs(vtable_cands) do
    if j > 16 then print("  ..." .. (#vtable_cands - 16) .. " more"); break end
    print("  " .. s)
end

print("")
print("--- LINKED LISTS (heap+heap): " .. #list_nodes .. " ---")
for j, s in ipairs(list_nodes) do
    if j > 16 then print("  ..." .. (#list_nodes - 16) .. " more"); break end
    print("  " .. s)
end

print("")
print("--- REFCOUNT+PTR: " .. #rc_ptrs .. " ---")
for j, s in ipairs(rc_ptrs) do
    if j > 16 then print("  ..." .. (#rc_ptrs - 16) .. " more"); break end
    print("  " .. s)
end

print("")

--------------------------------------------------------------------
-- Pass 3: Dereference up to 8 text pointers to verify they're code
--------------------------------------------------------------------
print("--- PASS 3: DEREFERENCE TEXT PTRS ---")
do
    local tested = 0
    for _, pg in ipairs(nz_pages) do
        if tested >= 8 then break end
        for off = 0, 0xF00, 0x100 do
            if tested >= 8 then break end
            local q = safe_rq(pg + off)
            if q then
                local h, l = get_hi_lo(q)
                if h == 0 and l >= 0x80000000 and l < 0x90000000 then
                    local dw = safe_rd(l)
                    if dw then
                        local b0 = dw % 256
                        local tag = "?"
                        if b0 == 0x55 or b0 == 0x48 or b0 == 0x41 or
                           b0 == 0xE8 or b0 == 0xE9 or b0 == 0xCC or
                           b0 == 0xC3 or b0 == 0x53 or b0 == 0x57 or
                           b0 == 0x89 or b0 == 0x8B or b0 == 0x4C or
                           b0 == 0x50 or b0 == 0x56 then
                            tag = "CODE"
                        else
                            tag = "DATA"
                        end
                        print(string.format("  *0x%X -> dword=%s b0=%02X [%s]", l, hex(dw), b0, tag))
                        tested = tested + 1
                    else
                        print(string.format("  *0x%X -> FAULT", l))
                        tested = tested + 1
                    end
                end
            end
        end
    end
end

print("")
pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41g COMPLETE ===")
