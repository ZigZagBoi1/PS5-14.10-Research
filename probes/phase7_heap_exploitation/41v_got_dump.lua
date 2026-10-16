-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41v: dump eboot GOT to find libkernel function pointers
-- Goal: find resolved PLT entries pointing into libkernel text,
-- then calculate where syscall;ret lives based on known offsets
--
-- FreeBSD syscall wrappers are typically:
--   mov $SYS_xxx, %eax   ; B8 XX 00 00 00
--   mov %rcx, %r10       ; 49 89 CA
--   syscall               ; 0F 05
--   jb cerror             ; 72 XX
--   ret                   ; C3
-- So syscall is at func+8, but "0F 05 C3" won't appear due to the jb.
-- HOWEVER: unaligned reads across function boundaries, or internal
-- helpers like __syscall, may contain the raw 0F 05 C3 sequence.
-- We also look for the Lua loader's own syscall stub address.

print("=== PROBE 41v: EBOOT GOT DUMP ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_dynlib_get_list = make_syscall(592)
local sc_dynlib_get_info = make_syscall(593)
local info_buf = memory.alloc(0x200)

--------------------------------------------------------------------
-- Get module bases
--------------------------------------------------------------------
-- eboot (handle 0)
for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
safe_wd(info_buf, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info_buf) end)
local eb_tl = safe_rd(info_buf + 0x108)
local eb_th = safe_rd(info_buf + 0x10C)
local eb_ts = safe_rd(info_buf + 0x110)
local eb_dl = safe_rd(info_buf + 0x118)
local eb_dh = safe_rd(info_buf + 0x11C)
local eb_ds = safe_rd(info_buf + 0x120)

local eboot_text = uint64(string.format("0x%X%08X", eb_th, eb_tl))
local eboot_data = uint64(string.format("0x%X%08X", eb_dh, eb_dl))
print("eboot text: " .. string.format("0x%X%08X", eb_th, eb_tl) .. " sz=0x" .. string.format("%X", eb_ts))
print("eboot data: " .. string.format("0x%X%08X", eb_dh, eb_dl) .. " sz=0x" .. string.format("%X", eb_ds))

-- Get ALL module text ranges for classification
local handle_buf = memory.alloc(512)
local num_buf = memory.alloc(8)
pcall(function() sc_dynlib_get_list(handle_buf, uint64(128), num_buf) end)
local num_h = safe_rd(num_buf) or 0

local mod_ranges = {}
for i = 0, math.min(num_h - 1, 38) do
    local h = safe_rd(handle_buf + i * 4)
    if h then
        for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
        safe_wd(info_buf, 0x160)
        pcall(function() sc_dynlib_get_info(uint64(h), info_buf) end)
        local name_bytes = {}
        for nb = 0, 31 do
            local c = safe_rb(info_buf + 0x08 + nb)
            if c and c > 0 and c < 128 then name_bytes[#name_bytes + 1] = string.char(c)
            else break end
        end
        local tl = safe_rd(info_buf + 0x108) or 0
        local th = safe_rd(info_buf + 0x10C) or 0
        local ts = safe_rd(info_buf + 0x110) or 0
        mod_ranges[#mod_ranges + 1] = {
            name = table.concat(name_bytes),
            handle = h,
            text_lo_h = th, text_lo_l = tl,
            text_size = ts,
        }
    end
end

-- Helper: classify a 64-bit address
local function classify(hi, lo)
    for _, m in ipairs(mod_ranges) do
        if hi == m.text_lo_h then
            local diff = lo - m.text_lo_l
            if diff >= 0 and diff < m.text_size then
                return m.name, diff
            end
        end
    end
    return nil, 0
end

print("")
print("modules: " .. #mod_ranges)

-- Find libkernel specifically
local lk_th, lk_tl, lk_ts = 0, 0, 0
local lk_name = ""
for _, m in ipairs(mod_ranges) do
    if m.name:find("kernel") then
        lk_th = m.text_lo_h
        lk_tl = m.text_lo_l
        lk_ts = m.text_size
        lk_name = m.name
        break
    end
end
print("libkernel: " .. string.format("0x%X%08X", lk_th, lk_tl) .. " sz=0x" .. string.format("%X", lk_ts))
print("")

--------------------------------------------------------------------
-- PART 1: Scan eboot data segment for GOT entries
-- GOT is usually at the start of data segment
-- Look for qwords pointing into any module's text
--------------------------------------------------------------------
print("--- PART 1: GOT SCAN ---")

local got_entries = {}
local lk_entries = {}
local scan_size = math.min(eb_ds, 0x40000) -- scan first 256KB of data

for off = 0, scan_size - 8, 8 do
    local q = safe_rq(eboot_data + off)
    if q == nil then break end
    local hex, hi, lo = qw_hex(q)
    local mname, moff = classify(hi, lo)
    if mname then
        got_entries[#got_entries + 1] = {off = off, name = mname, func_off = moff, hi = hi, lo = lo}
        if mname:find("kernel") then
            lk_entries[#lk_entries + 1] = {off = off, func_off = moff, addr_hex = hex}
        end
    end
end

print("total GOT entries pointing to module text: " .. #got_entries)

-- Count per module
local per_mod = {}
for _, e in ipairs(got_entries) do
    per_mod[e.name] = (per_mod[e.name] or 0) + 1
end
for name, count in pairs(per_mod) do
    print(string.format("  %-28s %d entries", name, count))
end
print("")

--------------------------------------------------------------------
-- PART 2: libkernel GOT entries — these give us function offsets
--------------------------------------------------------------------
print("--- PART 2: LIBKERNEL GOT ENTRIES ---")
print("(offset from libkernel text base)")
print("")

-- Sort by func_off
table.sort(lk_entries, function(a, b) return a.func_off < b.func_off end)

for i, e in ipairs(lk_entries) do
    print(string.format("  data+0x%05X -> libkernel+0x%05X (%s)",
        e.off, e.func_off, e.addr_hex))
end
print("")
print("libkernel entries: " .. #lk_entries)
print("")

--------------------------------------------------------------------
-- PART 3: For each libkernel function, the syscall instruction
-- is typically at func+8 in FreeBSD wrappers:
--   B8 XX 00 00 00   mov eax, SYS_xxx  (5 bytes)
--   49 89 CA         mov r10, rcx       (3 bytes)
--   0F 05            syscall            (2 bytes)
--   72 XX            jb cerror          (2 bytes)
--   C3               ret                (1 byte)
--
-- So: func+10 = 0F 05 (syscall)
--     func+12 = 72 XX (jb)
--     func+14 = C3 (ret) if no cerror needed (leaf error)
--
-- For __syscall itself: just "syscall; ret" = 0F 05 C3
-- This is at some fixed offset. Look for functions with small offsets
-- (likely __syscall or similar primitives)
--------------------------------------------------------------------
print("--- PART 3: CANDIDATE SYSCALL;RET OFFSETS ---")
print("")
print("In FreeBSD, the raw __syscall helper is typically:")
print("  0F 05 C3  (syscall; ret)")
print("at a small offset in libkernel text.")
print("")

-- Look for notable offsets — very small ones are likely primitives
-- Also: func+10 has the syscall for standard wrappers
-- And func+12 might be the start of another function that's C3-prefixed

-- Candidates for syscall;ret:
-- Any libkernel function where offset+10 has 0F 05,
-- and the NEXT function starts with C3 (ret) — creating 0F 05 C3 across boundary
-- Or: internal __syscall at a low offset

print("known function offsets (sorted):")
local unique_offs = {}
local seen = {}
for _, e in ipairs(lk_entries) do
    if not seen[e.func_off] then
        seen[e.func_off] = true
        unique_offs[#unique_offs + 1] = e.func_off
    end
end
table.sort(unique_offs)

for i, off in ipairs(unique_offs) do
    -- Mark potential syscall position
    local sc_at = off + 10
    print(string.format("  func at +0x%04X, syscall likely at +0x%04X", off, sc_at))
    -- check if sc_at+2 (= off+12) is close to another function start
    -- which would mean 0F 05 [next func byte]
end
print("")

--------------------------------------------------------------------
-- PART 4: Check if any pair of functions creates 0F 05 C3 boundary
-- func_A has syscall at A+10 (bytes 0F 05), then A+12 has jb (72 XX)
-- But if func_B starts at A+12 with C3... that creates 0F 05 C3
-- at address A+10. Check consecutive function pairs.
--------------------------------------------------------------------
print("--- PART 4: CROSS-FUNCTION BOUNDARY CHECK ---")
for i = 1, #unique_offs - 1 do
    local a = unique_offs[i]
    local b = unique_offs[i + 1]
    local gap = b - a
    -- standard wrapper: 5 + 3 + 2 + 2 + 1 = 13 bytes (0x0D)
    -- so b = a + 0x10 (16-byte aligned) or a + 0x0D or similar
    if gap <= 0x20 then
        -- if a+10 has syscall, and a+12 == b, then b starts at jb position
        -- OR if a+10 has syscall, and b = a+12, first byte of b could be anything
        print(string.format("  funcs +0x%04X and +0x%04X, gap=%d, syscall@+0x%04X, gap_from_sc=%d",
            a, b, gap, a + 10, b - (a + 10)))
    end
end
print("")

--------------------------------------------------------------------
-- PART 5: Try the obvious — look for __syscall primitive
-- It's typically one of the first functions. Small offset.
-- The pattern: if offset 0x0000 or 0x0010 is just syscall;ret
-- Try known FreeBSD offsets: 0, 8, 16, etc.
-- We can't READ these, but we can CALL them via ROP.
-- Print candidate addresses for blind testing.
--------------------------------------------------------------------
print("--- PART 5: BLIND CANDIDATES ---")
print("libkernel base: " .. string.format("0x%X%08X", lk_th, lk_tl))
print("")
print("candidate syscall;ret addresses to try:")
-- Standard FreeBSD has __syscall at very low offsets
-- Also: each wrapper's syscall is at func+8
-- Try smallest known function offsets + 8
for i = 1, math.min(#unique_offs, 10) do
    local off = unique_offs[i]
    local sc_off = off + 8
    local addr_lo = lk_tl + sc_off
    local addr_hi = lk_th
    if addr_lo >= 0x100000000 then
        addr_hi = addr_hi + 1
        addr_lo = addr_lo - 0x100000000
    end
    print(string.format("  libkernel+0x%04X (func+8): 0x%X%08X", sc_off, addr_hi, addr_lo))
end
print("")

-- Also try offsets 0, 4, 8, 0xC, 0x10 directly
print("raw low offsets:")
for _, off in ipairs({0, 4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20}) do
    local addr_lo = lk_tl + off
    local addr_hi = lk_th
    if addr_lo >= 0x100000000 then
        addr_hi = addr_hi + 1
        addr_lo = addr_lo - 0x100000000
    end
    print(string.format("  libkernel+0x%04X: 0x%X%08X", off, addr_hi, addr_lo))
end

--------------------------------------------------------------------
-- PART 6: Inspect syscall.pipe itself
-- The Lua syscall object must store a function pointer somewhere
-- Try to find it by dumping the userdata
--------------------------------------------------------------------
print("")
print("--- PART 6: LUA SYSCALL OBJECT ---")
-- syscall.pipe is a userdata with a syscall_no field
-- try to get its address and dump nearby memory
local pipe_str = tostring(syscall.pipe)
print("syscall.pipe: " .. (pipe_str or "nil"))

-- Try to read some known syscall objects
local test_sc = make_syscall(20) -- getpid
local test_str = tostring(test_sc)
print("test syscall(20): " .. (test_str or "nil"))

-- The userdata address might be in the string
-- Format: "userdata: 0xXXXXXXXX"
local addr_str = pipe_str:match("0x[0-9a-fA-F]+")
if addr_str then
    print("pipe userdata at: " .. addr_str)
    local ud_addr = uint64(addr_str)
    -- dump 64 bytes around the userdata
    print("userdata dump (16 qwords):")
    for i = 0, 15 do
        local q = safe_rq(ud_addr + i * 8)
        if q then
            local hex = qw_hex(q)
            local mname, moff = classify(type(q) == "table" and q.h or 0,
                type(q) == "table" and q.l or to_num(q))
            local tag = mname and string.format(" -> %s+0x%X", mname, moff) or ""
            print(string.format("  +0x%02X: %s%s", i * 8, hex, tag))
        end
    end
end

print("")
print("=== PROBE 41v COMPLETE ===")
