-- CRASH_CLASS: SAFE
-- PROBE 41d: dump non-zero pages before GPU mmap, categorize all qwords
-- Finding from 41c: 256+ readable pages, 90 non-zero, stale heap data

print("=== PROBE 41d: HEAP DATA DUMP ===")
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

local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then
        return val.h, val.l
    end
    local n = to_num(val)
    return 0, n
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(
            uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002),
            uint64("0xFFFFFFFFFFFFFFFF"), uint64(0)
        )
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

--------------------------------------------------------------------
-- Allocate anchor page
--------------------------------------------------------------------
local base = do_mmap(PAGE)
if not base then
    print("mmap FAILED")
    print("=== PROBE 41d COMPLETE ===")
    return
end
print("anchor: " .. hex(base))
print("")

--------------------------------------------------------------------
-- SECTION 1: Scan 512 pages backward, dump ALL non-zero qwords
-- categorize each as: kernel_ptr, heap_ptr, text_ptr, small, ascii, other
--------------------------------------------------------------------
print("--- SECTION 1: FULL BACKWARD SCAN (512 pages x 0x1000) ---")

local stats = {
    kernel_ptr = 0,
    heap_self = 0,
    heap_other = 0,
    user_low = 0,
    small_val = 0,
    ascii_like = 0,
    fill_pattern = 0,
    other = 0,
    total_nonzero = 0,
    pages_readable = 0,
    pages_nonzero = 0,
}

local kernel_ptrs = {}
local interesting = {}

for i = 1, 512 do
    local page_addr = base - i * 0x1000
    if page_addr <= 0 then break end

    local ok_test, test_val = pcall(function() return memory.read_dword(page_addr) end)
    if not ok_test then break end
    stats.pages_readable = stats.pages_readable + 1

    local page_has_data = false

    -- sample 8 qwords per page (every 0x200 bytes) to keep output manageable
    for off = 0, 0xF00, 0x200 do
        local addr = page_addr + off
        local ok_r, qval = pcall(function() return memory.read_qword(addr) end)
        if ok_r then
            local hi, lo = get_hi_lo(qval)
            if hi == 0 and lo == 0 then
                -- skip zero
            else
                stats.total_nonzero = stats.total_nonzero + 1
                page_has_data = true

                -- categorize
                local cat = "other"

                if hi == 0xAFAFAFAF and lo == 0xAFAFAFAF then
                    cat = "fill_pattern"
                elseif hi == 0xDEADDEAD or lo == 0xDEADDEAD then
                    cat = "fill_pattern"
                elseif hi == 0xFEEDFACE or lo == 0xFEEDFACE then
                    cat = "fill_pattern"
                elseif hi >= 0xFFFFFF80 then
                    cat = "kernel_ptr"
                    if #kernel_ptrs < 64 then
                        kernel_ptrs[#kernel_ptrs + 1] = string.format(
                            "  %s +0x%03X: %s", hex(page_addr), off, dump_qword(qval))
                    end
                elseif hi >= 0x00000003 and hi <= 0x00000004 and lo >= 0x10000000 then
                    cat = "heap_self"
                elseif hi == 0x00000000 and lo >= 0x80000000 and lo < 0x90000000 then
                    cat = "user_low"
                elseif hi == 0x00000000 and lo < 0x10000 then
                    cat = "small_val"
                else
                    -- check if looks like ASCII
                    local is_ascii = true
                    local b3 = lo % 256
                    local b2 = math.floor(lo / 256) % 256
                    local b1 = math.floor(lo / 65536) % 256
                    local b0 = math.floor(lo / 16777216) % 256
                    for _, b in ipairs({b0, b1, b2, b3}) do
                        if b ~= 0 and (b < 0x20 or b > 0x7E) then
                            is_ascii = false
                            break
                        end
                    end
                    if is_ascii and lo > 0x20202020 then
                        cat = "ascii_like"
                    end
                end

                stats[cat] = (stats[cat] or 0) + 1

                -- log interesting non-trivial values
                if cat == "kernel_ptr" or cat == "user_low" then
                    -- already logged above for kernel
                    if cat == "user_low" and #interesting < 32 then
                        interesting[#interesting + 1] = string.format(
                            "  %s +0x%03X: %s [%s]", hex(page_addr), off, dump_qword(qval), cat)
                    end
                end
            end
        end
    end

    if page_has_data then
        stats.pages_nonzero = stats.pages_nonzero + 1
    end
end

print("pages readable : " .. stats.pages_readable)
print("pages non-zero : " .. stats.pages_nonzero)
print("sampled qwords : " .. stats.total_nonzero .. " non-zero")
print("")
print("--- CATEGORIES ---")
print("  kernel_ptr   : " .. stats.kernel_ptr)
print("  heap_self    : " .. stats.heap_self)
print("  heap_other   : " .. (stats.other or 0))
print("  user_low     : " .. stats.user_low)
print("  small_val    : " .. stats.small_val)
print("  ascii_like   : " .. stats.ascii_like)
print("  fill_pattern : " .. stats.fill_pattern)
print("")

--------------------------------------------------------------------
-- SECTION 2: Kernel pointer dump
--------------------------------------------------------------------
if #kernel_ptrs > 0 then
    print("--- SECTION 2: KERNEL POINTERS (" .. #kernel_ptrs .. ") ---")
    for _, s in ipairs(kernel_ptrs) do print(s) end
else
    print("--- SECTION 2: NO KERNEL POINTERS FOUND ---")
end
print("")

--------------------------------------------------------------------
-- SECTION 3: Interesting user pointers
--------------------------------------------------------------------
if #interesting > 0 then
    print("--- SECTION 3: USER POINTERS (" .. #interesting .. ") ---")
    for _, s in ipairs(interesting) do print(s) end
else
    print("--- SECTION 3: NO INTERESTING USER PTRS ---")
end
print("")

--------------------------------------------------------------------
-- SECTION 4: Dense dump of first non-zero page (full 64 qwords)
--------------------------------------------------------------------
print("--- SECTION 4: DENSE PAGE DUMP ---")
do
    local found_page = nil
    for i = 1, 512 do
        local addr = base - i * 0x1000
        if addr <= 0 then break end
        local ok_r, val = pcall(function() return memory.read_dword(addr) end)
        if not ok_r then break end
        if to_num(val) ~= 0 then
            found_page = addr
            break
        end
    end

    if found_page then
        print("  page: " .. hex(found_page))
        for off = 0, 0xF8, 8 do
            local ok_r, qval = pcall(function() return memory.read_qword(found_page + off) end)
            if ok_r then
                local hi, lo = get_hi_lo(qval)
                if hi ~= 0 or lo ~= 0 then
                    local tag = ""
                    if hi >= 0xFFFFFF80 then tag = " KPTR!" end
                    if hi >= 3 and hi <= 4 and lo >= 0x10000000 then tag = " HEAP" end
                    print(string.format("  +0x%02X: %s%s", off, dump_qword(qval), tag))
                end
            end
        end
    else
        print("  no non-zero page found")
    end
end

print("")

pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41d COMPLETE ===")
