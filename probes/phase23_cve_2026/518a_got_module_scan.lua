-- CRASH_CLASS: LOW
-- PROBE 518a: find GOT + scan loaded modules for useful pointers
--
-- .dynamic is NOT mapped in PS5 eboot memory (517a confirmed).
-- The SCE loader consumes it at load time and discards it.
-- New strategy:
--   [A] Follow rodata pointers found in data+0x38-0x48
--   [B] Scan data segment for pointer tables (GOT candidates)
--   [C] Enumerate loaded modules via dynlib_get_info for handles 0-40
--   [D] Check if any module's data regions contain kernel-shaped values

print("=== PROBE 518a: GOT + module scan ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function read_str(addr, maxlen)
    maxlen = maxlen or 64
    local s = ""
    for i = 0, maxlen - 1 do
        local b = safe_rd(addr + i)
        if not b then break end
        local c = b % 256
        if c == 0 then break end
        if c >= 32 and c < 127 then
            s = s .. string.char(c)
        else
            s = s .. "."
        end
    end
    return s
end

local sc20  = make_syscall(20)
local sc593 = make_syscall(593)
local sc674 = make_syscall(674)

local pid = to_num(sc20())
print("pid: " .. pid)

-- get eboot info
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_addr = safe_rq(info + 0x108)
local data_addr = safe_rq(info + 0x118)
local rodata_addr = safe_rq(info + 0x128)
print("text: " .. fmt_hex(text_addr))
print("data: " .. fmt_hex(data_addr))
print("rodata: " .. fmt_hex(rodata_addr))

-- ============================================================
-- [A] Follow the rodata pointers at data+0x38, +0x40, +0x48
-- ============================================================
print("")
print("[A] Rodata pointers from data segment")

local ptrs = {0x38, 0x40, 0x48, 0x50, 0x58}
for _, off in ipairs(ptrs) do
    local ptr = safe_rq(data_addr + off)
    if ptr then
        local h, l = get_hi_lo(ptr)
        if h > 0 or l > 0x10000000 then
            -- try reading as string
            local s = read_str(ptr, 60)
            if #s > 2 then
                print(string.format("  +0x%02X -> %s = \"%s\"", off, fmt_hex(ptr), s))
            else
                -- try reading as pointer to pointer
                local pp = safe_rq(ptr)
                print(string.format("  +0x%02X -> %s [0]=%s", off, fmt_hex(ptr), pp and fmt_hex(pp) or "unreadable"))
            end
        end
    end
end

-- ============================================================
-- [B] Scan data region for GOT: dense table of code pointers
-- A GOT entry points to text segments of loaded modules.
-- Look for runs of 8+ consecutive qwords that point to known module ranges.
-- ============================================================
print("")
print("[B] GOT scan in data segment")

-- first, collect all module text ranges
local modules = {}
local mod_info = memory.alloc(0x200)
for h = 0, 40 do
    safe_wd(mod_info, 0x160)
    for j = 4, 0x15C, 4 do safe_wd(mod_info + j, 0) end
    local ok, ret = pcall(function() return sc593(uint64(h), mod_info) end)
    if ok and to_num(ret) == 0 then
        local mt = safe_rq(mod_info + 0x108)
        local md = safe_rq(mod_info + 0x118)
        if mt then
            local mh, ml = get_hi_lo(mt)
            if ml > 0 then
                local name = read_str(mod_info + 8, 40)
                table.insert(modules, {handle = h, text = mt, data = md, name = name})
            end
        end
    end
end
print("  loaded modules: " .. #modules)
for i, m in ipairs(modules) do
    if i <= 8 then
        print(string.format("  [%d] h=%d text=%s data=%s \"%s\"",
            i, m.handle, fmt_hex(m.text), m.data and fmt_hex(m.data) or "nil", m.name))
    end
end
if #modules > 8 then
    print("  ... +" .. (#modules - 8) .. " more")
end

-- scan data region for pointer-like values
-- a "code pointer" has hi byte matching a known module text range
print("")
print("  scanning data for code pointers...")

local data_h, data_l = get_hi_lo(data_addr)
local data_sz = 0x144000  -- first data region size
local code_ptr_count = 0
local got_start = nil
local got_run = 0
local best_run = 0
local best_start = nil

for off = 0, math.min(data_sz, 0x100000) - 8, 8 do
    local q = safe_rq(data_addr + off)
    if not q then break end

    local qh, ql = get_hi_lo(q)
    local is_code = false

    -- check if this value points into any module's text segment region
    for _, m in ipairs(modules) do
        local mh, ml = get_hi_lo(m.text)
        -- same high 16 bits and within ~16MB
        if qh == mh and ql >= ml and ql < ml + 0x1000000 then
            is_code = true
            break
        end
    end

    if is_code then
        code_ptr_count = code_ptr_count + 1
        if got_start == nil then
            got_start = data_addr + uint64(off)
        end
        got_run = got_run + 1
    else
        if got_run > best_run then
            best_run = got_run
            best_start = got_start
        end
        got_start = nil
        got_run = 0
    end

    -- progress every 128KB
    if off > 0 and off % 0x20000 == 0 then
        print(string.format("    ...+0x%X ptrs=%d best_run=%d", off, code_ptr_count, best_run))
    end
end

-- final check
if got_run > best_run then
    best_run = got_run
    best_start = got_start
end

print("  total code pointers: " .. code_ptr_count)
print("  longest consecutive run: " .. best_run .. " at " .. (best_start and fmt_hex(best_start) or "none"))

-- dump the best GOT candidate
if best_start and best_run >= 4 then
    print("")
    print("[C] GOT candidate at " .. fmt_hex(best_start))
    local show = math.min(best_run, 20)
    for i = 0, show - 1 do
        local entry = safe_rq(best_start + i * 8)
        if entry then
            -- identify which module this points into
            local eh, el = get_hi_lo(entry)
            local mod_name = "?"
            for _, m in ipairs(modules) do
                local mh, ml = get_hi_lo(m.text)
                if eh == mh and el >= ml and el < ml + 0x1000000 then
                    mod_name = m.name
                    break
                end
            end
            print(string.format("  [%d] %s -> %s", i, fmt_hex(entry), mod_name))
        end
    end
end

-- ============================================================
-- [D] Kernel pointer scan in module data segments
-- Check first 256 bytes of each non-eboot module's data region
-- for kernel-shaped values (0xFFFF8xxx+)
-- ============================================================
print("")
print("[D] Module data kptr scan")
local kptr_found = 0

for _, m in ipairs(modules) do
    if m.handle ~= 0 and m.data then
        local dh, dl = get_hi_lo(m.data)
        if dl > 0 then
            -- scan first 512 bytes
            for off = 0, 0x1F8, 8 do
                local q = safe_rq(m.data + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    if qh >= 0xFFFF8000 then
                        kptr_found = kptr_found + 1
                        print(string.format("  KPTR: h=%d +0x%X = %s \"%s\"",
                            m.handle, off, fmt_hex(q), m.name))
                    end
                end
            end
        end
    end
end
if kptr_found == 0 then
    print("  zero kernel pointers in module data headers")
end

-- ============================================================
-- [E] Check for interesting strings at data segment start
-- The +0x38-0x48 pointers go into rodata — read what's there
-- ============================================================
print("")
print("[E] Strings at rodata pointer targets")
for off = 0, 0x1F8, 8 do
    local ptr = safe_rq(data_addr + off)
    if ptr then
        local ph, pl = get_hi_lo(ptr)
        local rh, rl = get_hi_lo(rodata_addr)
        -- check if pointing into rodata
        if ph == rh and pl >= rl and pl < rl + 0x20000 then
            local s = read_str(ptr, 50)
            if #s > 3 then
                print(string.format("  data+0x%02X -> rodata+0x%X: \"%s\"",
                    off, pl - rl, s))
            end
        end
    end
end

print("")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 518a COMPLETE ===")
