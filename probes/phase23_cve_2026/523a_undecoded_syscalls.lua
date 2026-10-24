-- CRASH_CLASS: MODERATE
-- PROBE 523a: undecoded Sony syscalls with smart arg patterns
--
-- 604 (dl_get_metadata) and 636 (set_timezone_info) have no
-- decoded contracts in the 13.60 dossier. 604 is interesting:
-- the "dl" prefix suggests dynlib metadata, potentially including
-- kernel-side information about loaded modules.
--
-- Also tests several other "present but -1" Sony syscalls
-- with educated argument patterns based on their names.
--
-- Additionally: 640 has narg=8 and is "reviewed" — high arg
-- count might mean it takes a complex struct. Test it too.

print("=== PROBE 523a: undecoded Sony syscalls ===")
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

local sc20  = make_syscall(20)
local pid = to_num(sc20())
print("pid: " .. pid)

-- allocate work buffers
local buf = memory.alloc(0x2000)
local outlen = memory.alloc(16)

local function zero_buf(addr, sz)
    for j = 0, sz - 1, 4 do safe_wd(addr + j, 0) end
end

local function check_buf_kptr(addr, sz)
    local found = 0
    for off = 0, sz - 8, 8 do
        local q = safe_rq(addr + off)
        if q then
            local qh, ql = get_hi_lo(q)
            -- check for kernel pointer (exclude NaN: exponent != 0x7FF)
            local exponent = math.floor((qh % 0x80000000) / 0x100000)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF and exponent ~= 0x7FF then
                found = found + 1
                print(string.format("    *** KPTR at +0x%X: 0x%08X_%08X (exp=0x%03X) ***",
                    off, qh, ql, exponent))
            end
        end
    end
    return found
end

local function dump_buf(addr, sz, label)
    print("  " .. label .. " dump (" .. sz .. " bytes):")
    local nonzero = 0
    for off = 0, sz - 8, 8 do
        local q = safe_rq(addr + off)
        if q then
            local qh, ql = get_hi_lo(q)
            if qh ~= 0 or ql ~= 0 then
                nonzero = nonzero + 1
                if nonzero <= 20 then
                    print(string.format("    +0x%03X: 0x%08X_%08X", off, qh, ql))
                end
            end
        end
    end
    if nonzero > 20 then print("    ... " .. nonzero .. " total nonzero qwords") end
    if nonzero == 0 then print("    (all zero)") end
    return nonzero
end

local function try_syscall(num, desc, ...)
    local sc = make_syscall(num)
    zero_buf(buf, 0x1000)
    local ok, ret = pcall(function() return sc(...) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  %d (%s): ret=%d%s", num, desc, rv, ok and "" or " [PCALL-FAIL]"))
    return rv, ok
end

-- ============================================================
-- [A] 604 dl_get_metadata: try as (handle, outbuf, outlen_ptr)
-- Similar to 593 dynlib_get_info
-- ============================================================
print("")
print("[A] sys 604 dl_get_metadata")

-- pattern 1: (handle, buf, buflen_ptr) like 593
for _, h in ipairs({0, 2, 17, 49, 159}) do
    zero_buf(buf, 0x1000)
    safe_wd(outlen, 0x1000)
    safe_wd(outlen + 4, 0)
    local rv = try_syscall(604, "h=" .. h .. " (h,buf,len)",
        uint64(h), uint64(to_num(buf)), uint64(to_num(outlen)))
    if rv == 0 then
        local written = safe_rd(outlen)
        print("    len_out=" .. (written or 0))
        dump_buf(buf, math.min(written or 0x100, 0x200), "604 output")
        check_buf_kptr(buf, math.min(written or 0x200, 0x1000))
    end
end
print("")

-- pattern 2: (handle, cmd/type, buf, buflen_ptr) - multiplexer
for _, cmd in ipairs({0, 1, 2, 3, 4, 5, 0x10}) do
    zero_buf(buf, 0x1000)
    safe_wd(outlen, 0x1000)
    local rv = try_syscall(604, "h=0 cmd=" .. cmd,
        uint64(0), uint64(cmd), uint64(to_num(buf)), uint64(to_num(outlen)))
    if rv == 0 then
        local written = safe_rd(outlen)
        print("    cmd=" .. cmd .. " len_out=" .. (written or 0))
        dump_buf(buf, math.min(written or 0x100, 0x200), "604 output")
        check_buf_kptr(buf, math.min(written or 0x200, 0x1000))
    end
end
print("")

-- pattern 3: (handle, buf) simple
for _, h in ipairs({0, 2}) do
    zero_buf(buf, 0x1000)
    local rv = try_syscall(604, "h=" .. h .. " (h,buf)",
        uint64(h), uint64(to_num(buf)))
    if rv == 0 then
        dump_buf(buf, 0x200, "604 output")
        check_buf_kptr(buf, 0x1000)
    end
end
print("")

-- pattern 4: with size at buf+0 (like 593 uses size=0x160 at buf+0)
for _, sz in ipairs({0x40, 0x80, 0x100, 0x160, 0x200, 0x400}) do
    zero_buf(buf, 0x1000)
    safe_wd(buf, sz)
    local rv = try_syscall(604, "h=0 buf[0]=" .. string.format("0x%X", sz),
        uint64(0), uint64(to_num(buf)))
    if rv == 0 then
        dump_buf(buf, math.min(sz + 0x40, 0x400), "604 output")
        check_buf_kptr(buf, math.min(sz + 0x40, 0x1000))
    end
end
print("")

-- ============================================================
-- [B] 636 set_timezone_info
-- ============================================================
print("[B] sys 636 set_timezone_info")

-- pattern: (timezone_name_ptr, len)
local tz_str = memory.alloc(64)
-- write "UTC\0"
safe_wd(tz_str, 0x00435455) -- "UTC\0" little-endian

try_syscall(636, "UTC str", uint64(to_num(tz_str)), uint64(4))
try_syscall(636, "zeros", uint64(0), uint64(0))
try_syscall(636, "buf", uint64(to_num(buf)), uint64(0x40))
print("")

-- ============================================================
-- [C] 640 (narg=8) — complex struct handler
-- ============================================================
print("[C] sys 640 (narg=8)")

-- with credential check (has 'yes' in credential column)
-- try (0,0,0,0,0,0) first
try_syscall(640, "zeros", uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))

-- try (buf, size, cmd, ...) patterns
for _, cmd in ipairs({0, 1, 2, 3}) do
    zero_buf(buf, 0x200)
    local rv = try_syscall(640, "cmd=" .. cmd,
        uint64(cmd), uint64(to_num(buf)), uint64(0x200),
        uint64(0), uint64(0), uint64(0))
    if rv == 0 then
        dump_buf(buf, 0x200, "640 output")
        check_buf_kptr(buf, 0x200)
    end
end
print("")

-- ============================================================
-- [D] Test remaining undecoded present syscalls
-- Focus on ones that returned -1 to zeros but might work
-- with proper struct args
-- ============================================================
print("[D] Other undecoded present syscalls")

-- 602 - no name, might be related to dynlib
zero_buf(buf, 0x200)
try_syscall(602, "zeros", uint64(0), uint64(0), uint64(0), uint64(0))
try_syscall(602, "h=0,buf", uint64(0), uint64(to_num(buf)), uint64(0x200), uint64(0))
print("")

-- 603 - no name
try_syscall(603, "zeros", uint64(0), uint64(0), uint64(0), uint64(0))
try_syscall(603, "h=0,buf", uint64(0), uint64(to_num(buf)), uint64(0x200), uint64(0))
print("")

-- 605 - no name
try_syscall(605, "zeros", uint64(0), uint64(0), uint64(0), uint64(0))
try_syscall(605, "h=0,buf", uint64(0), uint64(to_num(buf)), uint64(0x200), uint64(0))
print("")

-- 606 - no name
try_syscall(606, "zeros", uint64(0), uint64(0), uint64(0), uint64(0))
try_syscall(606, "h=0,buf", uint64(0), uint64(to_num(buf)), uint64(0x200), uint64(0))
print("")

-- 607-615 quick sweep with (0, buf, size) pattern
print("  Quick sweep 607-615 with (0, buf, 0x200):")
for num = 607, 615 do
    zero_buf(buf, 0x200)
    local rv = try_syscall(num, "buf",
        uint64(0), uint64(to_num(buf)), uint64(0x200), uint64(0))
    if rv == 0 then
        local nz = dump_buf(buf, 0x200, num .. " output")
        if nz > 0 then check_buf_kptr(buf, 0x200) end
    end
end
print("")

-- ============================================================
-- [E] 638 (narg=4) and 641 (narg=2) and 642 (narg=4)
-- ============================================================
print("[E] 638/641/642")

-- 638: narg=4
for _, pattern in ipairs({
    {0, 0, 0, 0},
    {1, 0, 0, 0},
}) do
    zero_buf(buf, 0x200)
    try_syscall(638, table.concat(pattern, ","),
        uint64(pattern[1]), uint64(pattern[2] == 0 and to_num(buf) or pattern[2]),
        uint64(0x200), uint64(0))
end

-- 641: narg=2
try_syscall(641, "0,0", uint64(0), uint64(0))
try_syscall(641, "0,buf", uint64(0), uint64(to_num(buf)))
try_syscall(641, "1,0", uint64(1), uint64(0))
try_syscall(641, "pid,0", uint64(pid), uint64(0))

-- 642: narg=4
try_syscall(642, "0,0,0,0", uint64(0), uint64(0), uint64(0), uint64(0))
try_syscall(642, "0,buf,200,0",
    uint64(0), uint64(to_num(buf)), uint64(0x200), uint64(0))
print("")

-- ============================================================
-- [F] 644 (narg=0) - a zero-arg call!
-- ============================================================
print("[F] sys 644 (narg=0)")
local rv = try_syscall(644, "no args")
if rv ~= -1 then
    print("  *** INTERESTING: ret=" .. rv .. " ***")
end
print("")

local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 523a COMPLETE ===")
