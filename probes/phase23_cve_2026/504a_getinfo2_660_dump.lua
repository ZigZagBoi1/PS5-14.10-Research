-- CRASH_CLASS: LOW
-- PROBE 504a: syscall 660 dynlib_get_info2 — full struct dump + kptr scan
--
-- 13.60 offline decode: handler 0x34bc60, narg 2: 660(id: u32, info: void*).
-- NO gate (same as 593). Uses a v2 struct filler that may include fields
-- 593 does not fill — potential kernel pointers in the diff.
-- Prior probes returned -1 because they passed zeros; with real handles
-- from the 593 space and size=0x160 it should answer.
--
-- Also tests 656 dynlib_get_info_for_libdbg (debug-unit gate — one call
-- determines if the predicates pass on retail 14.10).

print("=== PROBE 504a: dynlib_get_info2(660) + libdbg(656) dump ===")
print("")

------------------------------------------------------------------ helpers
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
local sc593 = make_syscall(593)
local sc660 = make_syscall(660)
local sc656 = make_syscall(656)
local sc659 = make_syscall(659)

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ [A] get valid handles from 593
print("")
print("[A] Collecting module handles via 593...")

local handles = {}
local info593 = memory.alloc(0x200)

for h = 0, 50 do
    for i = 0, 0x1FC, 4 do safe_wd(info593 + i, 0) end
    safe_wd(info593, 0x160)

    local ok, ret = pcall(function()
        return sc593(uint64(h), info593)
    end)
    if ok and to_num(ret) == 0 then
        table.insert(handles, h)
    end
end
print("  valid handles: " .. #handles)

if #handles == 0 then
    print("FATAL: no handles")
    return
end

------------------------------------------------------------------ [B] 660 with real handles — full dump
print("")
print("[B] Testing 660 dynlib_get_info2 with real handles...")

local STRUCT_SIZE = 0x160
local kptr_found = false

for idx = 1, math.min(#handles, 5) do
    local h = handles[idx]

    -- get 593 baseline for this handle
    local buf593 = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf593 + i, 0) end
    safe_wd(buf593, STRUCT_SIZE)
    pcall(function() sc593(uint64(h), buf593) end)

    -- read 593 name for reference
    local name593 = ""
    for i = 0, 15 do
        local b = safe_rd(buf593 + 0x08 + i * 4)
        if not b then break end
        for shift = 0, 24, 8 do
            local c = math.floor(b / math.pow(2, shift)) % 256
            if c == 0 then break end
            name593 = name593 .. string.char(c)
        end
        if name593:find("%z") then break end
    end
    print(string.format("  handle=%d (%.40s)", h, name593))

    -- now call 660
    local buf660 = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf660 + i, 0) end
    safe_wd(buf660, STRUCT_SIZE)  -- size at +0

    local ok, ret = pcall(function()
        return sc660(uint64(h), uint64(to_num(buf660)))
    end)

    if ok then
        local rv = to_num(ret)
        print(string.format("    660 ret=%d", rv))

        if rv == 0 then
            -- scan all qwords for kernel pointers
            local diffs = 0
            for off = 0, STRUCT_SIZE - 4, 4 do
                local v593 = safe_rd(buf593 + off)
                local v660 = safe_rd(buf660 + off)
                if v593 ~= v660 then
                    diffs = diffs + 1
                    if diffs <= 20 then
                        print(string.format("    DIFF +0x%03X: 593=0x%08X 660=0x%08X",
                            off, v593 or 0, v660 or 0))
                    end
                end
            end
            print(string.format("    total diffs: %d dwords", diffs))

            -- kernel pointer scan on 660 output
            for off = 0, STRUCT_SIZE - 8, 8 do
                local val = safe_rq(buf660 + off)
                if val then
                    local vh, vl = get_hi_lo(val)
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        print(string.format("    *** KPTR +0x%03X = %s ***", off, fmt_hex(val)))
                        kptr_found = true
                    end
                end
            end
        end
    else
        print("    660 CRASHED")
    end
end

------------------------------------------------------------------ [C] 656 debug-unit gate test
print("")
print("[C] Testing 656 dynlib_get_info_for_libdbg (debug-unit gate)...")

local buf656 = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do safe_wd(buf656 + i, 0) end
safe_wd(buf656, STRUCT_SIZE)

local ok656, ret656 = pcall(function()
    return sc656(uint64(handles[1]), uint64(to_num(buf656)))
end)

if ok656 then
    local rv = to_num(ret656)
    print(string.format("  656 ret=%d (0=debug predicates PASS, nonzero=gated)", rv))
    if rv == 0 then
        print("  *** DEBUG-UNIT PREDICATES PASS ON THIS CONSOLE ***")
        -- dump first 64 bytes
        for off = 0, 60, 4 do
            local v = safe_rd(buf656 + off)
            print(string.format("    +0x%02X = 0x%08X", off, v or 0))
        end
    end
else
    print("  656 CRASHED")
end

------------------------------------------------------------------ [D] 659 dynlib_get_list
print("")
print("[D] Testing 659 dynlib_get_list...")

-- 659(out_handles: u32*, max_count: u32, actual_count: u32*)
local list_buf = memory.alloc(0x200)  -- room for 128 handles
local count_buf = memory.alloc(8)
safe_wd(count_buf, 0)

local ok659, ret659 = pcall(function()
    return sc659(uint64(to_num(list_buf)), uint64(128),
                 uint64(to_num(count_buf)))
end)

if ok659 then
    local rv = to_num(ret659)
    local cnt = safe_rd(count_buf)
    print(string.format("  659 ret=%d count=%d", rv, cnt or 0))
    if rv == 0 and cnt and cnt > 0 then
        -- list first 10 handles
        for i = 0, math.min(cnt - 1, 9) do
            local hv = safe_rd(list_buf + i * 4)
            print(string.format("    [%d] handle=%d", i, hv or 0))
        end
    end
else
    print("  659 CRASHED")
end

------------------------------------------------------------------ [E] 572 re-shape test
-- 13.60 shows two copyouts with no top gate. Try different arg layouts.
print("")
print("[E] Testing 572 alternate arg shapes...")

local sc572 = make_syscall(572)
local out572 = memory.alloc(0x200)

-- shape 1: (addr, outbuf, size)  — the layout that returned empty
for i = 0, 0x1FC, 4 do safe_wd(out572 + i, 0xDEADBEEF) end
local ok1, ret1 = pcall(function()
    return sc572(uint64(0), uint64(to_num(out572)), uint64(0x100))
end)
if ok1 then
    local sentinel = safe_rd(out572)
    print(string.format("  shape1(0, out, 0x100) ret=%d first_dw=0x%08X",
        to_num(ret1), sentinel or 0))
end

-- shape 2: (outbuf, size, cmd)
for i = 0, 0x1FC, 4 do safe_wd(out572 + i, 0xDEADBEEF) end
local ok2, ret2 = pcall(function()
    return sc572(uint64(to_num(out572)), uint64(0x100), uint64(1))
end)
if ok2 then
    local sentinel = safe_rd(out572)
    print(string.format("  shape2(out, 0x100, cmd=1) ret=%d first_dw=0x%08X",
        to_num(ret2), sentinel or 0))
end

-- shape 3: (cmd, outbuf, outsize, 0, 0, 0)
for i = 0, 0x1FC, 4 do safe_wd(out572 + i, 0xDEADBEEF) end
local ok3, ret3 = pcall(function()
    return sc572(uint64(1), uint64(to_num(out572)), uint64(0x100),
                 uint64(0), uint64(0), uint64(0))
end)
if ok3 then
    local sentinel = safe_rd(out572)
    print(string.format("  shape3(cmd=1, out, 0x100) ret=%d first_dw=0x%08X",
        to_num(ret3), sentinel or 0))
end

-- shape 4: (outbuf, 0x200, 0, 0, 0, 0) — large size
for i = 0, 0x1FC, 4 do safe_wd(out572 + i, 0xDEADBEEF) end
local ok4, ret4 = pcall(function()
    return sc572(uint64(to_num(out572)), uint64(0x200), uint64(0),
                 uint64(0), uint64(0), uint64(0))
end)
if ok4 then
    local sentinel = safe_rd(out572)
    print(string.format("  shape4(out, 0x200, 0) ret=%d first_dw=0x%08X",
        to_num(ret4), sentinel or 0))
end

------------------------------------------------------------------ verification
print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))

if kptr_found then
    print("*** KERNEL POINTERS FOUND — SEE ABOVE ***")
end

print("")
print("=== PROBE 504a COMPLETE ===")
