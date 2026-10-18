-- CRASH_CLASS: MODERATE
-- PROBE 56k5: mod* syscalls for KASLR — safer ordering
--
-- 56k4 showed kldstat(308) kills process instantly.
-- Test mod* family first (300-302) which may be softer.
-- One call per section with markers to identify crash point.

print("=== PROBE 56k5: MODSYS KASLR ===")

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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

-- [A] modnext (302) — enumerate module IDs
print("[A] modnext (sys 302)")
print("  calling modnext(0)...")
local sc_modnext = make_syscall(302)
local ok, ret = pcall(function() return sc_modnext(uint64(0)) end)
local rv = ok and to_num(ret) or -999
print(string.format("  modnext(0) = %d", rv))

if rv > 0 then
    local mod_id = rv
    for attempt = 2, 10 do
        print(string.format("  calling modnext(%d)...", mod_id))
        ok, ret = pcall(function() return sc_modnext(uint64(mod_id)) end)
        rv = ok and to_num(ret) or -999
        print(string.format("  modnext(%d) = %d", mod_id, rv))
        if rv <= 0 or rv == mod_id then break end
        mod_id = rv
    end
end

-- [B] modfind (300) — find module by name
print("")
print("[B] modfind (sys 300)")
local sc_modfind = make_syscall(300)
local name_buf = memory.alloc(64)

local test_names = {"kernel", "linker", "elf", "if_lo", "netgraph"}
for _, nm in ipairs(test_names) do
    -- Write name string
    for i = 0, 15 do safe_wd(name_buf + i*4, 0) end
    for i = 1, #nm do
        local off = i - 1
        local cur = safe_rd(name_buf + (off - off%4)) or 0
        local shift = (off % 4) * 8
        cur = cur + nm:byte(i) * (2^shift)
        safe_wd(name_buf + (off - off%4), cur)
    end

    print(string.format("  calling modfind('%s')...", nm))
    ok, ret = pcall(function() return sc_modfind(uint64(name_buf)) end)
    rv = ok and to_num(ret) or -999
    print(string.format("  modfind('%s') = %d", nm, rv))
end

-- [C] modstat (301) — get module info
-- struct module_stat { int version; char name[32]; int refs; int id;
--   struct module_stat *next; ... data ... }
print("")
print("[C] modstat (sys 301)")
local sc_modstat = make_syscall(301)
local mstat_buf = memory.alloc(0x200)

-- Try modids 1-5 with various version sizes
for mid = 1, 5 do
    for i = 0, 0x7F do safe_wd(mstat_buf + i*4, 0) end
    safe_wd(mstat_buf, 0x58)  -- version = sizeof(module_stat) on FreeBSD 9

    print(string.format("  calling modstat(%d, ver=0x58)...", mid))
    ok, ret = pcall(function()
        return sc_modstat(uint64(mid), uint64(mstat_buf))
    end)
    rv = ok and to_num(ret) or -999
    print(string.format("  modstat(%d) ret=%d", mid, rv))

    if rv == 0 then
        print("    *** SUCCESS ***")
        -- Dump all non-zero qwords
        for off = 0, 0x50, 8 do
            local q = safe_rq(mstat_buf + off)
            local h, l = get_hi_lo(q)
            if h ~= 0 or l ~= 0 then
                print(string.format("    +0x%02X: %s%s", off, hexval(q),
                    (h >= 0xFFFF8000) and " *** KERNEL PTR ***" or ""))
            end
        end
    elseif rv == -999 then
        print("    PCALL FAILED (crash?)")
    end

    if rv == -1 then
        -- Try other version sizes
        for _, vsz in ipairs({0x100, 0x40, 0x30, 0x20}) do
            for i = 0, 0x7F do safe_wd(mstat_buf + i*4, 0) end
            safe_wd(mstat_buf, vsz)
            print(string.format("  calling modstat(%d, ver=0x%X)...", mid, vsz))
            ok, ret = pcall(function()
                return sc_modstat(uint64(mid), uint64(mstat_buf))
            end)
            rv = ok and to_num(ret) or -999
            print(string.format("  modstat(%d, ver=0x%X) ret=%d", mid, vsz, rv))
            if rv == 0 then
                print("    *** SUCCESS ***")
                for off = 0, 0x50, 8 do
                    local q = safe_rq(mstat_buf + off)
                    local h, l = get_hi_lo(q)
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +0x%02X: %s%s", off, hexval(q),
                            (h >= 0xFFFF8000) and " *** KERNEL PTR ***" or ""))
                    end
                end
                break
            end
        end
        break  -- If modid 1 fails all versions, others will too
    end
end

-- [D] kldnext (307) — enumerate kld file IDs
print("")
print("[D] kldnext (sys 307)")
print("  calling kldnext(0)...")
local sc_kldnext = make_syscall(307)
ok, ret = pcall(function() return sc_kldnext(uint64(0)) end)
rv = ok and to_num(ret) or -999
print(string.format("  kldnext(0) = %d", rv))

if rv > 0 then
    print(string.format("  calling kldnext(%d)...", rv))
    local ok2, ret2 = pcall(function() return sc_kldnext(uint64(rv)) end)
    local rv2 = ok2 and to_num(ret2) or -999
    print(string.format("  kldnext(%d) = %d", rv, rv2))
end

-- [E] kldsym (337) — resolve symbol
print("")
print("[E] kldsym (sys 337)")
local sc_kldsym = make_syscall(337)
local sym_buf = memory.alloc(0x40)
for i = 0, 7 do safe_wd(sym_buf + i*4, 0) end

-- Write "printf\0"
for i = 0, 15 do safe_wd(name_buf + i*4, 0) end
safe_wd(name_buf, 0x6E697270)       -- prin
safe_wd(name_buf + 4, 0x00006674)   -- tf\0

safe_wd(sym_buf, 0x20)              -- version
safe_wq(sym_buf + 8, uint64(name_buf))  -- symname ptr
safe_wq(sym_buf + 0x10, uint64(0))  -- symvalue
safe_wq(sym_buf + 0x18, uint64(0))  -- symsize

print("  calling kldsym(0, 1, 'printf')...")
ok, ret = pcall(function()
    return sc_kldsym(uint64(0), uint64(1), uint64(sym_buf))
end)
rv = ok and to_num(ret) or -999
print(string.format("  kldsym ret=%d", rv))
if rv == 0 then
    local val = safe_rq(sym_buf + 0x10)
    print("  *** symvalue: " .. hexval(val) .. " ***")
end

-- [F] kldfind (306) — LAST because 43a showed it can crash
print("")
print("[F] kldfind (sys 306) — may crash")
for i = 0, 15 do safe_wd(name_buf + i*4, 0) end
safe_wd(name_buf, 0x6E72656B)  -- kern
safe_wd(name_buf + 4, 0x00006C65)  -- el\0

print("  calling kldfind('kernel')...")
local sc_kldfind = make_syscall(306)
ok, ret = pcall(function() return sc_kldfind(uint64(name_buf)) end)
rv = ok and to_num(ret) or -999
print(string.format("  kldfind('kernel') = %d", rv))

collectgarbage("restart")
print("")
print("=== PROBE 56k5 COMPLETE ===")
