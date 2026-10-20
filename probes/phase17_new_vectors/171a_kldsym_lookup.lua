-- CRASH_CLASS: HIGH (kldnext 307 and kldstat 308 kill the process on 14.10)
-- PROBE 171a: kldsym (337) with KLDSYM_LOOKUP
--
-- Theory 11 in docs/UNTESTED_THEORIES.md is the highest-ranked one still open:
-- kldsym resolves a kernel symbol by name, which on success hands over the
-- kernel's own addresses and defeats KASLR in one call. It was never tested -
-- probe 02 covered kldload/kldunload/kldfind/kldnext/kldstat but not kldsym,
-- and 43a/43b never returned output.
--
-- struct kld_sym_lookup { int version; char *symname; u_long symvalue; }
--   KLD_SYMLOOKUP_VERSION = sizeof(struct) = 24
--   KLDSYM_LOOKUP = 1
--
-- Each name is tried in its own pcall and printed separately, so a kill still
-- leaves the names that came before it. fileid 1 is the kernel; -1 and 0 are
-- tried afterwards in case 14.10 numbers them differently.

print("=== PROBE 171a: KLDSYM (337) ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
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

local sc20 = make_syscall(20)
local sc337 = make_syscall(337)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local lk = memory.alloc(0x40)
local namebuf = memory.alloc(0x100)

local function try(fileid, name)
    for i = 0, 0x3F, 4 do safe_wd(lk + i, 0) end
    for i = 0, 0xFC, 4 do safe_wd(namebuf + i, 0) end
    for i = 1, #name do safe_wd(namebuf + i - 1, string.byte(name, i)) end
    safe_wd(lk + 0x00, 24)                    -- version = sizeof(struct)
    safe_wq(lk + 0x08, uint64(namebuf))       -- symname
    safe_wq(lk + 0x10, uint64(0))             -- symvalue out
    local ok, rv = pcall(function()
        return sc337(uint64(fileid), uint64(1), uint64(lk), uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    local sv = safe_rq(lk + 0x10)
    local s_hi, s_lo = 0, 0
    if sv then s_hi, s_lo = get_hi_lo(sv) end
    print(string.format("  fileid=%d name=%-12s ok=%s rv=0x%08X%08X symvalue=0x%08X%08X",
        fileid, name, tostring(ok), hi, lo, s_hi, s_lo))
end

print("[1] fileid 1, kernel symbols")
try(1, "prison0")
try(1, "allproc")
try(1, "kernel_pmap")
try(1, "copyout")
try(1, "sysent")

print("[2] fileid 0 and -1, same first name")
try(0, "prison0")
try(-1, "prison0")

print("[3] canary after: ok=true pid=" .. tostring(to_num(sc20())))
print("=== PROBE 171a DONE ===")
