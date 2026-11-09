-- CRASH_CLASS: LOW
-- PROBE 552f: Find the REAL MapDirectMemory address
--
-- libkernel+0x15020 kills the process on ANY call (fcall or SROP).
-- It might not be MapDirectMemory at all, or it's auth-gated.
--
-- Strategy:
--   1. Try dlsym (syscall 591) to resolve "sceKernelMapDirectMemory" by name
--   2. Try dynlib_get_proc (syscall 592) with known NID
--   3. Scan eboot GOT for pointers into libkernel to catalog imports
--   4. Dump dynlib_get_info extended fields to find data segment

print("=== PROBE 552f: Find real MapDirectMemory address ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- eboot info
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- libkernel
local lk_handle = nil
local lk_lo, lk_hi, lk_size = 0, 0, 0
local handles_to_try = {0x2001}
for h = 0, 0x100 do handles_to_try[#handles_to_try + 1] = h end
for _, h in ipairs(handles_to_try) do
    local ib3 = memory.alloc(0x200)
    wd(N(ib3), 0x160)
    local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
    if ok3 and N(r3) == 0 then
        local name = ""
        for i = 0, 31 do
            local b = rd(N(ib3) + 8 + i)
            if b then local c = b % 256; if c == 0 then break end
                if c >= 32 and c < 127 then name = name .. string.char(c) end
            end
        end
        if name:find("libkernel") then
            lk_handle = h
            lk_lo = rd(N(ib3) + 0x108) or 0
            lk_hi = rd(N(ib3) + 0x10C) or 0
            lk_size = rd(N(ib3) + 0x110) or 0
            if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
            if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
            if lk_size < 0 then lk_size = lk_size + 0x100000000 end
            print(string.format("libkernel: handle=%d base=0x%X%08X size=0x%X name=%s",
                h, lk_hi, lk_lo, lk_size, name))
            -- Dump full info struct
            print("  dynlib_info dump:")
            for off = 0, 0x15F, 4 do
                local v = rd(N(ib3) + off)
                if v and v ~= 0 then
                    print(string.format("    +0x%03X: 0x%08X (%d)", off, v < 0 and v + 0x100000000 or v, v))
                end
            end
            break
        end
    end
end
if not lk_handle then print("FAIL: libkernel not found"); return end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

-- ============================================================
-- [A] Try dlsym (syscall 591) for known function names
-- ============================================================
print("")
print("[A] dlsym test (syscall 591)")
local sc_dlsym = mk(591)

local names = {
    "sceKernelMapDirectMemory",
    "sceKernelMapNamedDirectMemory",
    "sceKernelMapFlexibleMemory",
    "sceKernelMapNamedFlexibleMemory",
    "sceKernelMmap",
    "sceKernelAllocateDirectMemory",
    "sceKernelGetDirectMemorySize",
}

for _, name in ipairs(names) do
    local nbuf = memory.alloc(#name + 1)
    for i = 1, #name do wd(N(nbuf) + i - 1, string.byte(name, i)) end
    wd(N(nbuf) + #name, 0)

    local out = memory.alloc(8)
    wq(N(out), uint64(0))

    local ok_d, rv_d = pcall(function()
        return sc_dlsym(uint64(lk_handle), uint64(N(nbuf)), uint64(N(out)))
    end)

    local addr = rq(N(out))
    local rv = ok_d and N(rv_d) or -999
    if rv == 0 and addr then
        local ah, al = get_hi_lo(addr)
        if ah < 0 then ah = ah + 0x100000000 end
        if al < 0 then al = al + 0x100000000 end
        local offset = al - lk_lo + (ah - lk_hi) * 0x100000000
        print(string.format("  %s = %s (lk+0x%X) rv=%d",
            name, fmt(addr), offset, rv))
    else
        print(string.format("  %s = FAIL rv=%d", name, rv))
    end
end

-- ============================================================
-- [B] Known-good function offset verification
-- ============================================================
print("")
print("[B] Verify known offsets via dlsym")
-- Check that AllocateDirectMemory resolves to +0x17EF0
-- and GetDirectMemorySize resolves to +0x17810

-- ============================================================
-- [C] Scan eboot for GOT entries pointing to libkernel
-- ============================================================
print("")
print("[C] Scan eboot data for libkernel pointers")

-- Read eboot data segment from dynlib_info
local eb_data_lo = rd(N(ib) + 0x120) or 0
local eb_data_hi = rd(N(ib) + 0x124) or 0
local eb_data_sz = rd(N(ib) + 0x128) or 0
if eb_data_lo < 0 then eb_data_lo = eb_data_lo + 0x100000000 end
if eb_data_hi < 0 then eb_data_hi = eb_data_hi + 0x100000000 end
if eb_data_sz < 0 then eb_data_sz = eb_data_sz + 0x100000000 end

print(string.format("  eboot data: 0x%X%08X size=0x%X", eb_data_hi, eb_data_lo, eb_data_sz))

if eb_data_sz > 0 and eb_data_sz < 0x1000000 then
    local data_base = uint64(string.format("0x%X%08X", eb_data_hi, eb_data_lo))
    local scan_count = 0
    local found = {}

    -- Scan for qword values in libkernel text range
    local scan_sz = math.min(eb_data_sz, 0x100000)
    for off = 0, scan_sz - 8, 8 do
        local v = rq(N(data_base) + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            -- Check if pointer falls in libkernel text range
            if vh == lk_hi and vl >= lk_lo and vl < lk_lo + lk_size then
                local lk_off = vl - lk_lo
                table.insert(found, {off = off, lk_off = lk_off, addr = fmt(v)})
                if #found <= 50 then
                    print(string.format("    data+0x%06X → lk+0x%05X  %s",
                        off, lk_off, fmt(v)))
                end
            end
        end
        scan_count = scan_count + 1
        if scan_count % 50000 == 0 then io.flush() end
    end
    print(string.format("  scanned %d qwords, found %d libkernel pointers", scan_count, #found))
else
    print("  data segment not found or too large — trying offset guesses")
    -- Try reading at common GOT-relative offsets from eboot base
    -- PS5 eboot data typically starts at text+textsize
    local eb_text_sz = rd(N(ib) + 0x110) or 0
    if eb_text_sz < 0 then eb_text_sz = eb_text_sz + 0x100000000 end
    print(string.format("  eboot text size=0x%X", eb_text_sz))
end

print("")
print("DONE")
