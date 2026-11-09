-- CRASH_CLASS: HIGH
-- PROBE 803g: can 548 op 2 lower an existing executable page to writable?
--
-- Anonymous mappings cap at RW (measured in 803e), so the only way to get code we wrote into an
-- executable page is to make an existing text page writable and then raise it back.  That works
-- only if such a page's max_protection includes both W and X.  This probe asks op 2 for prot 3
-- (RW), prot 5 (RX) and prot 7 (RWX) on one eboot text page, one libc text page and, as
-- controls, one anonymous page and one heap page, restoring the original protection each time.
--
-- The write test only runs if a text page actually reports prot 3: it saves the first byte,
-- writes a canary, reads it back and restores the byte.

print("=== PROBE 803g: 548 OP 2 ON EXISTING TEXT PAGES ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rdb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) % 256 end
    return nil
end
local function wrb(a, v) return pcall(function() memory.write_byte(a, v) end) end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function split(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = rdb(a + i) or 0
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end

local getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc548 = make_syscall(548)
local sc_mmap = make_syscall(477)
pcall(function() return getpid() end)

local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)

local function scan()
    wq(countp, uint64(0))
    local ok = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return 0 end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
    return n
end

local function region_of(va)
    local n = scan()
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        if va >= lo and va < hi then
            return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18)
        end
    end
    return nil
end

-- first region with a given protection and a given name substring
local function find_region(want_prot, name_sub)
    local n = scan()
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        local p = rd(b + 0x18) or 0
        local nm = ascii(b + 0x20, 0x18)
        if p == want_prot and (name_sub == nil or nm:find(name_sub, 1, true)) then
            return lo, hi, p, nm
        end
    end
    return nil
end

local recs = memory.alloc(0x20 * 8)
local function protect(addr, len, prot)
    local b = recs
    wq(b, split(0, addr))
    wq(b + 8, split(0, 0))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, 2)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end

local function probe_page(tag, addr, pages)
    local _, _, p0 = region_of(addr)
    print(string.format("[%s] %X original prot=%s", tag, addr, tostring(p0)))
    if p0 == nil then return end
    for _, want in ipairs({3, 5, 7}) do
        local r = protect(addr, 0x4000, want)
        local _, _, p = region_of(addr)
        print(string.format("   want=%d ret=%-4s prot=%s", want, tostring(r), tostring(p)))
        if p ~= nil and p ~= want then
            -- restore
            protect(addr, 0x4000, p0)
        end
    end
    local _, _, p1 = region_of(addr)
    if p1 ~= p0 then
        local r = protect(addr, 0x4000, p0)
        local _, _, p2 = region_of(addr)
        print(string.format("   restore -> %s (ret=%s)", tostring(p2), tostring(r)))
    end
end

local e_lo, e_hi, e_p, e_nm = find_region(5, ".executable")
if e_lo then
    local page = e_hi - 0x4000
    probe_page("eboot", page)
    local _, _, p = region_of(page)
    if p == 3 then
        local orig = rdb(page)
        local okw = wrb(page, 0x90)
        local now = rdb(page)
        print(string.format("   write test: orig=%02X wrote=90 read=%s ok=%s",
            orig or -1, tostring(now), tostring(okw)))
        wrb(page, orig or 0)
        print(string.format("   restored byte -> %s", tostring(rdb(page))))
        protect(page, 0x4000, 5)
        local _, _, p3 = region_of(page)
        print(string.format("   back to RX -> prot=%s", tostring(p3)))
    end
else
    print("[eboot] no prot-5 .executable region found")
end

print("")
local l_lo, l_hi, l_p, l_nm = find_region(5, ".libc.prx")
if l_lo then
    probe_page("libc", l_lo + 0x8000)
else
    print("[libc] no prot-5 libc region found")
end

print("")
local heap = find_region(3, "SceLibcHeap")
if heap then probe_page("heap", heap) end
local anon = memory.alloc(0x4000)
probe_page("anon", anon)

print("")
print("[Z] alive pid=" .. to_num(getpid()))
