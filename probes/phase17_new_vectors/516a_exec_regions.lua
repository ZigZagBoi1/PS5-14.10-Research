-- CRASH_CLASS: LOW
-- PROBE 516a: map every RX region and scan the eboot tail for a syscall gadget.
--
-- 515a: sys 674 prot bits are 1=read, 2=write, 4=exec.  The loader's fn target is
-- RW heap, so it is not code.  The main image is the region named ".executable"
-- (prot 5) and last session's 4 MB scan covered only the first 4 MB of a
-- 0x494000-byte region.  This lists every RX region by name and scans the
-- uncovered tail for `0F 05` (syscall).

print("=== PROBE 516a: RX REGIONS AND EXEC TAIL ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
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
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end

local sc_getpid = make_syscall(20)
local sc674 = make_syscall(674)
pcall(function() return sc_getpid() end)

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(buf + i, 0) end
local countp = memory.alloc(16)
wq(countp, uint64(0))
local ok, ret = pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
local count = rd(countp) or 0
print(string.format("[0] 674 ret=%s regions=%d", ok and tostring(to_num(ret)) or "pcall-fail", count))
if count > MAX then count = MAX end

local exec_lo, exec_hi = nil, nil
print("[1] regions with exec bit:")
for i = 0, count - 1 do
    local base = buf + i * STRIDE
    local prot = rd(base + 0x18) or 0
    if (prot % 8) >= 4 then
        local lo = (rd(base) or 0) + (rd(base + 4) or 0) * 4294967296
        local hi = (rd(base + 8) or 0) + (rd(base + 12) or 0) * 4294967296
        local name = ascii(base + 0x20, 0x18)
        print(string.format("    [%08X,%08X) p=%X %s", lo, hi, prot, name))
        if name:find("executable") and (exec_hi == nil or (hi - lo) > (exec_hi - exec_lo)) then
            exec_lo, exec_hi = lo, hi
        end
    end
end

if not exec_lo then print("[2] no .executable region"); print("=== DONE ==="); return end
print(string.format("[2] scanning .executable tail [%X,%X)", exec_lo, exec_hi))
local scan_lo = exec_lo + 0x400000
if scan_lo < exec_lo then scan_lo = exec_lo end
local hits = 0
local t0 = os.clock()
for a = scan_lo, exec_hi - 4, 1 do
    local d = rd(a)
    if d and (d % 65536) == 0x050F then
        hits = hits + 1
        if hits <= 20 then
            local d2 = rd(a + 2) or 0
            print(string.format("    syscall at %08X next bytes %02X %02X %02X",
                a, d2 % 256, math.floor(d2 / 256) % 256, math.floor(d2 / 65536) % 256))
        end
    end
end
print(string.format("[2] hits=%d scanned=%d bytes in %.1fs", hits, exec_hi - scan_lo, os.clock() - t0))
print("=== DONE ===")
