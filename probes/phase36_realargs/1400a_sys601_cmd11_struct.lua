-- CRASH_CLASS: HIGH -- 601(0x11, 0, page) dereferences fields out of page; a page full of kernel
-- addresses killed the process in 1394a.  This probe uses only user addresses and zeros.
-- PROBE 1400a: what does 601 cmd 0x11 do with a benign struct?
--
-- 1393a established the shape: arg1 must be 0 (EINVAL 22 otherwise) and arg2 is range-checked as a
-- user pointer (EFAULT 14 when it is a kernel address).  1394a then filled arg2 with 0xFFFFFFFFC1000000
-- and the very first call killed the process, so the body dereferences fields of the struct.
--
-- Nothing has ever come back from a benign struct: every capture died on the first call.  This probe
-- asks three things in order, printing before each call:
--   [A] arg2 = an all-zero page           -> does it return, and what does it write back?
--   [B] arg2 = a page of user pointers    -> every field points at our own buffer, so a deref lands
--                                            in memory we own; if the body writes through a field we
--                                            will see it in the buffer
--   [C] arg2 = one user pointer + zeros   -> narrows which field is followed
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1393a_sys601_cmd11_kernel_arg2_20261109_141450.txt
--   results/phase35_dead_end_reruns/1394a_sys601_cmd11_field_deref_20261109_141535.txt

print("=== PROBE 1400a: 601 CMD 0x11 WITH A BENIGN STRUCT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function rq(a) local ok,v = pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function hex(v) return string.format("%08X", v % 4294967296) end
local function hexx(v) return string.format("%016X", v) end
local function addr_of(v) local h = math.floor(v / 4294967296) return string.format("0x%08X%08X", h, v % 4294967296) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc = mk(601)

-- the page the kernel reads, and the buffer every field will point at
local page = N(mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("[0] page -> %s", addr_of(page)))
local BUFVA = N(mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
local buf = BUFVA
for i = 0, 0x3FF, 4 do pcall(function() memory.write_dword(buf + i, uint64(0xA5A5A5A5)) end) end
print(string.format("[0] buf  -> %s", addr_of(BUFVA)))

local function zero_page()
    for i = 0, 0x3FF, 8 do wq(page + i, 0) end
end
local function snap_dwords(base, n)
    local t = {}
    for i = 0, n - 1 do t[i] = rd(base + i * 4) or 0 end
    return t
end
local function diff(base, n, tag)
    local changed, first = 0, -1
    for i = 0, n - 1 do
        local v = rd(base + i * 4) or 0
        if v ~= 0 then
            changed = changed + 1
            if first < 0 then first = i end
            if changed <= 16 then print(string.format("     %s+0x%03X = %s", tag, i * 4, hex(v))) end
        end
    end
    print(string.format("   %s: %d of %d dwords non-zero, first at +0x%X", tag, changed, n, first * 4))
    return changed
end

-- ---------------------------------------------------------------- A
print("")
print("[A] all-zero struct")
zero_page()
print("   calling 601(0x11, 0, page) ...")
local rv = N(sc(uint64(0x11), uint64(0), uint64(page), uint64(0), uint64(0), uint64(0)))
print(string.format("   <- rv=%d  %s", rv, es()))
if rv == -1 or rv == 4294967295 then print("   (errno only meaningful on -1)") end
diff(page, 0x100, "page")

-- ---------------------------------------------------------------- B
print("")
print("[B] struct of user pointers, buffer pre-filled with A5")
zero_page()
for i = 0, 0xFF, 8 do wq(page + i, BUFVA + (i % 0x40)) end
print("   calling 601(0x11, 0, page) with 32 user pointers ...")
rv = N(sc(uint64(0x11), uint64(0), uint64(page), uint64(0), uint64(0), uint64(0)))
print(string.format("   <- rv=%d  %s", rv, es()))
diff(page, 0x100, "page")
local bchg = 0
for i = 0, 0x3FF, 4 do
    local v = rd(buf + i) or 0
    if v ~= 0xA5A5A5A5 then
        bchg = bchg + 1
        if bchg <= 16 then print(string.format("     buf+0x%03X now %s", i, hex(v))) end
    end
end
print(string.format("   buf: %d of 256 dwords changed", bchg))

-- ---------------------------------------------------------------- C
print("")
print("[C] only the first field is a user pointer")
zero_page()
wq(page, BUFVA)
print("   calling 601(0x11, 0, page) with field0 = user ptr ...")
rv = N(sc(uint64(0x11), uint64(0), uint64(page), uint64(0), uint64(0), uint64(0)))
print(string.format("   <- rv=%d  %s", rv, es()))
diff(page, 0x40, "page")

print("")
print("[Z] alive check")
print(string.format("   pid still %d", N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

print("")
print("=== PROBE 1400a COMPLETE ===")
