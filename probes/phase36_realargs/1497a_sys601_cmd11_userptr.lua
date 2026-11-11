-- CRASH_CLASS: HIGH -- one lethal call, taken last. Everything is printed before it, and the loader
-- cannot survive a fault inside the kernel, so the capture ends at the call line if it dies.
-- PROBE 1497a: 601 cmd 0x11 dereferences a pointer taken out of the caller's page - what if that
-- pointer is a valid user address?
--
-- Measured so far, all with arg1 = 0 (arg1 must be NULL, else EINVAL):
--   1393a  arg2 = a kernel address          -> EFAULT(14), so arg2 itself is range checked as a user
--                                             pointer and the body runs only for a mapped user page
--   1394a  arg2 = page filled with 0xFFFFFFFFC1000000 -> KILLED
--   1400a  arg2 = page filled with all zeros           -> KILLED, which is the shape of a NULL
--                                             dereference of a field read out of that page
-- So the body reads a pointer out of the page and dereferences it. A kernel fill dies because the
-- value is not a user address; a zero fill dies because it is NULL. Nobody has ever supplied a value
-- that is a VALID mapped user address, which is the only fill that should let the dereference
-- complete - and the interesting question is what the body then does with it.
--
-- [A] build the target page, fill it with the address of a 0x4000 marker page, sentinel the marker
-- [B] one control call, 601(0x00) onto an output buffer, so the capture proves the syscall is healthy
-- [C] print everything, then the single call 601(0x11, 0, page)
-- [D] if it returns: errno, the page's first dwords, and every marker dword that changed
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1393a_sys601_cmd11_kernel_arg2_20261109_141450.txt
--   results/phase35_dead_end_reruns/1394a_sys601_cmd11_field_deref_20261109_141535.txt
--   results/phase36_realargs/1400a_sys601_cmd11_struct_20261109_144119.txt
--   results/phase36_realargs/1476a_sys601_cmd11_pointer_field.lua (designed, never sent)

print("=== PROBE 1497a: 601 CMD 0x11 WITH A VALID USER POINTER ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h, l = N(v.h), N(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return h * 4294967296 + l
end
local function dw(a) return N(memory.read_dword(a)) end
local function wd(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local function amap(n)
    local ok, v = pcall(function()
        return mk(477)(uint64(0), uint64(n), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return -1 end
    return sgn(v)
end

-- ---------------------------------------------------------------- [A]
print("")
print("--- [A] the page and the marker ---")
local MARK = amap(0x4000)
local PAGE = amap(0x4000)
print(string.format("  marker 0x%X page 0x%X", MARK, PAGE))
if MARK < 0x10000 or PAGE < 0x10000 then
    print("  could not map; stopping")
    print("=== PROBE 1497a INCOMPLETE ===")
    return
end
-- sentinel the marker, 0xA5A5A5A5 everywhere
for i = 0, 0x3FFF, 4 do wd(MARK + i, 0xA5A5A5A5) end
-- fill the page with the marker's address as 64-bit and as 32-bit values
for i = 0, 0x3FFF, 8 do
    wd(PAGE + i, MARK % 4294967296)
    wd(PAGE + i + 4, math.floor(MARK / 4294967296))
end
print(string.format("  page[0..7] = %08X %08X %08X %08X", dw(PAGE), dw(PAGE + 4), dw(PAGE + 8), dw(PAGE + 12)))
print(string.format("  marker[0]  = %08X (sentinel)", dw(MARK)))

-- ---------------------------------------------------------------- [B] control
print("")
print("--- [B] control: 601(0x00) onto an output buffer ---")
local out = amap(0x1000)
if out > 0x10000 then
    wd(out, 0x11111111)
    local ok, rv = pcall(function() return N(mk(601)(uint64(0), uint64(out), uint64(0), uint64(0x100), uint64(0), uint64(0))) end)
    print(string.format("  601(0x00) rv=%s out=%08X %08X", ok and tostring(rv) or "EXC", dw(out), dw(out + 4)))
else
    print("  could not map the control buffer")
end

-- ---------------------------------------------------------------- [C] the one call
print("")
print("--- [C] 601(0x11, arg1=0, arg2=page filled with a valid user pointer) ---")
print("  (if the capture ends here, the body dereferenced the field and died)")
local ok, rv = pcall(function()
    return N(mk(601)(uint64(0x11), uint64(0), uint64(PAGE), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("  returned: ok=%s rv=%s %s", tostring(ok), ok and tostring(rv) or "EXC",
    (ok and rv == -1) and es() or ""))

-- ---------------------------------------------------------------- [D]
print("")
print("--- [D] what happened to the page and the marker ---")
print(string.format("  page[0..3]   = %08X %08X %08X %08X", dw(PAGE), dw(PAGE + 4), dw(PAGE + 8), dw(PAGE + 12)))
local changed = 0
local first = -1
for i = 0, 0x3FFF, 4 do
    local v = dw(MARK + i)
    if v ~= 0xA5A5A5A5 then
        changed = changed + 1
        if first < 0 then first = i end
    end
end
print(string.format("  marker dwords changed: %d of 4096 (first at +0x%X)", changed, first))
if changed > 0 and first >= 0 then
    print(string.format("  marker[+0x%X] = %08X %08X %08X %08X", first,
        dw(MARK + first), dw(MARK + first + 4), dw(MARK + first + 8), dw(MARK + first + 12)))
end
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1497a COMPLETE ===")
