-- CRASH_CLASS: HIGH
-- PROBE 832a: 601 commands with a non-zero length argument
--
-- The 13.60 body sub_00ca32b0 (one of the command handlers) treats its second
-- parameter as a uio: [+0] iovec, [+8] iovcnt, [+0x10] offset, [+0x18] residual,
-- [+0x20] direction, and loops over a kernel ring buffer copying bytes out with
-- 0x782520 -> uiomove -> copyout 0x2591d0.  Every earlier 601 probe passed only
-- three arguments, so arg4 (uap[3]) was zero and the loop never ran: ret 0, page
-- untouched.  This repeats the surviving commands with arg3/arg4 filled in.
--
-- Safe commands first, the ones that returned -1 later, so a kill keeps the rows.

print("=== PROBE 832a: 601 with a length argument ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return to_num(v.h), to_num(v.l) end
    return 0, to_num(v)
end

local sc601 = make_syscall(601)
local PAGE = 0x2000
local page = memory.alloc(PAGE)
local KERN, LOW = 0, 0

local function zero_page()
    for i = 0, PAGE - 1, 8 do memory.write_qword(page + i, 0) end
end

local function scan(tag)
    local first, nz, kern = 0, 0, 0
    local q0 = memory.read_qword(page)
    for off = 0, PAGE - 8, 8 do
        local v = memory.read_qword(page + off)
        local h = get_hi_lo(v)
        if h ~= 0 then nz = nz + 1 end
        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
            kern = kern + 1
            if KERN < 6 then
                KERN = KERN + 1
                print(string.format("    %s KERN +0x%03X = %s", tag, off, hx(v)))
            end
        end
    end
    print(string.format("  %s page q0=%s nonzero-qwords=%d kernel-shaped=%d", tag, hx(q0), nz, kern))
end

local function run(cmd, a2, a3, a4, label)
    zero_page()
    print(string.format("[*] %s cmd=%X a2=%s a3=%s a4=%s", label, cmd, hx(a2), hx(a3), hx(a4)))
    local ok, r = pcall(function() return sc601(uint64(cmd), a2, a3, a4) end)
    if not ok then print("  PCALL-FAIL") return end
    print(string.format("  ret=%s", hx(r)))
    scan(label)
end

local P = uint64(to_num(page))

-- safe rows: these returned 0 with three arguments before
run(0x00, P, uint64(0x1000), uint64(0x100), "A")
run(0x07, P, uint64(0x1000), uint64(0x100), "B")
run(0x0b, P, uint64(0x1000), uint64(0x100), "C")
run(0x13, P, uint64(0x1000), uint64(0x100), "D")
run(0x09, P, uint64(0x1000), uint64(0x100), "E")

-- layout variants on the two that answer 0
run(0x00, uint64(0x1000), P, uint64(0x100), "F")
run(0x09, uint64(0x1000), P, uint64(0x100), "G")
run(0x0b, uint64(0x1000), P, uint64(0x100), "H")

-- rows that returned -1 with three arguments
run(0x05, P, uint64(0x1000), uint64(0x100), "I")
run(0x06, P, uint64(0x1000), uint64(0x100), "J")
run(0x0a, P, uint64(0x1000), uint64(0x100), "K")
run(0x10, P, uint64(0x1000), uint64(0x100), "L")
run(0x10, P, uint64(0), uint64(0x1000), "M")
run(0x12, P, uint64(0x1000), uint64(0x100), "N")

print("[Z] alive=true")
print("=== PROBE 832a COMPLETE ===")
