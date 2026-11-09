-- CRASH_CLASS: HIGH
-- PROBE 833a: 601 as a uio (iovec pointer + count + residual)
--
-- sub_00ca32b0 in the 13.60 body reads its second parameter as a uio:
--   [+0x00] iovec pointer   [+0x08] iovcnt   [+0x10] offset
--   [+0x18] residual        [+0x20] direction [+0x24] flag
-- and loops { pop a chunk from the kernel ring buffer 0x3e0d870; uiomove(...);
-- } while residual > 0, with the buffer built by 0xc06260(0x3e0d880,...).  The
-- syscall frame supplies those fields at uap[1], uap[2], uap[3], uap[4], uap[5],
-- so a real call is 601(cmd, iov, iovcnt, residual, direction, flag).
--
-- The commands that answered 0 with an untouched page (07, 09, 0b, 13) are the
-- candidates: before, iovec pointed at zeros, so uiomove moved 0 bytes.

print("=== PROBE 833a: 601 with a well-formed uio ===")
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
local OUT = 0x400
local out = memory.alloc(OUT)
local iov = memory.alloc(0x10)
local KERN = 0

local function zero_out()
    for i = 0, OUT - 1, 8 do memory.write_qword(out + i, 0) end
    memory.write_qword(iov, to_num(out) + OUT - 8)
    memory.write_qword(iov + 8, OUT - 8)
end

local function report(tag)
    local nz, kern, ascii = 0, 0, ""
    for off = 0, OUT - 8, 8 do
        local lo = to_num(memory.read_dword(out + off))
        local hi = to_num(memory.read_dword(out + off + 4))
        if hi ~= 0 or lo ~= 0 then nz = nz + 1 end
        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
            kern = kern + 1
            if KERN < 8 then
                KERN = KERN + 1
                print(string.format("    %s KERN +0x%03X = %08X%08X", tag, off, hi, lo))
            end
        end
    end
    for i = 0, 63 do
        local b = to_num(memory.read_byte(out + i))
        if b >= 32 and b < 127 then
            ascii = ascii .. string.char(b)
        else
            ascii = ascii .. "."
        end
    end
    print(string.format("  %s nonzero-qwords=%d kernel-shaped=%d txt=[%s]", tag, nz, kern, ascii))
end

local function run(cmd, residual, direction, label)
    zero_out()
    print(string.format("[*] %s cmd=%X residual=%X dir=%X", label, cmd, residual, direction))
    local ok, r = pcall(function()
        return sc601(uint64(cmd), uint64(to_num(iov)), uint64(1), uint64(residual), uint64(direction), uint64(0))
    end)
    if not ok then print("  PCALL-FAIL") return end
    print(string.format("  ret=%s", hx(r)))
    report(label)
end

run(0x09, 0x200, 0, "A")
run(0x07, 0x200, 0, "B")
run(0x0b, 0x200, 0, "C")
run(0x13, 0x200, 0, "D")
run(0x09, 0x200, 1, "E")
run(0x07, 0x200, 1, "F")
run(0x00, 0x200, 0, "G")

print("[Z] alive=true")
print("=== PROBE 833a COMPLETE ===")
