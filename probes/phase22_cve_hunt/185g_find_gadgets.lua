-- CRASH_CLASS: LOW
-- PROBE 185g: Find jmp $ gadget in eboot
--
-- mov [rdi],rax;ret confirmed at eboot+0x92C67
-- Need to find jmp $ (EB FE) — scanning full text section

print("=== 185g: FIND GADGETS ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end

-- Eboot base and text size
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
local tsz_lo = rd(info + 0x118)
local tsz_hi = rd(info + 0x11C)
print("eb=0x" .. string.format("%X%08X", eb_hi, eb_lo))
print("text_size=0x" .. string.format("%X%08X", tsz_hi, tsz_lo))

-- Scan for EB FE (jmp $) at 4-byte alignment, checking all positions
-- Also look for ret (C3), pop rdi;ret (5F C3), nop;ret (90 C3)
local jmp_count = 0
local ret_first = nil
local pop_rdi_ret = nil

local scan_end = tsz_lo
if scan_end > 0x400000 then scan_end = 0x400000 end

for off = 0, scan_end, 4 do
    local ok, dw = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
    if not ok then
        print("read failed @0x" .. string.format("%X", off))
        break
    end
    local v = to_num(dw)

    -- Check for EB FE at byte positions 0-1, 1-2, 2-3
    local b0 = v % 256
    local b1 = math.floor(v / 256) % 256
    local b2 = math.floor(v / 65536) % 256
    local b3 = math.floor(v / 16777216) % 256

    if b0 == 0xEB and b1 == 0xFE then
        jmp_count = jmp_count + 1
        if jmp_count <= 3 then
            print("jmp$ @0x" .. string.format("%X", off) .. " (pos 0)")
        end
    end
    if b1 == 0xEB and b2 == 0xFE then
        jmp_count = jmp_count + 1
        if jmp_count <= 3 then
            print("jmp$ @0x" .. string.format("%X", off + 1) .. " (pos 1)")
        end
    end
    if b2 == 0xEB and b3 == 0xFE then
        jmp_count = jmp_count + 1
        if jmp_count <= 3 then
            print("jmp$ @0x" .. string.format("%X", off + 2) .. " (pos 2)")
        end
    end

    -- pop rdi; ret = 5F C3
    if not pop_rdi_ret then
        if b0 == 0x5F and b1 == 0xC3 then
            pop_rdi_ret = off
        elseif b1 == 0x5F and b2 == 0xC3 then
            pop_rdi_ret = off + 1
        elseif b2 == 0x5F and b3 == 0xC3 then
            pop_rdi_ret = off + 2
        end
    end

    -- Limit scan time
    if jmp_count >= 3 and pop_rdi_ret then break end
end

print("jmp$ total=" .. jmp_count)
if pop_rdi_ret then print("pop_rdi_ret @0x" .. string.format("%X", pop_rdi_ret)) end

print("=== DONE ===")
