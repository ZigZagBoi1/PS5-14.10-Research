-- CRASH_CLASS: MODERATE -- 601 commands 0x1D-0x26 with a null arg2 first; the arg2=ptr
-- retry pass runs last so a kill there costs no earlier row
-- PROBE 1372b: finish the 601 command map, and look for the 0x1000 copyout block
--
-- 1372a (results/phase35_dead_end_reruns/1372a_sys601_high_commands_20261109_124039.txt)
-- measured: 0x10 arg2=0 -> -1 (no write), 0x1C arg2=0 -> -1 (no write), 0x1C arg2=valid
-- pointer -> process death with no further output. 1371a had already died at 0x1C with a
-- pointer in arg2, so 0x1C reads its second argument as a pointer and faults after the
-- copyin, the same shape the 622 0x400 arm shows.
--
-- So the 0x1000-byte alloc-and-copyout block at ca0d6c in the 13.60 listing is still
-- unlocated. 0x10 is not it. The remaining untested indices are 0x1D-0x26 plus the
-- known killers 0x03/0x04/0x08/0x0C/0x0B/0x1B/0x27.
--
-- This run takes 0x1D-0x26 with arg2 null first -- the null shape has never killed any
-- command whose index is inside arg1 (0x10 and 0x1C both returned -1) -- prints every
-- row, and only then replays with a pointer in arg2 for the commands that answered 0 or
-- wrote anything. Behaviour the block must show: rv=0 and 0x1000 bytes written into
-- arg1, the buffer never written between the uma allocation and the copyout.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_601_deep.asm:ca0d6c-ca0dd9 (the block)
--   results/kernel_handlers/analysis/sys_601_deep.md:24
--   results/phase35_dead_end_reruns/1371a_sys601_writer_sweep_20261109_123328.txt
--   results/phase35_dead_end_reruns/1372a_sys601_high_commands_20261109_124039.txt

print("=== PROBE 1372b: SYS 601 0x1D-0x26 ===")

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
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function wd(addr, val) pcall(function() memory.write_dword(addr, val) end) end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

local sc601 = make_syscall(601)
local A = memory.alloc(0x4000)
local B = memory.alloc(0x4000)
local A1, B1 = to_num(A), to_num(B)

local PAINT = 0xA5A5A5A5
local function paint(t, n) for i = 0, n - 4, 4 do wd(t + i, PAINT) end end

local function survey(t, n)
    local changed, d, k_idx, k_val = 0, {}, -1, 0
    for i = 0, n - 4, 4 do
        local v = rd(t + i)
        if v ~= nil and v ~= PAINT then
            changed = changed + 1
            if #d < 6 then d[#d + 1] = v end
            if k_idx < 0 and v ~= 0 and (v >= 0xFFFF8000 or (v >= 0xC0000000 and v < 0xFFFFF000)) then
                k_idx, k_val = i, v
            end
        end
    end
    return changed, d, k_idx, k_val
end

local resume = {}

local function call_shape(cmd, dst, arg2, label)
    paint(A, 0x1000)
    local ok, rv = pcall(function() return sc601(U(0, cmd), U(0, dst), U(0, arg2), U(0, 0), U(0, 0), U(0, 0)) end)
    rv = ok and to_num(rv) or -999
    local changed, d, k_idx, k_val = survey(A, 0x1000)
    local s = ""
    for i = 1, #d do s = s .. string.format(" %08X", d[i]) end
    print(string.format("  0x%02X %s : rv=%d  wrote=%d%s", cmd, label, rv, changed, s))
    if k_idx >= 0 then print(string.format("      KERNEL-SHAPED A+0x%X = %08X", k_idx, k_val)) end
    return rv, changed
end

print(string.format("[0] pid=%d A=0x%X B=0x%X", to_num(make_syscall(20)(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0))), A1, B1))

print("[A] arg2 null")
for cmd = 0x1D, 0x26 do
    print(string.format("[cmd 0x%02X] calling ...", cmd))
    local rv, changed = call_shape(cmd, A1, 0, "arg2=0 ")
    if rv == 0 or changed > 0 then resume[#resume + 1] = cmd end
end

print("[B] replay with a pointer in arg2: " .. #resume .. " command(s)")
for i = 1, #resume do
    local cmd = resume[i]
    print(string.format("[cmd 0x%02X] calling (ptr) ...", cmd))
    call_shape(cmd, A1, B1, "arg2=ptr")
end

print("=== PROBE 1372b COMPLETE ===")
