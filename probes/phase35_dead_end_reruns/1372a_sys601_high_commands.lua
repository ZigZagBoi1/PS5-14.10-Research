-- CRASH_CLASS: MODERATE -- 601 commands 0x1D-0x26 have never been called; 0x1C kills
-- with valid pointers (1371a), so a later one may too
-- PROBE 1372a: sys 601 0x1D-0x26, and does any of them do the 0x1000 copyout?
--
-- 1371a gave every safe 601 command a painted 0x1000-byte destination in arg1 and a
-- painted page in arg2. Nothing in 0x00-0x19 wrote more than two dwords, so the
-- 0x1000-byte alloc-and-copyout block at ca0d6c in the 13.60 listing was not reached;
-- the dossier calls it command 0x10, but 0x10 answers -1 with a valid destination and
-- writes nothing. 1371a then died at 0x1C with no output line and no fault dump, and
-- the loader was gone afterwards (CONNECTION_REFUSED on the next connect).
--
-- ca0d6c is only reachable through the jump table (the block above it ends in a jmp),
-- so the index cannot be decoded offline. The commands 0x1D-0x26 have never been
-- called at all, which is where the block has to be. Behaviour it must show: return 0
-- and write 0x1000 bytes into arg1, the allocation being a recycled uma-zone buffer
-- (zone 0x2bfc080, flags 0x2) that is never written between alloc and copyout -- the
-- first real kernel-heap disclosure if it exists on 14.10.
--
-- Each call is announced before it is made, so a killer costs only the commands after
-- it. Two shapes per command: arg2 null, then arg2 = a valid painted page.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_601_deep.asm:ca0d6c-ca0dd9 (the block)
--   results/kernel_handlers/analysis/sys_601_deep.md:24 (dossier calls 0x10 this)
--   results/phase35_dead_end_reruns/1371a_sys601_writer_sweep_20261109_123328.txt
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt

print("=== PROBE 1372a: SYS 601 0x1D-0x26 ===")

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
            if #d < 8 then d[#d + 1] = v end
            if k_idx < 0 and v ~= 0 and (v >= 0xFFFF8000 or (v >= 0xC0000000 and v < 0xFFFFF000)) then
                k_idx, k_val = i, v
            end
        end
    end
    return changed, d, k_idx, k_val
end

local function call_shape(cmd, dst, arg2, label)
    paint(A, 0x1000)
    local ok, rv = pcall(function() return sc601(U(0, cmd), U(0, dst), U(0, arg2), U(0, 0), U(0, 0), U(0, 0)) end)
    rv = ok and to_num(rv) or -999
    local changed, d, k_idx, k_val = survey(A, 0x1000)
    local s = ""
    for i = 1, #d do s = s .. string.format(" %08X", d[i]) end
    print(string.format("  0x%02X %s : rv=%d  wrote=%d%s", cmd, label, rv, changed, s))
    if k_idx >= 0 then
        print(string.format("      KERNEL-SHAPED A+0x%X = %08X", k_idx, k_val))
    end
end

print(string.format("[0] pid=%d A=0x%X B=0x%X", to_num(make_syscall(20)(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0))), A1, B1))

-- 0x10 with a null arg2 first: 1371a only ever called it with a pointer in arg2,
-- and the 0x1000 alloc block reads no argument other than the destination.
print("[cmd 0x10] calling ...")
call_shape(0x10, A1, 0, "arg2=0 ")

-- 0x1C died in 1371a with a pointer in arg2 and printed nothing. If it is the alloc
-- block, the same call with arg2 null is the cheap discriminating shape.
print("[cmd 0x1C] calling ...")
call_shape(0x1C, A1, 0, "arg2=0 ")
call_shape(0x1C, A1, B1, "arg2=ptr")

for cmd = 0x1D, 0x26 do
    print(string.format("[cmd 0x%02X] calling ...", cmd))
    call_shape(cmd, A1, 0, "arg2=0 ")
    call_shape(cmd, A1, B1, "arg2=ptr")
end

print("=== PROBE 1372a COMPLETE ===")
