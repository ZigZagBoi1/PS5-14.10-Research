-- CRASH_CLASS: MODERATE -- 601 commands; 0x03/0x04/0x08/0x0C/0x1B/0x27 are excluded
-- (kill or wedge the loader), the rest have all returned without dying
-- PROBE 1371a: which sys 601 command writes kernel data into a caller buffer?
--
-- The cmd 0x10 branch in the 13.60 listing allocates 0x1000 bytes and copies them
-- straight out (results/kernel_handlers/asm/sys_601_deep.asm):
--
--     ca0d6c  lea rsi,[rip+0x1f5b30d]      ; 0x2bfc080, the uma zone name
--     ca0d73  mov edi,0x1000
--     ca0d78  mov edx,0x2                 ; allocator flags
--     ca0d80  call 0xc08b50               ; allocation, result in rbx
--     ca0d9d  call 0xc1a3e0               ; diagnostic printf
--     ca0da2  mov edx,0x1000
--     ca0da7  mov rdi,r15                 ; arg1, the caller destination
--     ca0daa  mov rsi,rbx                 ; the fresh allocation
--     ca0daf  call 0x259900               ; copyout 0x1000 bytes
--     ca0dcf..ca0dd9                      ; kfree(rbx)
--
-- Nothing between the allocation and the copyout writes the buffer, so if zone
-- 0x2bfc080 hands back recycled memory this is a 4 KiB kernel-heap disclosure -- the
-- first real address leak this project would have. cmd 0x10 has only ever been called
-- as 601(0x10, 0x100, buf) (results/phase35_dead_end_reruns/1355a_...:34-35) and as a
-- state probe in 1357a, never with a real destination in arg1, so the branch above has
-- not actually been exercised.
--
-- This walk gives every safe command a painted 0x2000-byte destination in arg1 and a
-- second painted page in arg2, then reports how much of each was written, the first
-- dwords, and whether any written dword looks like a kernel address. Numbers are called
-- in ascending order after the two best candidates (0x10, 0x0E) so that a kill (if one
-- happens) still leaves the interesting rows on the wire.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_601_deep.asm:ca0d6c-ca0dd9 (alloc + 0x1000 copyout)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--   results/phase35_dead_end_reruns/1357a_sys601_cmd12_gate_20261109_111650.txt
--   probes/phase17_new_vectors/1192a_601_dispatcher_command.lua:33 (kill list)
--   docs/SYS_601_PROCESS_CONTROL_14_10.md

print("=== PROBE 1371a: SYS 601 CALLER-BUFFER WRITERS ===")

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
local function getpid_()
    local ok, v = pcall(function() return make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then return to_num(v) end
    return -1
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function wd(addr, val) pcall(function() memory.write_dword(addr, val) end) end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

local mk = make_syscall
local sc601 = mk(601)

local A = memory.alloc(0x4000)          -- arg1 destination page
local B = memory.alloc(0x4000)          -- arg2 page
local A1 = to_num(A)
local B1 = to_num(B)

local function paint(t, n, v)
    for i = 0, n - 4, 4 do wd(t + i, v) end
end

-- returns changed dword count, first 8 dwords, index of the first kernel-shaped dword
local function survey(t, n)
    local changed, first_k, k_idx = 0, 0, -1
    local d = {}
    for i = 0, n - 4, 4 do
        local v = rd(t + i) or 0xA5A5A5A5
        if v ~= 0xA5A5A5A5 then
            changed = changed + 1
            if #d < 8 then d[#d + 1] = v end
            if k_idx < 0 and (v >= 0xFFFF8000 or (v >= 0xC0000000 and v < 0xFFFFF000)) then
                k_idx = i
            end
        end
    end
    return changed, d, k_idx
end

local function hexlist(d)
    local s = ""
    for i = 1, #d do s = s .. string.format(" %08X", d[i]) end
    return s
end

local order = {0x10, 0x0E, 0x1A, 0x0D, 0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0A,
               0x0F, 0x11, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1C, 0x1D, 0x1E, 0x1F,
               0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26}
local SKIP = {[0x03]=true, [0x04]=true, [0x08]=true, [0x0C]=true, [0x1B]=true, [0x27]=true}

print(string.format("[0] pid=%d A=0x%X B=0x%X", getpid_(), A1, B1))

for i = 1, #order do
    local cmd = order[i]
    if not SKIP[cmd] then
        paint(A, 0x1000, 0xA5A5A5A5)
        paint(B, 0x1000, 0x5A5A5A5A)
        local ok, rv = pcall(function() return sc601(U(0, cmd), U(0, A1), U(0, B1), U(0, 0), U(0, 0), U(0, 0)) end)
        rv = ok and to_num(rv) or -999
        local ca, da, ka = survey(A, 0x1000)
        local cb, db, kb = survey(B, 0x1000)
        print(string.format("  cmd 0x%02X : rv=%d  A=%d%s  B=%d%s",
            cmd, rv,
            ca, #da > 0 and (" [" .. hexlist(da) .. "]") or "",
            cb, #db > 0 and (" [" .. hexlist(db) .. "]") or ""))
        if ka >= 0 then print(string.format("      KERNEL-SHAPED A+0x%X = %08X", ka, rd(A + ka) or 0)) end
        if kb >= 0 then print(string.format("      KERNEL-SHAPED B+0x%X = %08X", kb, rd(B + kb) or 0)) end
    end
end

print("=== PROBE 1371a COMPLETE ===")
