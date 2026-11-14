-- CRASH_CLASS: MODERATE -- maps our own shm and dmem memory, writes markers, splits an entry with
-- 548 op 2, then reads back. A wrong read could fault, so every read prints first and the dmem
-- variant runs last.
-- PROBE 1505a: does vm_map clipping rewrite the shared object's window?
--
-- 13.60 vm_map_clip_end (0xffffffff8ac8b770) and clip_start (0xffffffff8ac8b4e0) contain a block
-- FreeBSD r230171 does not have:
--
--   8ac8b7a1  cmp byte ptr [rdi + 0x9d], 2      ; object type == 2
--   8ac8b7a8  sete r13b
--   8ac8b7c2  cmp qword ptr [rbx + 0x70], 0     ; entry has a side object
--   8ac8b7c7  je  skip
--   8ac8b7d4  call 0x8b1946a0                   ; lock obj+0x18
--   8ac8b7e5  mov qword ptr [rax + 0x1a0], rcx ; obj->[0x1a0] = entry->[0x70]
--   8ac8b7ec  mov rax, [rbx + 0x28]             ; entry->end
--   8ac8b7f0  sub rax, [rbx + 0x20]             ; - entry->start
--   8ac8b7f8  mov qword ptr [rcx + 0x1a8], rax ; obj->[0x1a8] = entry length
--
-- i.e. the object - SHARED by every entry that maps it - takes its window pointer and window
-- length from whichever single entry was clipped last. FreeBSD keeps all of that in the entry.
-- If a later fault, protect or teardown reads obj+0x1a0/0x1a8, it will address geometry that
-- belongs to only one of two aliases.
--
-- 548 op 2 is a real vm_map_protect and vm_map_protect clips when the range does not cover the
-- whole entry, so a userland process can force the clip. Test on the only object we can map twice:
-- a POSIX shm object mapped at two addresses.
--
-- [A] shm object, two MAP_SHARED aliases A and B, markers at four offsets, confirm A and B alias
-- [B] 548 op 2 prot 1 on [A+0x4000, A+0x8000) - forces clip_start and clip_end on A's entry
-- [C] re-read A and B at every offset: do the markers survive, shift, or fault?
-- [D] same on a /dev/dmem0 mapping (four different physical offsets, so a shift is visible)
--
-- -- prior art:
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (548 op2 splits device entries)
--   results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt (the split entries persist)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (munmap collapses the whole entry)
--   results/phase19_posixshm/391a_shm_open_retest.lua (shm_open/ftruncate/mmap shapes)

print("=== PROBE 1505a: CLIP AND THE SHARED OBJECT WINDOW ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
local rec = memory.alloc(0x40)

local function protect(addr, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent, uint64(addr)) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0))
    end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(done))
end

local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(rec + 0x10))
end

-- ---------------------------------------------------------------- [A] shm, two aliases
print("")
print("--- [A] shm object mapped twice ---")
local SHM = sgn(mk(482)(uint64(1), uint64(0x202), uint64(0x180), uint64(0), uint64(0), uint64(0)))
print(string.format("  shm_open -> %d %s", SHM, SHM < 0 and es() or ""))
if SHM < 0 then print("=== PROBE 1505a VOID ===") return end
print(string.format("  ftruncate -> %d", sgn(mk(480)(uint64(SHM), uint64(0x10000), uint64(0), uint64(0), uint64(0), uint64(0)))))

local A = sgn(mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(SHM), uint64(0)))
local B = sgn(mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(SHM), uint64(0)))
print(string.format("  A=0x%X B=0x%X %s", A, B, (A < 0 or B < 0) and es() or ""))
if A < 0 or B < 0 then print("=== PROBE 1505a INCOMPLETE ===") return end

local OFF = { 0x0, 0x4000, 0x8000, 0xC000 }
local MARK = { 0x11110000, 0x22220001, 0x33330002, 0x44440003 }
for i = 1, 4 do wr(A + OFF[i], MARK[i]) end
local alias_ok = true
for i = 1, 4 do
    local v = rd(B + OFF[i])
    if v ~= MARK[i] then alias_ok = false end
    print(string.format("  A+0x%X=%08X  B+0x%X=%08X", OFF[i], rd(A + OFF[i]) or 0xDEAD,
                        OFF[i], v or 0xDEAD))
end
print(string.format("  aliases agree: %s", tostring(alias_ok)))
print(string.format("  547 A=%d prot=%d   B=%d prot=%d", map547(A), select(2, map547(A)),
                    map547(B), select(2, map547(B))))

-- ---------------------------------------------------------------- [B] clip A
print("")
print("--- [B] 548 op 2 prot 1 on [A+0x4000, A+0x8000) - forces clip_start + clip_end ---")
local rv, cnt = protect(A + 0x4000, 0x4000, 1)
print(string.format("  rv=%d processed=%d %s", rv, cnt, rv < 0 and es() or ""))
print(string.format("  547 A now %d prot=%d", map547(A), select(2, map547(A))))

-- ---------------------------------------------------------------- [C] what happened
print("")
print("--- [C] markers after the clip ---")
for i = 1, 4 do
    local va = A + OFF[i]
    print(string.format("  about to read A+0x%X", OFF[i]))
    local v = rd(va)
    print(string.format("    A+0x%X = %s (expect %08X) %s", OFF[i],
          v and string.format("%08X", v) or "FAULT", MARK[i],
          (v == MARK[i]) and "ok" or "*** CHANGED ***"))
end
for i = 1, 4 do
    local va = B + OFF[i]
    print(string.format("  about to read B+0x%X", OFF[i]))
    local v = rd(va)
    print(string.format("    B+0x%X = %s (expect %08X) %s", OFF[i],
          v and string.format("%08X", v) or "FAULT", MARK[i],
          (v == MARK[i]) and "ok" or "*** CHANGED ***"))
end
print(string.format("  547 A=%d prot=%d  B=%d prot=%d", map547(A), select(2, map547(A)),
                    map547(B), select(2, map547(B))))

-- ---------------------------------------------------------------- [D] dmem variant
print("")
print("--- [D] same on /dev/dmem0, four distinct physical offsets ---")
local FD = -1
do
    local path = "/dev/dmem0"
    local pb = memory.alloc(#path + 2)
    for i = 1, #path do pcall(function() memory.write_byte(pb + i - 1, string.byte(path, i)) end) end
    pcall(function() memory.write_byte(pb + #path, 0) end)
    local ok, v = pcall(function() return mk(5)(uint64(pb), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then FD = sgn(v) end
end
print(string.format("  /dev/dmem0 fd=%d %s", FD, FD < 0 and es() or ""))
if FD >= 0 then
    local D = sgn(mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(1), uint64(FD), uint64(0)))
    print(string.format("  D=0x%X %s", D, D < 0 and es() or ""))
    if D >= 0 then
        local DMARK = { 0xA1A10000, 0xB2B20001, 0xC3C30002, 0xD4D40003 }
        for i = 2, 4 do wr(D + OFF[i], DMARK[i]) end
        local ok1 = true
        for i = 2, 4 do
            if rd(D + OFF[i]) ~= DMARK[i] then ok1 = false end
        end
        print(string.format("  markers written 0x4000/0x8000/0xC000: %s", tostring(ok1)))
        local rv2, c2 = protect(D + 0x4000, 0x4000, 1)
        print(string.format("  clip rv=%d processed=%d %s", rv2, c2, rv2 < 0 and es() or ""))
        for i = 2, 4 do
            print(string.format("  about to read D+0x%X", OFF[i]))
            local v = rd(D + OFF[i])
            print(string.format("    D+0x%X = %s (expect %08X) %s", OFF[i],
                  v and string.format("%08X", v) or "FAULT", DMARK[i],
                  (v == DMARK[i]) and "ok" or "*** CHANGED ***"))
        end
        print(string.format("  547 D=%d prot=%d", map547(D), select(2, map547(D))))
    end
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1505a COMPLETE ===")
