-- CRASH_CLASS: MODERATE
-- PROBE 1469a: does the entry-scoped munmap (1450a) free pages another mapping still owns?
--
-- Context:
--   1450a measured that munmap(73) removes the WHOLE vm_map_entry containing addr: unmapping a
--   single 4 KiB page out of a 0x4000 mapping takes all four.  The 13.60 body computes the range
--   correctly (start = addr & ~0x3fff, end = round_page(len + off) + start) and calls the map remove
--   at 0x8ac89370, so the deviation is inside the VM layer, not in the syscall.
--
--   A VM layer that removes whole entries may also mishandle page ownership.  Two mappings of one
--   POSIX shm object share physical pages through the vm_object; if unmapping one alias releases the
--   pages instead of just the object reference, the second alias keeps a mapping of freed memory --
--   a page-level use-after-free, which is a kernel R/W primitive (spray a kernel object onto the
--   freed page and write through the surviving alias).
--
--   [A] proves the two aliases share pages, [B] munmaps one of them, [C] sprays 64 fresh mappings
--   and re-reads the survivor: a content change with no write from us is page reuse.
--   [D] tests the other half of the same mechanism -- MAP_FIXED over the middle of a live mapping,
--   which needs a split at both ends -- and then checks whether the outer pages still belong to the
--   original mapping after the middle is unmapped.
--
--   Every read is gated by 547 (which does not dereference) so an unmapped page is reported, never
--   touched; 547's start/end fields are 32-bit truncated (1450a), so it is used as a boolean only.
--
-- -- prior art:
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt
--   results/phase36_realargs/1468a_dual_map_wx_20261109_180339.txt (shm aliases share pages)
--   results/phase19_posixshm/391a_shm_open_retest.lua (482/480/477 shapes)
--   docs/VM_LAYER_14_10.md

print("=== PROBE 1469a: MUNMAP ENTRY SCOPE vs SHARED PAGES ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wr(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function hx(v) if v==nil then return "--------" end return string.format("%08X", v) end

local function call(sc, a1, a2, a3, a4, a5, a6)
    a3 = a3 or 0; a4 = a4 or 0; a5 = a5 or 0; a6 = a6 or 0
    local ok, rv = pcall(function() return sc(uint64(a1),uint64(a2),uint64(a3),uint64(a4),uint64(a5),uint64(a6)) end)
    if not ok then return nil end
    return to_num(rv)
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc_mmap, sc_munmap, sc_qp = mk(477), mk(73), mk(547)
local reg = as_addr(memory.alloc(0x40))
local function mapped(a)
    local rv = call(sc_qp, a, reg, 0, 0)
    return rv == 0
end
local function peek(tag, a)
    if not mapped(a) then print(string.format("   %s @0x%X: not mapped", tag, a)); return nil end
    local v = rd(a)
    print(string.format("   %s @0x%X: %s", tag, a, hx(v)))
    return v
end

local MARK = 0x11223344

-- [A] two aliases of one shm object
print("[A] shm_open + two MAP_SHARED aliases")
local okA, rA = pcall(function() return mk(482)(uint64(1), uint64(0x202), uint64(0x180)) end)
local fd = okA and to_num(rA) or -1
if fd < 0 then print("[!] no shm fd (" .. (okA and tostring(rA) or "EXC") .. ")"); print("=== PROBE 1469a COMPLETE ==="); return end
print(string.format("[A] fd=%d", fd))
print(string.format("[A] ftruncate -> %s", tostring(call(mk(480), fd, 0x4000))))
local A1 = call(sc_mmap, 0, 0x4000, 3, 1, fd, 0)
local B1 = call(sc_mmap, 0, 0x4000, 3, 1, fd, 0)
if A1 == nil or A1 <= 0 or B1 == nil or B1 <= 0 then
    print(string.format("[!] alias mmap failed A=%s B=%s", tostring(A1), tostring(B1)))
    print("=== PROBE 1469a COMPLETE ==="); return
end
print(string.format("[A] A=0x%X B=0x%X", A1, B1))
wr(A1, MARK); wr(A1 + 0x1000, MARK + 1); wr(A1 + 0x3000, MARK + 3)
peek("A", A1)
local alias_ok = (peek("B", B1) == MARK) and (peek("B+0x1000", B1 + 0x1000) == MARK + 1)
print(string.format("[A] aliases share pages: %s", alias_ok and "YES" or "NO"))
print("")

-- [B] munmap one page of the first alias (whole entry per 1450a)
print("[B] munmap(A, 0x1000) -- 1450a says the whole entry goes")
print(string.format("[B] -> %s", tostring(call(sc_munmap, A1, 0x1000, 0, 0))))
for _, off in ipairs({ 0, 0x1000, 0x2000, 0x3000 }) do
    print(string.format("   A+0x%X mapped=%s", off, tostring(mapped(A1 + off))))
end
peek("B", B1)
peek("B+0x3000", B1 + 0x3000)
print("")

-- [C] spray fresh mappings and see whether the survivor's page is reused
print("[C] spray 64 x 0x4000 anonymous mappings, fill with 5A5A5A5A")
local spray = {}
for i = 1, 64 do
    local p = call(sc_mmap, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
    if p and p > 0 then
        spray[#spray + 1] = p
        for o = 0, 0x3000, 0x1000 do wr(p + o, 0x5A5A5A5A) end
    end
end
print(string.format("[C] mapped %d regions", #spray))
local after = peek("B", B1)
print(string.format("[C] B changed: %s (was %s, now %s)", tostring(after ~= MARK), hx(MARK), hx(after)))
peek("B+0x1000", B1 + 0x1000)
print("")

-- [D] MAP_FIXED over the middle of a live mapping
print("[D] MAP_FIXED over the middle of a fresh 0x4000 mapping")
local C1 = call(sc_mmap, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
if C1 == nil or C1 <= 0 then print("[!] C mmap failed"); print("=== PROBE 1469a COMPLETE ==="); return end
print(string.format("[D] C=0x%X", C1))
wr(C1, 0xAAAA0001); wr(C1 + 0x1000, 0xAAAA0002); wr(C1 + 0x3000, 0xAAAA0004)
local D1 = call(sc_mmap, C1 + 0x1000, 0x1000, 3, 0x1012, 0xFFFFFFFF, 0)
print(string.format("[D] MAP_FIXED at C+0x1000 -> %s", D1 == nil and "EXC" or string.format("0x%X", D1)))
for _, off in ipairs({ 0, 0x1000, 0x2000, 0x3000 }) do
    print(string.format("   C+0x%X mapped=%s", off, tostring(mapped(C1 + off))))
end
peek("C", C1)
peek("C+0x1000", C1 + 0x1000)
peek("C+0x3000", C1 + 0x3000)
if D1 and D1 > 0 then
    wr(D1, 0xBBBB0002)
    peek("C+0x1000 after write at D", C1 + 0x1000)
end
print("")

print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1469a COMPLETE ===")
