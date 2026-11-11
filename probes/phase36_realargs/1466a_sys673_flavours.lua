-- CRASH_CLASS: MODERATE -- no byte of any mapping is read or written; 673 only looks the address up.
-- PROBE 1466a: which mapping flavour creates the type-11 vm_object that 673 and 654 demand
--
-- Context:
--   1451a established that 673 blockpool_move (and 654 blockpool_map, read statically at
--   0xffffffff8b3696cf) both do vm_map_lookup_entry(addr) and then require
--       `test byte [entry+0x60],2 == 0`, `entry->object != NULL` and `cmp byte [obj+0x9d],0xb`.
--   1451a scanned for a store of the constant 0xb to [obj+0x9d] over all 5,343,048 instructions and
--   found none, and measured EINVAL for anonymous, /dev/zero, /dev/dmem0 and /dev/gc.
--
--   The flavour that was NOT tested is the one Sony creates itself: the GPU mapping (prot 0x33,
--   flags 0x1002, fd -1), plus a POSIX shm mapping (482) and a file mapping.  Those are the only
--   mappings a game process can make whose vm_object is created by a Sony code path rather than by
--   FreeBSD's generic anonymous/vnode path, so they are where an object type outside 0..10 would
--   live.
--
--   Nothing here reads or writes the mapping: 673 only resolves the address, which is what makes a
--   GPU mapping safe to pass (a read of GPU memory kills past pcall, 376a/380a).
--
--   0x400000 is the only 653 blockpool_open flag value that returned a handle (0x324), and 654 then
--   refused every address for the same reason, so the same flavour sweep is run for 654 afterwards.
--
-- -- prior art:
--   results/phase36_realargs/1451a_sys673_object_type_20261109_172829.txt
--   results/phase36_realargs/1465a_blockpool_open_flags_20261109_175825.txt
--   results/phase36_realargs/1452a_fault_teardown_race_20261109_174104.txt (a loader thread fault kills the process)
--   docs/VM_LAYER_14_10.md section 2
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1466a: 673/654 ACROSS MAPPING FLAVOURS ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    local a = as_addr(b)
    for i = 1, #s do pcall(function() memory.write_byte(uint64(a + i - 1), string.byte(s, i)) end) end
    pcall(function() memory.write_byte(uint64(a + #s), 0) end)
    return a
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc673, sc654, sc477, sc73 = mk(673), mk(654), mk(477), mk(73)

local function call(sc, a1, a2, a3, a4, a5, a6)
    a5 = a5 or 0; a6 = a6 or 0
    local ok, rv = pcall(function() return sc(uint64(a1),uint64(a2),uint64(a3),uint64(a4),uint64(a5),uint64(a6)) end)
    if not ok then return nil end
    return to_num(rv)
end

local function report(tag, rv)
    if rv == nil then print(string.format("   %s -> EXC", tag))
    elseif rv == -1 then print(string.format("   %s -> -1 errno=%s", tag, es()))
    else print(string.format("   %s -> %d (0x%X)", tag, rv, rv)) end
end

-- exercise 673 and 654 on one address pair
local function hit(va, len)
    local lo = math.floor(va / 0x10000) * 0x10000
    local hi = lo + 0x10000
    local hi2 = lo + math.max(0x10000, math.ceil(len / 0x10000) * 0x10000)
    print(string.format("   va=0x%X lo=0x%X hi=0x%X", va, lo, hi2))
    report(string.format("673(0x%X,0x%X,0x%X,0)", lo, hi2, lo), call(sc673, lo, hi2, lo, 0))
    report(string.format("673(0x%X,0x%X,0x%X,0)", lo, hi2, hi), call(sc673, lo, hi2, hi, 0))
    report(string.format("654(0x%X,0x%X,3,0,0)", lo, hi - lo), call(sc654, lo, hi - lo, 3, 0))
end

-- [A] anonymous control
print("[A] anonymous")
local A = call(sc477, 0, 0x40000, 3, 0x1002, 0xFFFFFFFF)
if A and A > 0 then hit(A, 0x40000) else print(string.format("   mmap failed %s", tostring(A))) end
print("")

-- [B] GPU mapping, the flavour never tried
print("[B] GPU (prot 0x33, flags 0x1002, fd -1)")
local B = call(sc477, 0, 0x40000, 0x33, 0x1002, 0xFFFFFFFF)
if B and B > 0 then hit(B, 0x40000) else print(string.format("   mmap failed %s", tostring(B))) end
print("")

-- [C] /dev/zero
print("[C] /dev/zero")
local zfd = call(mk(5), str_addr("/dev/zero"), 0x4002, 0, 0)
if zfd and zfd >= 0 then
    local C = call(sc477, 0, 0x40000, 3, 1, zfd)
    if C and C > 0 then hit(C, 0x40000) else print(string.format("   mmap failed %s", tostring(C))) end
    pcall(function() mk(6)(uint64(zfd),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
else
    print("   open failed")
end
print("")

-- [D] file mapping of eboot
print("[D] /app0/eboot.bin (prot 1)")
local ffd = call(mk(5), str_addr("/app0/eboot.bin"), 0x4000, 0, 0)
if ffd and ffd >= 0 then
    local D = call(sc477, 0, 0x40000, 1, 1, ffd)
    if D and D > 0 then hit(D, 0x40000) else print(string.format("   mmap failed %s", tostring(D))) end
    pcall(function() mk(6)(uint64(ffd),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
else
    print(string.format("   open failed %s", tostring(ffd)))
end
print("")

-- [E] POSIX shm
print("[E] shm_open(482) + MAP_SHARED")
local sfd = call(mk(482), 0, 0x2, 0x1FE)
if sfd and sfd >= 0 then
    print(string.format("   shm fd=%d", sfd))
    pcall(function() mk(530)(uint64(sfd), uint64(0x40000)) end)
    local E = call(sc477, 0, 0x40000, 3, 1, sfd)
    if E and E > 0 then hit(E, 0x40000) else print(string.format("   mmap failed %s", tostring(E))) end
    pcall(function() mk(6)(uint64(sfd),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
else
    print(string.format("   shm_open -> %s", tostring(sfd)))
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1466a COMPLETE ===")
