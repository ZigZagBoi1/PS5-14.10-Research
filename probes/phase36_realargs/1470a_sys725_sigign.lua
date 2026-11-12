-- CRASH_CLASS: HIGH -- 725 killed a zero-arg caller and killed again on the 477-good shape
-- (results/phase17_new_vectors/277a_mmap2_realargs_20261109_180550.txt, capture stops at the [A]
-- header).  One connection at risk.
-- PROBE 1470a: mmap2(725) with SIGSYS ignored -- is it absent or hostile?
--
-- Context:
--   277a called 725 with the 477-known-good shape (0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0) WITHOUT
--   ignoring SIGSYS, and the process died before the first result printed.  Under the default
--   disposition a `nosys` slot raises SIGSYS, whose default action terminates -- which is exactly
--   what 353a/353b showed for 307/308/337/570: with signal 12 ignored they return -1 instead of
--   dying.  So the 277a death cannot yet distinguish "725 is absent on 14.10" from "725 has a real
--   handler that faults".  That distinction is the whole point of this probe.
--
--   Why 725 matters: it is `mmap2` in the 13.60 table (thunk 0x2664c8 -> body 0x8b478ae0), a SECOND
--   mapping entry point.  Every W^X measurement in this project went through 477 or 74.  If 725
--   exists on 14.10 its protection policy has never been measured, and a second entry point is
--   exactly where a platform patch is most likely to have been missed.
--
--   Shape, from the 13.60 handler note: (addr, len, prot, flags, qword arg4, offset).  The 477
--   control uses the same arguments so a difference is attributable to the syscall, not the shape.
--
-- -- prior art:
--   results/phase17_new_vectors/277a_mmap2_realargs_20261109_180550.txt (killed without SIG_IGN)
--   results/phase17_new_vectors/353b_lethal_reclassify_20261022_163752.txt (SIG_IGN idiom + readback)
--   docs/SYSENT_PRESENCE_14_10.md:736 (725 mmap2 listed among the 677+ tail)
--   results/phase3_signals_codexec/424a-424c (the W^X wall as measured through 477/74)

print("=== PROBE 1470a: mmap2(725) WITH SIGSYS IGNORED ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end

local function call(sc, a1, a2, a3, a4, a5, a6)
    a3 = a3 or 0; a4 = a4 or 0; a5 = a5 or 0; a6 = a6 or 0
    local ok, rv = pcall(function() return sc(uint64(a1),uint64(a2),uint64(a3),uint64(a4),uint64(a5),uint64(a6)) end)
    if not ok then return nil, "EXC" end
    return to_num(rv)
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

-- [A] ignore SIGSYS (signal 12) so a nosys slot returns -1 instead of killing the process
print("[A] sigaction(12, SIG_IGN)")
local sa = as_addr(memory.alloc(0x80))
for o = 0, 0x78, 8 do wq(sa + o, 0) end
wq(sa + 0, 1) -- sa_handler = SIG_IGN
local srv = call(mk(416), 12, sa, 0)
print(string.format("[A] -> %s readback handler=%s (expect 0 and 1)",
    srv == nil and "EXC" or tostring(srv), tostring(rd(sa + 0))))
print("")

local sc477, sc725 = mk(477), mk(725)

-- [B] control: 477 with the known-good shape
print("[B] 477 mmap(0, 0x4000, 3, 0x1002, -1, 0)")
local r477 = call(sc477, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[B] -> %s", r477 == nil and "EXC" or tostring(r477)))
print("")

-- [C] the same shape through 725
print("[C] 725 with the same shape")
local r725 = call(sc725, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
if r725 == nil then print("[C] EXC")
elseif r725 == -1 then print(string.format("[C] -> -1 errno=%s (a nosys slot, or a refused call)", es()))
else print(string.format("[C] -> %d (0x%X)", r725, r725)) end
print("")

-- [D] only if 725 answered with an address: its protection policy
if r725 and r725 > 0 and r725 < 0x8000000000 then
    for _, prot in ipairs({ 5, 7, 4, 1, 0 }) do
        print(string.format("[D] 725 prot=%d", prot))
        local r = call(sc725, 0, 0x4000, prot, 0x1002, 0xFFFFFFFF, 0)
        print(string.format("[D] -> %s", r == nil and "EXC" or tostring(r)))
    end
    print("")
end

print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1470a COMPLETE ===")
