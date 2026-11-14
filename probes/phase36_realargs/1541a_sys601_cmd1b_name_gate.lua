-- CRASH_CLASS: MODERATE -- 601 cmd 0x1B is recorded in the corpus as a loader-killer at
-- docs/MDBG_601_COMMAND_MAP_14_10.md:54, but the 13.60 body is fully decoded below and every
-- path in it is either a copyin, a store into a 0xd8-byte kernel object, or a return code.
-- A kill is possible and costs one relaunch; the run is one probe on an otherwise idle console.
-- PROBE 1541a: 601 cmd 0x1B is a name-gated, caller-controlled qword write. Measure it.
--
-- Context. 601 cmd 0x1B was closed twice: docs/SYS601_SECOND_STAGE_14_10.md called the
-- ctx+0xf0 write family unreachable because ctx+0xf0 is a 0/1 flag (it is not - see the
-- correction section of docs/MDBG_601_COMMAND_MAP_14_10.md), and the command map lists 0x1B
-- itself as LOADER-DEAD from 1355a. The 13.60 body at VA 0x8b6610db (dumps print with base
-- 0x8a9c0000, so it appears as ca10db) says something much more specific:
--
--   ca10f5  lea rsi,[rbp-0xf0] / mov edx,0x48 / mov rdi,r15
--   ca1104  call 0x8ac19280          ; copyin(arg2, local, 0x48)
--   ca1114  mov byte [rbp-0xa9],0    ; local+0x47 = 0, NUL-terminating a name at local+0x28
--   ca1122  call 0x8b65afc0          ; get-or-create the mdbg ctx (it stores [proc+0x568])
--   ca114e  rbx = [ctx+0xf0]         ; the 0xd8 object
--   ca1164  jne ca1de7               ; already installed -> classify only
--   ca117b  call malloc(0xd8) / ca1dd2 mov [ctx+0xf0],rbx
--   ca1de7  .. nine strncmp(local+0x28, <literal>, <len>) .. -> ebx = 1..9, 0 when none match
--   ca1ffb  lock / cmp [proc+0x568],0 / cmp [ctx+0xf0],0; r14d = 3 if either is NULL
--   ca203d  dec ebx / cmp ebx,8 / ja ca223e (EINVAL); table at 0xffffffff8e031210 (undumped)
--   each of the nine cases: or byte [rax+0xd4|+0xd5],<bit> then
--                           mov rcx,[rbp-0xe8/+0xe0/+0xd8/+0xd0] / mov [rax+<off>],rcx
--   ca2200  xor r14d,r14d            ; rv = 0
--
-- The nine object offsets, in dispatch order, are +0x00/+0x08/+0x10/+0x18, +0x60/+0x68,
-- +0x30/+0x38/+0x40/+0x48, +0x50/+0x58, +0xb0/+0xb8/+0xc0/+0xc8, +0x20/+0x28,
-- +0x70/+0x78/+0x80/+0x88, +0x90/+0x98/+0xa0/+0xa8 and a dword at +0xd0 - every one inside
-- 0xd8, and every source is a qword of the struct the caller supplied at arg2.
--
-- The nine channel names, read out of docs/dumps_13.60/kernel_data.bin (base 0xffffffff8b9c0000):
--   0x8bd1965f "Sce.PSM:AppName"        len 0x10 -> code 1
--   0x8bd42c26 "Sce.PSM:SdbInfo"        len 0x10 -> code 2
--   0x8bce51a9 "Sce.PSM:LogArea"        len 0x10 -> code 3
--   0x8bcc5161 "Sce.Debug:UserObjArray" len 0x17 -> code 4
--   0x8bc9c08b "Sce.Debug:Gnm"          len 0x0e -> code 5
--   0x8bd241af "Sce.Debug:Gn2"          len 0x0e -> code 6
--   0x8bce51b9 "Sce.Debug:Gn3"          len 0x0e -> code 7
--   0x8bc86e96 "Sce.Debug:Gn4"          len 0x0e -> code 8
--   0x8bd38646 "Sce.Debug:KPNoverride"  len 0x16 -> code 9
--
-- So the command contract is a positive/negative pair the corpus can read directly: a matching
-- name returns 0 (and performs the stores), a non-matching name returns -1 EINVAL(22). That is
-- the discriminator this probe uses. It also means the earlier "0x1B kills" reading came from a
-- shape whose name never matched, or from the attach state left by the rungs before it.
--
-- What this buys if it works: a kernel-heap write of four caller-chosen qwords (struct+0x08,
-- +0x10, +0x18, +0x20) into up to twenty-six fixed slots plus a dword, inside a 0xd8 object the
-- kernel allocated. That is not an addressed write - the object's own
-- address is not knowable - so it is only the first half of a primitive. It is worth measuring
-- because nothing in this project has yet produced a controlled write into kernel memory.
--
-- The caller qwords are sentinels, not pointers. Every one of the nine cases is a store, so a
-- sentinel cannot be dereferenced; using a kernel address here would risk nothing gained.
--
-- -- prior art:
--   docs/MDBG_601_COMMAND_MAP_14_10.md (the 0x1B LOADER-DEAD row, and the get-or-create correction)
--   docs/SYS601_SECOND_STAGE_14_10.md (the ctx+0xf0 family this supersedes)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt (the capture that ends at "calling 0x1B")
--   results/phase36_realargs/1538b_sys601_length_owner_sweep_20261110_154233.txt (the arg3 delta sweep)
--   results/kernel_handlers/asm/sys_601_deep.asm (flat listing at base 0x8a9c0000)
--   docs/dumps_13.60/kernel_dump_manifest.json (data base 0xffffffff8b9c0000)

print("=== PROBE 1541a: 601 cmd 0x1B, NAME-GATED CALLER-QWORD WRITE ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ok_sig = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local okc, sigrv = pcall(function() return mk(416)(uint64(s), uint64(N(sa)), uint64(0)) end)
    if okc and N(sigrv) == 0 then ok_sig = ok_sig + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ok_sig))

local sc601 = mk(601)
local S = memory.alloc(0x100)

local function put_name(name)
    for i = 0x28, 0x48 do pcall(function() memory.write_byte(S + i, uint64(0)) end) end
    for i = 1, #name do
        pcall(function() memory.write_byte(S + 0x28 + (i - 1), uint64(name:byte(i))) end)
    end
end

local function setup(name)
    for i = 0, 0xFC, 4 do memory.write_dword(S + i, 0) end
    pcall(function()
        memory.write_qword(S + 0x08, uint64("0x1111111111111111"))
        memory.write_qword(S + 0x10, uint64("0x2222222222222222"))
        memory.write_qword(S + 0x18, uint64("0x3333333333333333"))
        memory.write_qword(S + 0x20, uint64("0x4444444444444444"))
    end)
    put_name(name)
end

local function call(tag, nq)
    print(string.format("  %-28s 601(0x1B, buf, %d) ...", tag, nq))
    local ok, r = pcall(function() return sc601(uint64(0x1B), uint64(N(S)), uint64(nq), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("       rv=PCALL-FAIL") return -999, "" end
    local v = N(r)
    local e = (v == -1) and es() or ""
    print(string.format("       rv=%s %s", tostring(v), e))
    return v, e
end

print("")
print("[A] a name that matches none of the nine, called FIRST so that a death here isolates the")
print("    preamble (copyin + ctx create + malloc) rather than the nine-way store")
setup("ZZZZZZZZZZZZZZZZZZZZ")
local a1, a1e = call("bogus name", 9)

print("")
print("[B] the matching name: the only path that reaches the dispatch. Expect rv=0.")
setup("Sce.Debug:Gnm")
local b1, b1e = call("Gnm, match", 9)

print("")
print("[C] repeat with the same buffer: the 0xd8 object is already installed, so this is the")
print("    classify-only path and must give the same answer as [B]")
setup("Sce.Debug:Gnm")
local c1, c1e = call("Gnm, repeat", 9)

print("")
print("[D] a second channel name, to show the classifier moves off the first match")
setup("Sce.PSM:AppName")
local d1, d1e = call("AppName", 9)

print("")
print("[E] the longest literal, 22 characters against a 0x20-byte name field")
setup("Sce.Debug:UserObjArray")
local e1, e1e = call("UserObjArray", 9)

print("")
print("[F] the latch control: a bogus name AFTER a success. If the command is name-gated this must")
print("    still be EINVAL; if it merely latched on the first call it will answer 0")
setup("ZZZZZZZZZZZZZZZZZZZZ")
local f1, f1e = call("bogus after success", 9)

print("")
print("[G] verdict")
if b1 == 0 and a1 == -1 and f1 == -1 then
    print("  0x1B answers 0 for a matching channel name and -1 EINVAL(22) for a non-matching one,")
    print("  before and after a success => the name is the gate, not a first-call latch")
    print("  13.60 predicts the nine-way store on the rv=0 path; that store is NOT observed here")
    print(string.format("  repeat=%s  appname=%s  userobjarray=%s",
        tostring(c1), tostring(d1), tostring(e1)))
    if c1 ~= 0 then print("  but the classify-only repeat did not match [B]; the answer is not stable across repeats") end
elseif a1 == 0 or b1 == 0 then
    print(string.format("  a success was seen but the gate does not hold: bogus-before=%s(%s) match=%s(%s) bogus-after=%s(%s)",
        tostring(a1), tostring(a1e or ""), tostring(b1), tostring(b1e or ""), tostring(f1), tostring(f1e or "")))
else
    print(string.format("  0x1B did not follow the 13.60 name contract: bogus=%s (%s) match=%s (%s) bogus-after=%s (%s)",
        tostring(a1), tostring(a1e or ""), tostring(b1), tostring(b1e or ""), tostring(f1), tostring(f1e or "")))
end

print("")
print(string.format("=== PROBE 1541a COMPLETE pid=%s ===", tostring(PID)))
