-- CRASH_CLASS: MODERATE -- the shape is a well-formed call for the length-gated case at
-- 0x8b6611ce, so a command that owns a different body is reached with arguments it was not
-- designed for. The known loader-dead commands 0x03/0x04/0x08/0x0C/0x1B/0x27 are excluded and
-- 0x11 - lethal when both pointed-to slots are mapped - runs LAST, after the verdict.
-- Every call prints its tag before the call, so a death names its command by the last tag in
-- the capture, and a liveness call runs every eight commands.
-- PROBE 1538b: which 601 command takes arg3 as a LENGTH in qwords.
--
-- Context. The 13.60 body has a case at VA 0xffffffff8b6611ce (the dumps print addresses with a
-- base of 0x8a9c0000, so it appears there as ca11ce) that reads arg3 as a count:
--
--     ca11d2/ca11d9  lea rdi,[rbp-0xf0] / mov esi,0x78
--     ca11e5         call 0x8ac18ff0            ; bzero(local, 0x78)
--     ca11ea         lea rax,[r12-0x10]         ; r12 = uap[2] = arg3
--     ca11ef         mov r14d,0x16              ; EINVAL
--     ca11f5         cmp rax,0 - 0xe
--     ca11f9         jb fail                    ; unsigned: keep only arg3 in [2,15]
--     ca1211         shl r12,3                  ; arg3 * 8
--     ca1227         call 0x8ac19280            ; copyin(r15, local, arg3*8)
--     ca1237         mov rbx,[rbp-0xf0]         ; local[0]
--     ca123e         mov r15,[rbp-0xe8]         ; local[1]
--     ca1245         cmp rbx,1
--     ca1249/ca1257  lea rcx,[r15-3] / cmp rcx,2 / setb cl / and cl,al
--     ca125c         jne fail                   ; local[0]==1 and local[1] in {3,4}
--     ca1269         mov r14,[rbp-0xe0]         ; local[2] = a USER pointer
--     ca12b6         call 0x8ac19900            ; string copy through it
--
-- copyin at 0x8ac19280 is (rdi = user source, rsi = kernel destination, rdx = length), per
-- docs/ARG1_CLASSES_14_10.md:308 and its own prologue at 0x8ac192c6 `mov rax,rdi / add rax,rdx`.
-- [2,15] is exactly 0x78/8, so arg3 is the entry count and the struct begins {1, <3|4>, <ptr>}.
-- Every earlier 601 probe passed a FLAGS WORD in arg3 (1384a's trial() is
-- `mk(601)(cmd, sptr, flags, 0,0,0)`), so 0 and 1 fell below the bound and 0x20 and 0xC0 above
-- it: every command in the family was measured outside the one range its validator accepts.
--
-- Which command owns 0x8b6611ce is NOT known. The dispatch table at 0x8e031160 is outside every
-- dump, and 0x01/0x24 are already assigned: they share the body at 0x8b66067f (ca067f), which
-- copyins 16 bytes from uap[1] and treats arg2 as flags. So this probe sweeps the family.
--
-- The measurement is a DELTA, not an absolute. Twelve commands (00, 07, 09, 0B, 0D, 0E, 13, 14,
-- 19, 1A, 1D, 20 - 1193a's errno-0 set) return 0 whatever the arguments are, so "rv ~= -1" alone
-- would report them as hits. Each command is therefore called twice, first with the new shape
-- (arg3 = 3, {1,3,<mapped string>}) and then with the corpus shape (arg3 = 0, which that body
-- rejects at ca11f9 before any copyin), and only a CHANGE in the answer counts.
--
-- The struct is rewritten before EVERY call, because 0x00 writes 8 bytes at offset 0 of its
-- buffer (1170a: `[00] rv=0 changed=8 first=0`; 1193c pins the value to 0x100) and 0x0E and 0x1A
-- write too. A stale buffer would leave qword0 = 0x100 and the ca11ce gate `cmp rbx,1` could
-- never pass, turning the whole sweep into a false negative.
--
-- The third qword is a full page with the string at its start, because the copy at ca12b6 may
-- run in either direction and a kernel->user copy of up to 0x78 bytes must not run past the end
-- of what we own.
--
-- -- prior art:
--   probes/phase35_dead_end_reruns/1384a_sys601_cmd01_payload.lua (trial() puts a flags word in arg3; every shape EINVAL)
--   results/phase35_dead_end_reruns/1384a_sys601_cmd01_payload_20261109_140012.txt (0x01/0x24 measured against that wrong slot)
--   results/phase35_dead_end_reruns/1383b_sys601_shape_matrix2_20261109_135948.txt (0x11 a1a2 kills; capture ends there)
--   results/phase17_new_vectors/1193a_601_errno_map.lua (the twelve-command errno-0 set)
--   results/phase17_new_vectors/1193c_601_cmd00_write.lua (cmd 00 writes 0x100 at offset 0)
--   results/phase17_new_vectors/1170a_601_cmd00_shape.lua ([00] rv=0 changed=8 first=0)
--   results/phase17_new_vectors/1192a_601_dispatcher_command.lua (skip list 0x03/0x04/0x08/0x0C/0x1B/0x27)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (arg3 is a length; 0x01/0x24 own 0x8b66067f; copy geometry audit)
--   results/kernel_handlers/asm/sys_601_deep.asm (flat listing at base 0x8a9c0000; the case is ca11ce)

print("=== PROBE 1538b: WHICH 601 COMMAND TAKES arg3 AS A LENGTH ===")
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
    local o = pcall(function() return mk(416)(uint64(s), uint64(N(sa)), uint64(0)) end)
    if o then ok_sig = ok_sig + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ok_sig))

-- a whole page for the third qword, string at its start
local page = memory.alloc(0x1000)
pcall(function() memory.write_byte(page, uint64(120)) end)
pcall(function() memory.write_byte(page + 1, uint64(0)) end)
print(string.format("[0] third-qword page at 0x%X (0x1000 bytes, string at +0)", N(page)))

local sc601 = mk(601)
local S = memory.alloc(0x100)
local function setup(q1)
    for i = 0, 0xFC, 4 do memory.write_dword(S + i, 0) end
    if q1 then
        memory.write_qword(S + 0x00, uint64(1))
        memory.write_qword(S + 0x08, uint64(q1))
        memory.write_qword(S + 0x10, uint64(N(page)))
    end
end

local function call(tag, cmd, nq)
    print(string.format("  %-22s 601(0x%02X, buf, %d) ...", tag, cmd, nq))
    local ok, r = pcall(function() return sc601(uint64(cmd), uint64(N(S)), uint64(nq), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("       rv=PCALL-FAIL") return -999, "pcall" end
    local v = N(r)
    local e = (v == -1) and es() or ""
    print(string.format("       rv=%s %s", tostring(v), e))
    return v, e
end

print("")
print("[A] liveness with a mapped buffer (cmd 0x00 writes 8 bytes into it)")
setup(nil)
call("baseline 0x00 arg3=0", 0x00, 0)

local skip = { [0x03]=true, [0x04]=true, [0x08]=true, [0x0C]=true, [0x1B]=true, [0x27]=true, [0x11]=true }
local order = {}
for c = 0x00, 0x26 do if not skip[c] then order[#order+1] = c end end

print("")
print("[B] per command: the length shape, then the corpus shape, then the delta")
local hits = {}
local n = 0
for _, c in ipairs(order) do
    setup(3)
    local b, be = call(string.format("0x%02X len3 {1,3,str}", c), c, 3)
    local a, ae = -999, "skipped"
    if b ~= -999 then
        setup(nil)
        a, ae = call(string.format("0x%02X len0 corpus", c), c, 0)
    end
    if b ~= -999 and a ~= -999 then
        local changed = (b ~= a) or (be ~= ae)
        print(string.format("     delta 0x%02X: len3=%s (%s) vs len0=%s (%s) -> %s",
            c, tostring(b), be, tostring(a), ae, changed and "CHANGED" or "same"))
        if changed then
            hits[#hits+1] = c
            print(string.format("     ^^^ 0x%02X ANSWERED DIFFERENTLY UNDER THE LENGTH SHAPE", c))
        end
    end
    n = n + 1
    if n % 8 == 0 then
        setup(nil)
        call("liveness 0x00", 0x00, 0)
    end
end

print("")
print("[C] verdict")
if #hits == 0 then
    print("  no command in 0x00-0x26 changed its answer when arg3 became a length")
else
    local names = {}
    for _, c in ipairs(hits) do names[#names+1] = string.format("0x%02X", c) end
    print("  CHANGED: " .. table.concat(names, " "))
end

print("")
print("[D] each changed command re-asked with local[1] = 4 and at arg3 = 15")
if #hits == 0 then
    print("  nothing to re-ask")
else
    for _, c in ipairs(hits) do
        setup(4)
        call(string.format("0x%02X q1=4 len3", c), c, 3)
        setup(3)
        call(string.format("0x%02X len15", c), c, 15)
    end
end

print("")
print("[E] last, because 1383b shows it can kill: 0x11 with both slots mapped")
setup(3)
call("0x11 both mapped", 0x11, 3)

print("")
print(string.format("=== PROBE 1538b COMPLETE pid=%s ===", tostring(PID)))
