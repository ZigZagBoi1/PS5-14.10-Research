-- CRASH_CLASS: HIGH -- a kill here costs one relaunch of the game process. 601 cmd 0x1B has killed
-- twice on record: 1355a with arg3=0x100 and 1541a with arg3=9, the latter after a well-formed call.
-- PROBE 1542a: 601 cmd 0x1B with arg3 as a mapped pointer, not a small integer.
--
-- Context. 1541a called `601(0x1B, struct, 9)` with a mapped 0x100-byte struct whose name field held
-- twenty Z characters - a name matching none of the nine channel literals - and the process died
-- inside the call:
--
--   [0] pid=214
--   [0] SIG_IGN installed on 10/10 signals
--   [A] bogus name   601(0x1B, buf, 9) ...            <- capture ends here
--   then 9026 -> CONNECTION_REFUSED
--
-- That rules out both explanations the 13.60 listing supports. The name classifier cannot have been
-- reached (a non-matching name returns EINVAL at ca203d..ca223e without touching anything), and the
-- nine-way store cannot have been reached either (it needs a match). So the fault is before the
-- classifier, and every instruction before it is a stack copyin of a mapped buffer, a mutex, a
-- get-or-create, or a malloc - none of which can fault on these arguments.
--
-- The one argument 1541a did not vary is arg3. Both kills used a small integer there (0x100 and 9).
-- If the 14.10 body reads arg3 as a *pointer* - the shape 573's case bodies use, where the caller
-- pointer is dereferenced directly with no copyin - then both calls dereference a small address and
-- die in the same place, which is what the captures show.
--
-- So this probe sends a mapped page in arg3 and repeats the name gate. Two outcomes matter and the
-- verdict for both is printed BEFORE the last rung, so a death cannot erase it:
--   * [A]-[C] return EINVAL/0/EINVAL  -> the page rescues 0x1B and the name gate holds.
--   * [A] kills                       -> arg3 is not the variable; 0x1B is an unconditional trap.
-- [D] then sends arg3 = 0. It is LAST and it can only kill or return; either answer is informative
-- only about whether arg3 is dereferenced, and it is read against a verdict already printed.
--
-- If [A]-[C] survive, the page is also read back: a kernel copyout into arg3 (the most plausible
-- shape of "arg3 is a pointer") would be visible as a change from the 0x43434343 fill.
--
-- -- prior art:
--   results/phase36_realargs/1541a_sys601_cmd1b_name_gate_20261110_161109.txt (the well-formed kill, arg3=9)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt (the arg3=0x100 kill)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (the 0x1B row, the nine channel literals, the copy geometry, the 1541a note)
--   results/kernel_handlers/asm/sys_601_deep.asm (flat listing at base 0x8a9c0000)
--   note: 1195a did NOT reach 0x1B - it is in that probe's SKIP list

print("=== PROBE 1542a: 601 cmd 0x1B, arg3 AS A MAPPED POINTER ===")
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
local P = memory.alloc(0x1000)

for i = 0, 0xFFC, 4 do pcall(function() memory.write_dword(P + i, 0x43434343) end) end
print(string.format("[0] struct=%s  arg3 page=%s  fill=0x43434343", tostring(N(S)), tostring(N(P))))

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

local function call(tag, a3)
    print(string.format("  %-30s 601(0x1B, buf, %s) ...", tag, tostring(a3)))
    local ok, r = pcall(function() return sc601(uint64(0x1B), uint64(N(S)), a3, uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("       pcall raised: " .. tostring(r)) return -999, "" end
    local v = N(r)
    local e = (v == -1) and es() or ""
    print(string.format("       rv=%s %s", tostring(v), e))
    return v, e
end

-- counts how many of the first 8 dwords of the page still hold the fill value
local function page_delta()
    local changed = 0
    for i = 0, 0x1C, 4 do
        local ok, d = pcall(function() return N(memory.read_dword(P + i)) end)
        if not ok or d ~= 0x43434343 then changed = changed + 1 end
    end
    return changed
end

print("")
print("[A] non-matching name, arg3 = a mapped 0x1000 page")
print("    the 13.60 contract says EINVAL(22); a kill says arg3 is not what makes 0x1B die")
setup("ZZZZZZZZZZZZZZZZZZZZ")
local a1, a1e = call("bogus, arg3=page", uint64(N(P)))

print("")
print("[B] matching name, arg3 = the same page. Expect rv=0 if the classifier is reachable.")
setup("Sce.Debug:Gnm")
local b1, b1e = call("Gnm, arg3=page", uint64(N(P)))

print("")
print("[C] non-matching name again, after a success: a name-gated body must still answer EINVAL")
setup("ZZZZZZZZZZZZZZZZZZZZ")
local c1, c1e = call("bogus after success", uint64(N(P)))

print("")
print(string.format("[C-check] page dwords changed from the 0x43434343 fill: %d of 8", page_delta()))

print("")
print("[V] verdict, printed BEFORE the rung that can kill")
local VOID = (a1 == -999 or b1 == -999 or c1 == -999)
if VOID then
    print("  VOID: pcall raised before any kernel answer, so nothing here is a kernel observation")
    print(string.format("  a=%s(%s) b=%s(%s) c=%s(%s)", tostring(a1), tostring(a1e or ""),
        tostring(b1), tostring(b1e or ""), tostring(c1), tostring(c1e or "")))
elseif a1 == -1 and b1 == 0 and c1 == -1 then
    print("  the mapped page RESCUES 0x1B and the name gate holds: bogus -1, match 0, bogus -1")
    print("  so the 1541a kill was arg3 being a small integer, not a trap on the command")
else
    print("  neither contract; raw answers only:")
    print(string.format("  a=%s(%s) b=%s(%s) c=%s(%s)", tostring(a1), tostring(a1e or ""),
        tostring(b1), tostring(b1e or ""), tostring(c1), tostring(c1e or "")))
end

print("")
if VOID then
    print("[D] skipped: the run is void, so nothing is risked here")
else
    print("[D] arg3 = 0 with a matching name. Last rung: a death here means arg3 is dereferenced.")
    setup("Sce.Debug:Gnm")
    local d1, d1e = call("Gnm, arg3=0", uint64(0))
    if d1 == -999 then
        print("  arg3=0 raised a Lua error, not a kill: argue from [A]-[C] only")
    else
        print(string.format("  arg3=0 returned %s(%s): 0 is accepted, so arg3 is NOT dereferenced",
            tostring(d1), tostring(d1e or "")))
        print("  the page rescue therefore stands on its own, not on a pointer reading")
    end
end

print("")
print(string.format("=== PROBE 1542a COMPLETE pid=%s ===", tostring(PID)))
