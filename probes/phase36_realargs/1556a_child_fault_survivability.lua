-- CRASH_CLASS: HIGH (deliberately faults a child thread; the question is whether
--                   the loader survives it at all)
-- PROBE 1556a: does a fault in a thr_create(430) child kill the loader?
--
-- prior art:
--   probes/phase36_realargs/1553a_munmap_vs_store_race.lua and its capture
--     results/phase36_realargs/1553a_munmap_vs_store_race_20261110_192006.txt —
--     a child storing into a page that 548 op1 then unmapped faulted at RIP =
--     the store gadget with rdi = the unmapped page, and the loader died right
--     afterwards (9026 CONNECTION_REFUSED). No verdict line ever printed, so
--     that run is graded V. The fault itself is the correct-kernel signature,
--     but whether the loader can survive such a fault was never established.
--   CLAUDE.md and 1331a (results/1331a_202609??) — "a child contains an ordinary
--     fault, not a call that terminates the process": 1331a spawned 512 children
--     that each faulted on a KERNEL-half address and the parent kept running.
--     That is the opposite of what 1553a saw, so one of the two is about a
--     different kind of fault.
--   docs/THREADING_ALIVE_14_10.md — thr_create(430) gates: +0x108 = 0x480,
--     +0x0d0 = 0, +0x110 = 0x10000, CS +0x0c0 = 0x43, SS +0x100 = 0x3B,
--     RIP +0x0e0, RSP +0x0f8; GP registers come from +0x048..+0x0b8.
--   CLAUDE.md gadget catalogue: `mov [rdi],rax;ret` at eboot+0x92C67 (child
--     verified in 56l).
--   157a (results/phase17_new_vectors/157a_syscall_loop_thread_20261020_172245.txt)
--     — a child walking a stack filled with ONE repeated gadget address loops
--     without ever leaving the fill, which is why the fill here is a single
--     repeated qword rather than a multi-gadget pattern.
--
-- Why this matters: every remaining race design (VM map delete versus a store,
-- versus a first-touch fault, versus a page-table walk) makes the losing child
-- fault. If a child fault takes the loader down, each such run costs a console
-- relaunch and prints no verdict, so the whole axis is unaffordable and the
-- designs have to change shape. If the loader survives, 1553a's death came from
-- the interaction between the fault and the 548 call rather than from the fault
-- itself, and the heartbeat oracle is affordable.
--
-- Instrument: eboot text base from 593, gadgets verified by their bytes, a
-- child whose RIP is the store gadget and whose RDI is either unmapped ([A])
-- or a page the parent unmaps underneath it ([B]). Every decision the probe
-- makes is printed BEFORE the call that could end the run.

print("=== PROBE 1556a: is a child-thread fault survivable? ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return v end
    return nil
end
local function rqn(a) return to_num(rq(a) or 0) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wq(a, v) pcall(function() memory.write_qword(uint64(a), uint64(v)) end) end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid     = mk(20)
local sc_thr_create = mk(430)
local sc_nanosleep  = mk(240)
local sc_mmap       = mk(477)
local sc_547        = mk(547)
local sc_548        = mk(548)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RAX = 0x048, 0x078
local MARKER = 0x0011223344556677

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    zero(ts, 16)
    wd(ts, math.floor(ms / 1000))
    wd(ts + 8, (ms % 1000) * 1000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

local function mmap_anon(len)
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(len), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local n = to_num(v)
    if n < 0x1000 or n > 549755813888 then return nil end
    return n
end

-- ---- [0] prerequisites ----
print(string.format("[0] pid=%s", tostring(to_num(sc_getpid()))))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local tlo, thi = rd(info + 0x108), rd(info + 0x10C)
if not tlo then
    print("=== ABORT: no eboot base ===")
    return
end
local eboot = uint64(string.format("0x%X%08X", thi or 0, tlo))
local STORE = eboot + 0x92C67
local a, b = rb(STORE), rb(STORE + 1)
print(string.format("[0] eboot=%s store=%s = %02X %02X (want 48 89)",
    q(eboot), q(STORE), a or -1, b or -1))
if not (a == 0x48 and b == 0x89) then
    print("=== ABORT: gadget moved ===")
    return
end

-- 8 raw bytes of the gadget address, little endian, for a bulk fill
local function qbytes(addr)
    local v = to_num(addr)
    local out = {}
    for i = 1, 8 do
        out[i] = string.char(v % 256)
        v = math.floor(v / 256)
    end
    return table.concat(out)
end
local STORE_B = qbytes(STORE)

local ctx = memory.alloc(0x500)
local tid = memory.alloc(8)

local function arm(rip, rsp, rdi)
    zero(ctx, 0x500)
    zero(tid, 8)
    wq(ctx + C_MAGIC, 0x480)
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, 0x10000)
    wq(ctx + C_CS, 0x43)
    wq(ctx + C_SS, 0x3B)
    wq(ctx + C_RIP, rip)
    wq(ctx + C_RSP, rsp)
    wq(ctx + C_RDI, rdi)
    wq(ctx + C_RAX, MARKER)
end
local function spawn()
    local ok, rv = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid))
    end)
    return ok and to_num(rv) or -999, rqn(tid)
end

-- ---- [A] a child whose FIRST instruction faults on an unmapped user page ----
local STACK = 0x4000
local Sv = mmap_anon(STACK + 0x4000)
if not Sv then
    print("=== ABORT: no stack ===")
    return
end
pcall(function() memory.write_buffer(uint64(Sv), string.rep(STORE_B, STACK / 8)) end)
print(string.format("[A] stack=0x%X filled with the store gadget", Sv))

local BAD = 0x200000000
local rvBad = -1
pcall(function() rvBad = to_num(sc_547(uint64(BAD), uint64(info), uint64(0x40),
    uint64(0), uint64(0), uint64(0))) end)
print(string.format("[A] BAD=0x%X 547=%d (want -1: not mapped)", BAD, rvBad))
if rvBad ~= -1 then
    print("=== ABORT: the fault target is mapped ===")
    return
end

print("[A] spawning a child that will fault on its first store. If the next three")
print("[A] lines do not appear, one child fault takes the whole loader down.")
arm(STORE, Sv, BAD)
local rvA, tidA = spawn()
print(string.format("[A] thr_create rv=%d tid=0x%X", rvA, tidA))

sleep_ms(1)
print(string.format("[A] +1ms  pid=%s", tostring(to_num(sc_getpid()))))
sleep_ms(20)
print(string.format("[A] +21ms pid=%s", tostring(to_num(sc_getpid()))))
print("[A] SURVIVED: a child fault on an unmapped user page does not kill the loader")
print("")

-- ---- [B] the 1553a shape: a live store loop, then the parent unmaps the page --
local Pv = mmap_anon(0x4000)
if not Pv or Pv % 0x4000 ~= 0 then
    print("=== ABORT: no 16 KiB-aligned target ===")
    return
end
zero(Pv, 0x4000)
print(string.format("[B] target P=0x%X reads 0x%X", Pv, rqn(Pv)))

local Sv2 = mmap_anon(0x800000 + 0x4000)
if not Sv2 then
    print("=== ABORT: no big stack ===")
    return
end
local filled = pcall(function()
    memory.write_buffer(uint64(Sv2), string.rep(STORE_B, 0x800000 / 8))
end)
print(string.format("[B] stack=0x%X fill ok=%s slots=%d", Sv2, tostring(filled), 0x100000))

local ent = memory.alloc(0x40)
local done = memory.alloc(8)
zero(ent, 0x40)
wd(ent + 0x00, Pv % 4294967296)
wd(ent + 0x04, math.floor(Pv / 4294967296))
wd(ent + 0x10, 0x4000)
wd(ent + 0x18, 3)
pcall(function() memory.write_byte(uint64(ent + 0x1C), 1) end)
wd(done, 0xEEEEEEEE)

print("[B] spawning the store loop, then unmapping P under it")
arm(STORE, Sv2, Pv)
local rvB, tidB = spawn()
local rvU, procU = -999, nil
if rvB == 0 then
    local okU, vU = pcall(function()
        return sc_548(uint64(0), uint64(0), uint64(ent), uint64(1),
                      uint64(done), uint64(0))
    end)
    rvU = okU and to_num(vU) or -999
    procU = rd(done)
end
print(string.format("[B] thr_create rv=%d tid=0x%X  548 op1 rv=%d processed=%s",
    rvB, tidB, rvU, tostring(procU)))

local rec = memory.alloc(0x40)
zero(rec, 0x40)
local ok547, rv547 = pcall(function()
    return sc_547(uint64(Pv), uint64(rec), uint64(0x40),
                  uint64(0), uint64(0), uint64(0))
end)
print(string.format("[B] 547(P) rv=%d (want -1)", ok547 and to_num(rv547) or -999))
sleep_ms(20)
print(string.format("[B] +20ms pid=%s", tostring(to_num(sc_getpid()))))
print("[B] SURVIVED: the child faulted on the unmapped page and the loader lived")
print("")
print("=== PROBE 1556a COMPLETE ===")
