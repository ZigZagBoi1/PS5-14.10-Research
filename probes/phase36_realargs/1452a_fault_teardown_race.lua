-- CRASH_CLASS: HIGH
-- PROBE 1452a: fault-vs-teardown race, after the containment question
--
-- Context:
--   1450a measured that munmap(73) on 14.10 removes the WHOLE vm_map_entry that contains addr,
--   whatever the offset inside it and whatever len says (a neighbour entry is untouched).  The
--   13.60 body (0xffffffff8b478bb0) computes start/end correctly and then calls the map-remove
--   helper, so the collapse is below the syscall boundary: the VM layer has been modified.
--   1446d showed the page tables go with the entry, so in the four shapes measured there was no
--   stale mapping.  A stale PTE needs an interleaving, not a shape -- a fault handler installing a
--   PTE after teardown has already freed the page.
--
--   CAVEAT: [A] deliberately faults a loader thread.  Both precedents point the same way --
--   results/phase35_dead_end_reruns/1350b_sys622_kill_containment_20261109_110109.txt and
--   results/phase17_new_vectors/1042a_aio_lua_race_20261103_183752.txt both end at the spawn line
--   with nothing after -- so the EXPECTED outcome of [A] is a dead game process and a relaunch.
--   [C] is gated on [A]'s marker and does not run unless the thread completed.
--
--   Before racing anything, two things must be established:
--     [A] does a loader Lua thread that faults on an unmapped address take the whole process with
--         it?  (1350b showed a 622 kill does.  1199a-1199c showed a raw thr_create child fault is
--         contained.  A loader thread is a third case and has never been measured.)
--     [B] does mmap hand back the same VA after the entry is removed?  1450a saw 0x31072C000 three
--         times in a row, but that is three samples from one probe.
--
--   The detector is CONTENT, not a crash: the child reads a canary word that main refreshes every
--   round.  Anything that is neither 0 (fresh zero page) nor the canary means the page under that
--   address belongs to somebody else -- a kernel page shows up as a 0xFFFF8xxx/0xFFFFFFFF high
--   dword.  The child guards every read with sys 547 (query_memory_protection) so that a legitimately
--   unmapped window does not kill it, and records its counters in shared memory.
--
-- -- prior art:
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (entry-scoped munmap)
--   results/phase36_realargs/1446d_instrument_selftest_20261109_171122.txt (PTEs go with the entry)
--   results/phase35_dead_end_reruns/1350b_sys622_kill_containment_20261109_XXXXXX.txt (a kill in a
--     loader thread takes the process; the thread sees separate globals, so format addresses in)
--   results/phase17_new_vectors/1175a_loader_thread_api_20261104_160547.txt (a parked thread does
--     not stop main)
--   results/phase17_new_vectors/1199a (raw thr_create child faults are contained, 512 of them)
--   CLAUDE.md rule 5: reading unmapped/execute-only memory faults past pcall.

print("=== PROBE 1452a: FAULT vs TEARDOWN RACE ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function sgn(v) local n=N(v) if n<0 then return -1 end return n end
local function hex(v) if v==nil then return "????????" end return string.format("0x%X", v) end
local function isva(v) return v > 0x10000 and v < 0x8000000000 end
local function rdq(a) local ok,v = pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wrq(a,v) return (pcall(function() memory.write_qword(a, uint64(v)) end)) end

local MAP, UNMAP, QPROT, GETPID = mk(477), mk(73), mk(547), mk(20)

local function getpid() return sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0))) end

local fd = 0
do local ok, v = pcall(function() return N(memory.read_qword(signal.fd_addr)) end)
   if ok then fd = v end end

local SH = N(memory.alloc(0x100))          -- shared: +0x00 stage, +0x08 stop, +0x10 foreign,
for i = 0, 0x80, 8 do wrq(SH + i, 0) end    -- +0x18 first bad value, +0x20 iters, +0x28 notice
local REG = N(memory.alloc(0x100))

print(string.format("[0] pid=%d fd=%d SH=0x%X", getpid(), fd, SH))
print("")

local function spin(n) local x = 0 for i = 1, n do x = x + i end return x end

local function mmap_anon(len)
    local ok, va = pcall(function()
        return MAP(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return -1 end
    local n = N(va)
    if not isva(n) then return -1 end
    return n
end
local function unmap(addr)
    return sgn(UNMAP(uint64(addr), uint64(0x1000), uint64(0), uint64(0), uint64(0), uint64(0)))
end
local function mapped(addr)
    for i = 0, 0x20, 4 do pcall(function() memory.write_dword(REG + i, uint64(0)) end) end
    local ok, rv = pcall(function() return QPROT(uint64(addr), uint64(REG)) end)
    if not ok then return false end
    return sgn(rv) == 0
end

--------------------------------------------------------------------------
-- [A] containment: does a faulting loader thread take the process?
--------------------------------------------------------------------------
print("[A] containment: a loader thread reads an unmapped address")
do
    local dst = 0x7FFFFF000000
    local src = string.format([[
local S = 0x%X
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local ok = pcall(function() return memory.read_qword(uint64(0x%X)) end)
if ok then
    memory.write_qword(uint64(S+0x28), uint64(0x2222))
else
    memory.write_qword(uint64(S+0x28), uint64(0x3333))
end
memory.write_qword(uint64(S+0x28), uint64(0x4444))
]], SH, dst)
    wrq(SH + 0x28, 0x1111)
    local ok, res = pcall(run_lua_code_in_new_thread, src, { async = true, client_fd = fd })
    if not ok then print(string.format("   spawn FAILED: %s", tostring(res))) end
    for i = 1, 20 do
        print(string.format("   MAIN-%d", i))
        spin(3000000)
    end
    print(string.format("   marker=0x%X  %s", rdq(SH + 0x28) or 0,
        (rdq(SH + 0x28) == 0x4444) and "THREAD SURVIVED THE READ" or "THREAD DIED"))
end
print(string.format("[A] alive pid=%d", getpid()))
print("")
if rdq(SH + 0x28) ~= 0x4444 then
    print("[!] [A] thread did not survive the read -- skipping [B]/[C]")
    print("=== PROBE 1452a COMPLETE ===")
    return
end

--------------------------------------------------------------------------
-- [B] does mmap hand back the same VA after the entry is removed?
--------------------------------------------------------------------------
print("[B] address stability over 6 mmap/unmap rounds")
local A = -1
do
    local seen = {}
    for r = 1, 6 do
        local va = mmap_anon(0x4000)
        if va > 0 then
            seen[#seen + 1] = va
            if r == 1 then A = va end
            unmap(va)
        else
            seen[#seen + 1] = -1
        end
    end
    for i = 1, #seen do print(string.format("   round %d -> %s", i, hex(seen[i]))) end
    A = seen[1]
end
print("")

if A <= 0 then print("[!] no mapping, stopping"); print("=== PROBE 1452a COMPLETE ==="); return end

--------------------------------------------------------------------------
-- [C] the race
--------------------------------------------------------------------------
print(string.format("[C] race: main mmap/unmap at 0x%X while a thread reads the canary", A))
local ROUNDS = 30000
local CANARY = 0x44112233

do
    local src = string.format([[
local S, A = 0x%X, 0x%X
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local Q = mk(547)
local REG = N(memory.alloc(0x100))
local foreign, firstv, iters = 0, 0, 0
local CAN = %d
memory.write_qword(uint64(S+0x38), uint64(0xC0DE))
while iters < 20000000 do
    local st = N(memory.read_qword(uint64(S+8)))
    if st ~= 0 then break end
    for i = 0, 0x20, 4 do pcall(function() memory.write_dword(REG + i, uint64(0)) end) end
    local ok, rv = pcall(function() return Q(uint64(A), uint64(REG)) end)
    if ok and N(rv) == 0 then
        local v = N(memory.read_dword(uint64(A)))
        if v ~= 0 and v ~= CAN then
            foreign = foreign + 1
            if foreign == 1 then firstv = v end
        end
    end
    iters = iters + 1
    if iters %% 65536 == 0 then memory.write_qword(uint64(S+0x20), uint64(iters)) end
end
memory.write_qword(uint64(S+0x10), uint64(foreign))
memory.write_qword(uint64(S+0x18), uint64(firstv))
memory.write_qword(uint64(S+0x20), uint64(iters))
]], SH, A, CANARY)
    local ok, res = pcall(run_lua_code_in_new_thread, src, { async = true, client_fd = fd })
    if not ok then
        print(string.format("   spawn FAILED: %s", tostring(res)))
    else
        local moved, mm_fail, u_ok, u_err = 0, 0, 0, 0
        for r = 1, ROUNDS do
            local va = mmap_anon(0x4000)
            if va > 0 then
                if va ~= A then moved = moved + 1 end
                pcall(function() memory.write_dword(va, uint64(CANARY)) end)
                pcall(function() memory.write_dword(va + 0x1000, uint64(CANARY)) end)
                local u = unmap(va)
                if u == 0 then
                    u_ok = u_ok + 1
                else
                    u_err = u_err + 1
                    print(string.format("   unmap FAILED at round %d (rv=%d), aborting", r, u))
                    break
                end
            else
                mm_fail = mm_fail + 1
            end
            if r % 5000 == 0 then
                print(string.format("   round %d moved=%d mmap_fail=%d unmap_ok=%d unmap_err=%d child_alive=%s foreign=%d",
                    r, moved, mm_fail, u_ok, u_err,
                    (rdq(SH + 0x38) == 0xC0DE) and "y" or "n", rdq(SH + 0x10) or 0))
            end
        end
        wrq(SH + 8, 1)
        local n = 0
        while n < 20 and rdq(SH + 0x20) == 0 do
            spin(2000000) n = n + 1
            print(string.format("   drain %d iters=%d alive=%s", n, rdq(SH + 0x20) or 0,
                (rdq(SH + 0x38) == 0xC0DE) and "y" or "n"))
        end
        print(string.format("   child iters=%d foreign=%d first=0x%X",
            rdq(SH + 0x20) or 0, rdq(SH + 0x10) or 0, rdq(SH + 0x18) or 0))
        print(string.format("   rounds done moved=%d mmap_fail=%d unmap_ok=%d unmap_err=%d", moved, mm_fail, u_ok, u_err))
    end
end
print("")

print(string.format("[D] survivor pid=%d", getpid()))
print("")
print("=== PROBE 1452a COMPLETE ===")
