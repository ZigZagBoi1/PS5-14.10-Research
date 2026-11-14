-- CRASH_CLASS: LOW
-- PROBE 1222a: socket-level ioctl and the Sony socket extensions, scanned for kernel pointers.
--
-- Upstream's open row O10 says the ioctl sweep tested /dev nodes but never socket descriptors
-- (docs/2026-10-25/README.md:73). This corpus separately recorded that syscall 54 "never resolves
-- the descriptor - ENOTTY even for fd 9999", which would make the socket ioctl space unreachable.
-- Both cannot be right. FIONBIO is the cheapest discriminator: it either sets O_NONBLOCK on a real
-- socket or returns ENOTTY.
--
-- Then the never-called Sony network entries 102 netgetsockinfo, 125 netgetiflist, 113 socketex and
-- 141 kqueueex get a first call with output buffers that are scanned for supervisor-range qwords.

print("=== PROBE 1222a: socket ioctl + Sony net extensions ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
local function scan(tag, addr, len)
    local kp, n = 0, 0
    local first = nil
    for i = 0, len - 8, 8 do
        local v = rq(addr + i)
        if v then
            n = n + 1
            if v >= 0xFFFF800000000000 then
                kp = kp + 1
                if not first then first = string.format("+0x%X=0x%X", i, v) end
            end
        end
    end
    print(string.format("    scan %s: %d qwords, %d supervisor-range %s", tag, n, kp, first or ""))
    return kp
end

print("[A] socket(AF_INET, SOCK_DGRAM, 0)")
local sv = memory.alloc(8)
local fd = N(mk(97)(uint64(2),uint64(2),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("    fd=%d (%s)", fd, tostring(fd)))
if fd <= 0 then print("no socket"); print("=== DONE ===") return end

print("[B] FIONBIO (0x8004667E) through syscall 54 - does 54 resolve a socket at all")
local bio = memory.alloc(8) wd(bio, 1)
call("FIONBIO", function() return mk(54)(uint64(fd),uint64(0x8004667E),uint64(bio),uint64(0),uint64(0),uint64(0)) end)
call("FIONBIO off", function() return mk(54)(uint64(fd),uint64(0x8004667E),uint64(bio),uint64(0),uint64(0),uint64(0)) end)
wd(bio, 0)
call("FIONBIO zero", function() return mk(54)(uint64(fd),uint64(0x8004667E),uint64(bio),uint64(0),uint64(0),uint64(0)) end)

print("[C] SIOC* ifreq sweep on the socket, 0x200 buffer scanned for kernel pointers")
local buf = memory.alloc(0x400)
local total_kp = 0
local codes = {0xC0206911,0x8912,0xC0206920,0x8921,0xC0206922,0x8923,0x8913,0x8914,0x8915,
               0x8916,0x8917,0x8918,0x8919,0x891A,0x891B,0xC0206933,0xC0206934,0xC0806935,
               0xC0206936,0xC0206938,0xC020693A,0x8940,0x8941,0x8942,0x8943,0x8944,0x8945,
               0x8946,0x8947,0x8948,0x8949,0x894A,0x894B,0x894C,0x894D,0x894E,0x894F}
for i = 1, #codes do
    for j = 0, 0x3F8, 8 do wd(buf + j, 0) end
    local ok, rv = pcall(function() return mk(54)(uint64(fd),uint64(codes[i]),uint64(buf),uint64(0),uint64(0),uint64(0)) end)
    local h,l = hilo(rv)
    local kp = scan(string.format("0x%X", codes[i]), buf, 0x100)
    total_kp = total_kp + kp
    print(string.format("  ioctl 0x%08X ret=0x%08X_%08X err=%s", codes[i], h, l, ES()))
end
print(string.format("[C] supervisor-range qwords across the sweep: %d", total_kp))

print("[D] Sony socket extensions, first calls")
for _, num in ipairs({102, 125, 113, 141}) do
    for j = 0, 0x3F8, 8 do wd(buf + j, 0) end
    local ok, rv = pcall(function() return mk(num)(uint64(fd),uint64(buf),uint64(0x100),uint64(0),uint64(0),uint64(0)) end)
    local h,l = hilo(rv)
    print(string.format("  sys %d (fd,buf,0x100) ret=0x%08X_%08X err=%s", num, h, l, ES()))
    scan(string.format("sys%d", num), buf, 0x100)
    for j = 0, 0x3F8, 8 do wd(buf + j, 0) end
    ok, rv = pcall(function() return mk(num)(uint64(buf),uint64(0x100),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    h,l = hilo(rv)
    print(string.format("  sys %d (buf,0x100) ret=0x%08X_%08X err=%s", num, h, l, ES()))
    scan(string.format("sys%d-b", num), buf, 0x100)
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
