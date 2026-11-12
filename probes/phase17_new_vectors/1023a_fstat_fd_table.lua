-- CRASH_CLASS: LOW
-- PROBE 1023a: fstat every descriptor and look for a kernel pointer in struct stat
--
-- 1021a established that 189 fstat is a live handler on 14.10 (open("/app0/eboot.bin") = 23,
-- fstat = 0, struct filled), which contradicts the "fstat kills the process" entry in
-- CLAUDE.md's dead-end list. FreeBSD fills st_dev and st_ino from the vnode and, on sockets
-- and kqueues, from objects that live in the kernel heap. A socket's struct stat has carried
-- a kernel pointer in some console builds. This walks every descriptor the loader holds,
-- prints the first eight qwords of the result and flags anything in the supervisor range.

print("=== PROBE 1023a: FSTAT ACROSS THE FD TABLE ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end
local function top(x) local h,l=get_hi_lo_local(x) return h end
function get_hi_lo_local(v)
    if type(v)=="table" and v.h then return v.h, v.l end
    if type(v)=="number" then return math.floor(v/4294967296), v % 4294967296 end
    local s=tostring(v):match("0x(%x+)")
    if s then local n=tonumber(s,16) if n then return math.floor(n/4294967296), n % 4294967296 end end
    return 0,0
end
local sc_fstat = mk(189); local sc_socket = mk(97); local sc_kq = mk(362); local sc_close = mk(6)
local sc_getpid = mk(20)

local buf = memory.alloc(0x100); local ba = as_addr(buf)
local pid = to_num(select(2, pcall(function() return sc_getpid() end)))
print(string.format("[0] pid=%d", pid))

-- make a couple of live objects so the table is not only the loader's own fds
local sp = to_num(select(2, pcall(function() return sc_socket(uint64(2), uint64(2), uint64(0)) end)))
local kq = to_num(select(2, pcall(function() return sc_kq() end)))
print(string.format("[0] socketpair-ish socket=%d kqueue=%d", sp, kq))

for fd = 0, 40 do
    for o=0,0xF8,8 do wd(ba+o,0) end
    local ok, rv = pcall(function() return sc_fstat(uint64(fd), uint64(ba)) end)
    local r = ok and to_num(rv) or -999
    if r == 0 then
        local vals, hits = {}, {}
        for o=0,0x38,8 do
            local v = rq(ba+o)
            vals[#vals+1] = string.format("%X", to_num(v))
            local h = get_hi_lo_local(v)
            if h >= 0xFFFF8000 then hits[#hits+1] = string.format("+0x%X", o) end
        end
        print(string.format("  fd %2d ok  %s%s", fd, table.concat(vals, " "), #hits > 0 and ("  KP "..table.concat(hits,",")) or ""))
    elseif r == -1 then
        -- closed descriptor: silence
    else
        print(string.format("  fd %2d rv=%d", fd, r))
    end
end
if sp > 0 then pcall(function() return sc_close(uint64(sp)) end) end
if kq > 0 then pcall(function() return sc_close(uint64(kq)) end) end
print(string.format("[Z] alive pid=%d", to_num(select(2, pcall(function() return sc_getpid() end)))))
print("=== COMPLETE ===")
