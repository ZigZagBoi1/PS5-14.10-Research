-- CRASH_CLASS: MODERATE
-- PROBE 975c: fcntl(F_GETFL) as a descriptor enumerator
--
-- fstat kills and dup returns -1, but fcntl(F_GETFL) validates a descriptor without
-- reading or writing it. If it works, the process's descriptor table becomes visible
-- for the first time, including anything the game itself holds open.
print("=== PROBE 975c: FCNTL FD MAP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local pid=to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  socketpair = %d, %d", fd0, fd1))
local buf=memory.alloc(0x40)

local function fc(fd, cmd, tag)
    local ok, rv = pcall(function() return mk(92)(uint64(fd), uint64(cmd), uint64(0)) end)
    if not ok then return nil end
    local h,l = hi_lo(rv)
    print(string.format("  [%s fd=%d cmd=%d] ret=0x%08X_%08X (%d)", tag, fd, cmd, h, l, to_num(rv)))
    return to_num(rv)
end

print("[B] known-good control")
fc(fd0, 3, "good")     -- F_GETFL
fc(fd0, 1, "good")     -- F_GETFD
print("[C] known-bad control")
fc(0x7FF, 3, "bad")
print("[D] read(fd,buf,0) control")
local function rd0(fd)
    local ok, rv = pcall(function() return mk(3)(uint64(fd), uint64(buf), uint64(0)) end)
    if not ok then return nil end
    local h,l = hi_lo(rv)
    return to_num(rv)
end
print(string.format("  read0 good=%d bad=%d", rd0(fd0) or -999, rd0(0x7FF) or -999))

print("[E] sweep 0..47 with F_GETFL")
local open, closed = {}, 0
for fd=0,47 do
    local r = fc(fd, 3, "fl")
    if r == nil then print("    KILLED at fd "..fd) return end
    if r >= 0 then open[#open+1] = string.format("%d:0x%X", fd, r) else closed = closed + 1 end
end
print(string.format("[F] open=%d closed=%d", #open, closed))
print("    " .. table.concat(open, " "))
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
