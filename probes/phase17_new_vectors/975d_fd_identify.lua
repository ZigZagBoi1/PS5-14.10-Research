-- CRASH_CLASS: LOW
-- PROBE 975d: identify every open descriptor in the loader process
--
-- fcntl(F_GETFL) works (975c), so the table is visible. This classifies each entry:
-- getsockname(32) succeeds only for sockets and returns sa_family and, for AF_UNIX,
-- the bound path; lseek(478, SEEK_CUR) succeeds only for seekable files.
print("=== PROBE 975d: FD IDENTIFICATION ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function rbyte(a) local o,v=pcall(function() return to_num(memory.read_byte(a)) end) if o then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function cstr(p, max)
    local s=""
    for i=0,max-1 do
        local c=rbyte(p+i)
        if c<=0 then break end
        if c>=32 and c<127 then s=s..string.char(c) else s=s.."?" end
    end
    return s
end

local pid=to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local sa=memory.alloc(0x120)
local lp=memory.alloc(8)

local function classify(fd)
    -- F_GETFL
    local okf, fl = pcall(function() return mk(92)(uint64(fd),uint64(3),uint64(0)) end)
    local flags = okf and to_num(fl) or -1
    if flags < 0 then return nil end
    -- getsockname
    for i=0,0x11C,4 do wd(sa+i,0) end
    wd(lp,0x110)
    local oks, srv = pcall(function() return mk(32)(uint64(fd),uint64(sa),uint64(lp)) end)
    local issock = oks and to_num(srv)==0
    local fam, path = -1, ""
    if issock then
        fam = rbyte(sa+1)
        if fam == 1 then path = cstr(sa+2, 100)        -- AF_UNIX
        elseif fam == 2 then path = string.format("inet port=%d", (rbyte(sa+2)*256)+rbyte(sa+3))
        elseif fam == 28 then path = "inet6" end
    end
    -- lseek SEEK_CUR
    local okl, lsv = pcall(function() return mk(478)(uint64(fd),int64(0),uint64(1)) end)
    local seek = (okl and to_num(lsv)>=0)
    return flags, issock and fam or nil, path, seek
end

print("[B] control: socketpair fds then the real table")
local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  socketpair = %d, %d", fd0, fd1))
print("[C] table 0..40")
for fd=0,40 do
    local flags, fam, path, seek = classify(fd)
    if flags ~= nil then
        local kind = "?"
        if fam then kind = "SOCKET" elseif seek then kind = "FILE" elseif flags == 2 then kind = "RDRW?" else kind = "other" end
        print(string.format("  fd=%-2d fl=0x%X %-6s %s%s", fd, flags, kind, path, seek and " seekable" or ""))
    end
end
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
