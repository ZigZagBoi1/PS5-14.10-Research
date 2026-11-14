-- CRASH_CLASS: MODERATE
-- PROBE 1223c: blockpool_map takes a VA, not an offset.
--
-- 1223b passed offset 0 and got EINVAL for every access code. Re-reading the prologue:
--   9a9586 mov rbx,[rax+0x200]     ; rax = td_proc, so [proc+0x200] is the vmspace/vm_map
--   9a9592 cmp [rbx+0x20], r14     ; [vm_map+0x20] = min_offset
--   9a9596 jbe 0x9a95b4            ; continue only if min_offset <= uap[0]
--   9a95ba mov rcx,[rbx+0x28]      ; [vm_map+0x28] = max_offset
--   9a95c1 jbe error               ; and uap[0] < max_offset
--   9a95b4 test r14w,r14w          ; uap[0] must be 0x10000-aligned
-- So uap[0] is an address inside this process's vm_map, not an offset into the pool. 0 failed
-- because min_offset is above zero. uap[1] is the length (same alignment), uap[2] the access code
-- (bitmask 0x409 = codes 0, 3, 10), uap[3] and uap[4] are unread so far in the checks.
print("=== PROBE 1223c: blockpool_map with a chosen VA ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
local function dump24(tag, a)
    local s = {} for i = 0, 5 do s[#s+1] = string.format("%08X", rd(a + i*4)) end
    print(string.format("    %s: %s", tag, table.concat(s, " ")))
end
print(string.format("[0] pid=%d", N(mk(20)())))
local h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[1] blockpool_open = 0x%X err=%s", h, ES()))

local obuf = memory.alloc(0x40)
local mapped = 0
local vas = {0x2000000000, 0x3000000000, 0x1000000000, 0x40000000}
for vi = 1, #vas do
    local va = vas[vi]
    for _, acc in ipairs({3,0,10}) do
        local rv = N(mk(654)(uint64(va),uint64(0x10000),uint64(acc),uint64(0),uint64(0),uint64(0)))
        print(string.format("    va=0x%X len=0x10000 acc=%d -> 0x%X err=%s", va, acc, rv, ES()))
        if rv == 0 or (rv > 0x10000 and rv < 0x7FFFFFFFFF) then mapped = (rv == 0) and va or rv break end
    end
    if mapped ~= 0 then break end
end
if mapped == 0 then
    print("[2] every VA refused; trying the handle in uap[3] and uap[4]")
    for _, slot in ipairs({3,4}) do
        local args = {uint64(0x2000000000),uint64(0x10000),uint64(3),uint64(0),uint64(0),uint64(0)}
        args[slot] = uint64(h)
        local rv = N(mk(654)(args[1],args[2],args[3],args[4],args[5],uint64(0)))
        print(string.format("    handle in uap[%d] -> 0x%X err=%s", slot, rv, ES()))
        if rv == 0 or (rv > 0x10000 and rv < 0x7FFFFFFFFF) then mapped = 0x2000000000 break end
    end
end
if mapped ~= 0 then
    print(string.format("[3] mapped at 0x%X; 547 and a write test follow", mapped))
    for i = 0, 0x3C, 4 do wd(obuf + i, 0xDEADBEEF) end
    call("547", function() return mk(547)(uint64(mapped),uint64(obuf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    dump24("547", obuf)
    wd(mapped, 0x41424344)
    print(string.format("    read back 0x%08X", rd(mapped)))
else
    print("[3] nothing mapped")
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
