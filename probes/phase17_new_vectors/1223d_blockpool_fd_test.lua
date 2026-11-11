-- CRASH_CLASS: LOW
-- PROBE 1223d: is blockpool_open(653)'s return value a file descriptor?
--
-- 1223a-c: 653 returns a small increasing value (0x17, 0x18, 0x19 across runs), mmap(477) with it
-- as fd gives EINVAL for every prot/flags shape, and blockpool_map(654) gives EINVAL because
-- vm_map_lookup at the caller's VA finds no entry. The body of 654 proves the lookup:
--   9a9691 call 0x2c6820  (mtx_lock on [proc+0x200], the vm_map)
--   9a9696 lea rdx,[rbp-0x38] ; 9a969d mov rsi,r14 ; 9a96a0 call 0x2c6c40   (vm_map_lookup(rbx, uap[0], &entry))
--   9a96c2 mov rsi,[rcx+0x50] ; 9a96cf cmp byte [rsi+0x9d],0xb            (entry->object->class must be 0xb)
-- So 654 only manipulates a mapping that already exists. Something else must create it.
-- fstat is the cheapest fd test: 189(fd, buf) returns 0 and fills a stat for a real descriptor,
-- EBADF otherwise.
print("=== PROBE 1223d: what is 653's return value ===")
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
local h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[1] 653 = 0x%X (%d)", h, h))
local sb = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(sb + i, 0) end
call("fstat(653ret)", function() return mk(189)(uint64(h),uint64(sb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    stat mode=0x%X size=0x%X", rd(sb + 4), rd(sb + 0x20)))
call("fstat(0)", function() return mk(189)(uint64(0),uint64(sb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("fstat(1)", function() return mk(189)(uint64(1),uint64(sb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("fstat(9999)", function() return mk(189)(uint64(9999),uint64(sb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
call("close(653ret)", function() return mk(6)(uint64(h),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
