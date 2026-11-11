-- CRASH_CLASS: MODERATE
-- PROBE 1223b: blockpool_map(654) is the mapping entry, not mmap(477).
--
-- 1223a: blockpool_open(653) returned handle 0x17, but mmap(477) with that fd gave EINVAL for every
-- shape. The name map and the body agree that the mapping call is 654 blockpool_map (narg 5):
--   9a957f mov rax,[rdi+8]        ; td_proc
--   9a9583 mov r14,[rsi]          ; uap[0] = offset
--   9a9586 mov rbx,[rax+0x200]    ; the blockpool context hung off proc
--   9a9592 cmp [rbx+0x20],r14     ; offset < size
--   9a95b4 test r14w,r14w         ; offset must be 0x10000-aligned
--   9a95ba mov rcx,[rbx+0x28]     ; end
--   9a95c3 mov r8,[rsi+8]         ; uap[1] = length, also 0x10000-aligned
--   9a95d8 mov r13d,[rsi+0x10]    ; uap[2] = access code, bitmask 0x409 (0,3,10)
--   9a95dc mov r9d,[rsi+0x18]     ; uap[3]
--   9a95e0 mov r12d,[rsi+0x20]    ; uap[4]
-- then vm work, and 0x9a96cf is the "cmp byte [rsi+0x9d],0xb" type check.
-- So: open the pool, map a range, then ask 547 about the returned address.

print("=== PROBE 1223b: blockpool_map ===")
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
    local s = {}
    for i = 0, 5 do s[#s+1] = string.format("%08X", rd(a + i*4)) end
    print(string.format("    %s: %s", tag, table.concat(s, " ")))
end

print(string.format("[0] pid=%d", N(mk(20)())))
local h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[1] blockpool_open(0,0) = 0x%X err=%s", h, ES()))

local obuf = memory.alloc(0x40)
local mapped = 0
print("[2] blockpool_map(offset, length, access, 0, 0)")
for _, acc in ipairs({3,0,10,2}) do
    local rv = N(mk(654)(uint64(0),uint64(0x10000),uint64(acc),uint64(0),uint64(0),uint64(0)))
    print(string.format("    acc=%d -> 0x%X err=%s", acc, rv, ES()))
    if rv > 0x10000 and rv < 0x7FFFFFFFFF then mapped = rv break end
end

if mapped == 0 then
    print("[3] no mapping; trying a 0x4000 length and a page offset")
    for _, len in ipairs({0x4000, 0x200000}) do
        local rv = N(mk(654)(uint64(0),uint64(len),uint64(3),uint64(0),uint64(0),uint64(0)))
        print(string.format("    len=0x%X -> 0x%X err=%s", len, rv, ES()))
        if rv > 0x10000 and rv < 0x7FFFFFFFFF then mapped = rv break end
    end
end

if mapped ~= 0 then
    print(string.format("[3] mapped at 0x%X; 547 follows", mapped))
    for i = 0, 0x3C, 4 do wd(obuf + i, 0xDEADBEEF) end
    call("547", function() return mk(547)(uint64(mapped),uint64(obuf),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    dump24("547", obuf)
    print("[4] write test into the mapping")
    wd(mapped, 0x41424344)
    print(string.format("    read back 0x%08X", rd(mapped)))
    call("655 unmap", function() return mk(655)(uint64(0),uint64(0x10000),uint64(0),uint64(0),uint64(0),uint64(0)) end)
else
    print("[3] blockpool_map refused every shape; nothing to inspect")
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
