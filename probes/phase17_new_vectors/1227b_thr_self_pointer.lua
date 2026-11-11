-- CRASH_CLASS: LOW
-- PROBE 1227b: thr_self(432) takes a pointer (FreeBSD long *id), so the earlier -1 was a bad arg.
-- With a real tid, thr_get_ucontext(634) becomes testable.
print("=== PROBE 1227b: thr_self pointer form, then 634 ===")
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
    print(string.format("    %s: %d supervisor qwords %s", tag, kp, first or ""))
end
print(string.format("[0] pid=%d", N(mk(20)())))
local tp = memory.alloc(16) wd(tp,0) wd(tp+4,0)
call("432(&tid)", function() return mk(432)(uint64(tp),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local tid = rd(tp)
print(string.format("    tid = 0x%X (%d)", tid, tid))
if tid > 0 then
    local ctx = memory.alloc(0x600)
    for i=0,0x5FC,4 do wd(ctx+i,0xA5A5A5A5) end
    call("634(tid)", function() return mk(634)(uint64(tid),uint64(ctx),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    local s={} for i=0,15 do s[#s+1]=string.format("%08X",rd(ctx+i*4)) end
    print("    first 0x40: "..table.concat(s," "))
    scan("634", ctx, 0x4c0)
    for i=0,0x5FC,4 do wd(ctx+i,0xA5A5A5A5) end
    call("634(pid)", function() return mk(634)(uint64(N(mk(20)())),uint64(ctx),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    scan("634 pid", ctx, 0x4c0)
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")
