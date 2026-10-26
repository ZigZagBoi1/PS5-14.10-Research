-- CRASH_CLASS: LOW
-- PROBE 778b: open-only device sweep
--
-- 778a opened /dev/null, /dev/zero, /dev/random, /dev/urandom and then
-- blocked forever reading /dev/ptmx, which wedged the loader. So: no reads
-- here. Opening only. Anything that opens gets inspected in a later probe,
-- one device per probe, so a blocking read costs one probe, not a session.
print("=== PROBE 778b: DEVICE OPEN SWEEP ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local page=to_num(memory.alloc(0x400)); zero(page,0x400)
local paths={
 "/dev/klog","/dev/bpf","/dev/bpf0","/dev/auditpipe","/dev/io","/dev/mem",
 "/dev/kmem","/dev/gc","/dev/dce","/dev/hid","/dev/dmem0","/dev/dmap",
 "/dev/sce_keymgr","/dev/sce_ssud","/dev/sce_uart","/dev/sce_rtc","/dev/sce_thermal",
 "/dev/uart","/dev/ad0","/dev/da0","/dev/vhci","/dev/ugen0.1","/dev/ump0",
 "/dev/pty","/dev/console","/dev/ttyv0","/dev/sysmouse","/dev/event0",
 "/proc/self/status","/proc/curproc/cmdline","/proc/self/map","/dev/fd/0",
 "/dev/sce_camera","/dev/sce_audio","/dev/sce_vdec","/dev/sce_venc"
}
local opened=0
for _,p in ipairs(paths) do
    zero(page,0x400)
    pcall(function()
        for i=1,#p do memory.write_byte(page+i-1, p:byte(i)) end
        memory.write_byte(page+#p, 0)
    end)
    local fd=call(mk(5),page,4,0,0,0,0)
    if type(fd)=="number" and fd>=0 then
        opened=opened+1
        print(string.format("[+] %-24s open fd=%d",p,fd))
        call(mk(6),fd,0,0,0,0,0)
    end
end
print(string.format("[A] opened %d/%d alive=%s",opened,#paths,tostring(call(mk(20),0,0,0,0,0,0))))
print("=== 778b DONE ===")
