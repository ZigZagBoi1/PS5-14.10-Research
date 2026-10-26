-- CRASH_CLASS: LOW
-- PROBE 778a: enumerate console devices and scan what they hand back
--
-- Every kernel primitive so far has been a syscall. The device layer is the
-- other entry point and has never been enumerated from this loader. We only
-- open and read, so the worst case is a device that refuses or kills on read
-- (read is pcall-wrapped; a driver fault is not). No ioctl, no write.
print("=== PROBE 778a: DEVICE ENUM ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local page=to_num(memory.alloc(0x1000)); zero(page,0x1000)
local paths={
 "/dev/null","/dev/zero","/dev/random","/dev/urandom",
 "/dev/console","/dev/klog",
 "/dev/bpf","/dev/bpf0","/dev/auditpipe","/dev/io","/dev/mem","/dev/kmem",
 "/dev/gc","/dev/dce","/dev/hid","/dev/dmem0","/dev/dmap","/dev/sce_keymgr",
 "/dev/sce_ssud","/dev/sce_uart","/dev/uart","/dev/ad0","/dev/da0","/dev/vhci",
 "/dev/ugen0.1","/proc/self/status","/proc/curproc/cmdline","/dev/ump0",
 "/dev/sce_rtc","/dev/sce_thermal","/dev/pts/0","/.no_such_control_path"
}
local ok_count=0
for _,p in ipairs(paths) do
    zero(page,0x1000)
    pcall(function()
        for i=1,#p do memory.write_byte(page+i-1, p:byte(i)) end
        memory.write_byte(page+#p, 0)
    end)
    local fd=call(mk(5),page,4,0,0,0,0)
    if type(fd)=="number" and fd>=0 then
        ok_count=ok_count+1
        zero(page,0x1000)
        local r=call(mk(3),fd,page,64,0,0,0)
        local kern=0
        for i=0,7 do
            local v=rd(page+i*8+4)
            if v and v>=0xFFFF8000 then kern=kern+1 end
        end
        local hex=""
        for i=0,7 do hex=hex..string.format("%02X",rd(page+i) or 0).." " end
        print(string.format("[+] %-26s fd=%d read=%s kern=%d %s",p,fd,tostring(r),kern,hex))
        call(mk(6),fd,0,0,0,0,0)
    end
end
print(string.format("[A] opened %d/%d alive=%s",ok_count,#paths,tostring(call(mk(20),0,0,0,0,0,0))))
print("=== 778a DONE ===")
