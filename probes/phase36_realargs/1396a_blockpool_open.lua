-- CRASH_CLASS: MODERATE -- blockpool_open allocates a 0x410b0-byte kernel object and a file
-- descriptor per successful call; the flags domain is four values, so the sweep is bounded. Phase B
-- only runs if a descriptor comes back, and it maps that descriptor READ|WRITE without writing.
-- PROBE 1396a: does blockpool_open (sys 653) still mint a file descriptor on 14.10?
--
-- The blockpool family is the one Sony object family this project never opened. Its 13.60 body
-- (results/kernel_handlers/asm/sys_653_deep.asm, entry 0x9a7d10) is small and unusually permissive:
--
--   r15d = uap[0]; test r15d, 0xffafffff; jne EINVAL        <- only bits 0x100000 / 0x400000 pass
--   kmalloc(0x410b0, type 0x255fdd0, 0x8102)                 <- the pool object
--   [obj+0x60] = proc->p_?; [obj+0x64] = proc->p_?           <- ids copied from the process
--   a per-index counter at 0x3ba5e90 capped by 0x3ba5ec0     <- EMFILE (0x18) when full
--   obj inserted into the global list at 0x3ba5e88
--   falloc(td, &fp, &fdnum, flags|2)                         <- A REAL FILE DESCRIPTOR
--   fp->f_ops = 0x255fec8, fp->f_data = obj, type 0x11
--   td->td_retval[0] = fdnum                                 <- the descriptor is the return value
--
-- There is no credential check anywhere in it, so if 14.10 keeps the shape this returns a live fd
-- and the rest of the family becomes reachable: 654 blockpool_map (a 64 KiB vm_object range
-- operation whose only stated precondition is that the map entry's vm_object type byte at +0x9d
-- equals 0xb), 655 blockpool_unmap, 657 blockpool_batch (which already answers 0 to everyone) and
-- 672/673 blockpool_move. docs/DEAD_ENDS.md:85 records 673 returning -1 for every shape tried,
-- with the reason "the GPU mmap backing object is not type 11" - i.e. the type gate, not a
-- privilege gate, is what stopped it. A descriptor we allocate ourselves would supply the type.
--
-- The last measurement of 653 on 14.10 is 1341b's `653(a=0)` -> ret 22 and 1342a's N class -> 22,
-- both of which contradict the 13.60 mask (0 & 0xffafffff == 0, so 0 must pass it). Either 14.10
-- changed the handler or the earlier probes passed a different value. This probe passes the flags
-- word in uap[0] and six explicit zeros, and prints rv plus errno for each.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_653_deep.asm (the open path above)
--   results/kernel_handlers/asm/sys_654.asm:11469 (blockpool_map body, vm_object type 0xb gate)
--   results/kernel_handlers/asm/sys_673.asm:13154 (blockpool_move, same gate)
--   docs/DEAD_ENDS.md:85 (673 refused for the GPU backing object)
--   results/phase35_dead_end_reruns/1341b_vm_ops_ordered_20261109_095307.txt (`653(a=0)` -> 22)

print("=== PROBE 1396a: BLOCKPOOL OPEN (SYS 653) ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = N(v) % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function rq(a) local ok,v = pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIGSYS ignored so an absent slot answers -1 instead of killing the process.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end
local rb = rd(sa)
print(string.format("[0] SIG_IGN installed, sig12 handler readback=%s", rb and hex(rb) or "?"))

local MAP_SHARED  = 1
local PROT_RW     = 3

local function mm(addr, len, prot, flags, fd, off)
    local ok, rv = pcall(function()
        return mk(477)(uint64(addr), uint64(len), uint64(prot), uint64(flags), uint64(fd), uint64(off))
    end)
    if not ok then return -99999 end
    return N(rv)
end

local function call_bp_open(flags)
    local ok, rv = pcall(function()
        return mk(653)(uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return -99999, "pcall raised" end
    return N(rv), es()
end

print("")
print("[A] blockpool_open(flags) -- the 13.60 mask admits only 0x0/0x100000/0x400000/0x500000")
local FDS = {}
for _, f in ipairs({0, 0x100000, 0x400000, 0x500000, 1, 0x200000, 0x1000, 0x10000000}) do
    local rv, e = call_bp_open(f)
    local note = ""
    if rv >= 3 and rv < 4096 then
        note = "  <- looks like a descriptor"
        table.insert(FDS, rv)
    end
    print(string.format("   653(0x%X) -> %d  %s%s", f, rv, tostring(e), note))
    if rv == -99999 then break end
end

if #FDS == 0 then
    print("[A] no descriptor returned; family stays unreachable from open")
else
    print("")
    print("[B] descriptors returned: " .. table.concat(FDS, ","))
    for _, fd in ipairs(FDS) do
        local st = memory.alloc(0x200)
        for i = 0, 0xC0, 8 do pcall(function() memory.write_qword(st + i, uint64(0)) end) end
        local frv, fe = pcall(function() return N(mk(189)(uint64(fd), uint64(st), uint64(0), uint64(0), uint64(0), uint64(0))) end)
        print(string.format("   [B] fd=%d fstat -> %s %s  (buf +0:%s +4:%s)", fd,
            frv and tostring(frv) or "EXC", frv and es() or "",
            rd(st) and hex(rd(st)) or "?", rd(st + 4) and hex(rd(st + 4)) or "?"))

        local p = mm(0, 0x40000, PROT_RW, MAP_SHARED, fd, 0)
        print(string.format("   [B] fd=%d mmap(len=0x40000, PROT_RW, SHARED, off=0) -> %d %s", fd, p, es()))
        if p > 0 and p ~= -1 then
            local q0 = rq(p)
            print(string.format("   [B] fd=%d mapped read +0=%s", fd, q0 and tostring(q0) or "?"))
            local nz = 0
            for i = 0, 0x3FFC, 4 do local v = rd(p + i) if v and v ~= 0 then nz = nz + 1 end end
            print(string.format("   [B] fd=%d mapped page nonzero dwords=%d/4096", fd, nz))

            print("   [C] blockpool_map(addr,len,sel,flags,0) on the new mapping")
            for _, sh in ipairs({
                {0x10000, 0x0, 0x22}, {0x10000, 0x0a, 0x0}, {0x10000, 0x3, 0x22},
                {0x40000, 0x0, 0x22}, {0x10000, 0x15, 0x22},
            }) do
                local len, sel, fl = sh[1], sh[2], sh[3]
                local ok2, rv2 = pcall(function()
                    return N(mk(654)(uint64(p), uint64(len), uint64(sel), uint64(fl), uint64(0), uint64(0)))
                end)
                print(string.format("       654(addr,0x%X,sel=0x%X,fl=0x%X) -> %s %s", len, sel, fl,
                    ok2 and tostring(rv2) or "EXC", ok2 and es() or ""))
            end
            print("   [C] blockpool_move(off,0,len,0,0,0) on the same mapping")
            for _, off in ipairs({0, 0x10000, p}) do
                local ok3, rv3 = pcall(function()
                    return N(mk(673)(uint64(off), uint64(0), uint64(0x10000), uint64(0), uint64(0), uint64(0)))
                end)
                print(string.format("       673(0x%X,0,0x10000) -> %s %s", off,
                    ok3 and tostring(rv3) or "EXC", ok3 and es() or ""))
            end
        end
    end
end

print("")
print("[D] blockpool_batch (657) with the same fd shape, for the record")
if #FDS > 0 then
    local fd = FDS[1]
    local ok, rv = pcall(function()
        return N(mk(657)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    print(string.format("   657(fd=%d,0,0,0,0,0) -> %s %s", fd, ok and tostring(rv) or "EXC", ok and es() or ""))
    for _, fd2 in ipairs(FDS) do
        pcall(function() return N(mk(6)(uint64(fd2), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    end
    print("   [D] descriptors closed")
end

print("")
print("=== PROBE 1396a COMPLETE ===")
