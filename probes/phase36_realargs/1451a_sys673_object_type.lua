-- CRASH_CLASS: MODERATE
-- PROBE 1451a: sys 673 contract + which vm_object type it accepts
--
-- Context: 13.60 body of syscall 673 is 0xffffffff8b36b1f0 (thunk rva 0x265f88 group).
--   Decoded gate chain (13.60):
--     rbx = vm_map from [proc+0x200]
--     uap[0] = r14  must be >= map->min and 0x10000-aligned   (test r14w,r14w / jne fail)
--     uap[1] = r15  must be >= map->min and 0x10000-aligned
--     uap[2] = r12  must be 0x10000-aligned                   (movzx edi,r12w / jne fail)
--     uap[3]        must be 0                                 (cmp dword [rsi+0x18],0)
--     then vm_map_lookup_entry(map, uap[0], &entry)  [0x8ac86c40]
--     entry->flags bit 1 must be clear               (test byte [entry+0x60],2)
--     entry->object ([entry+0x50]) must be non-NULL
--     OBJECT TYPE GATE:  cmp byte [obj+0x9d], 0xb ; jne fail   <-- type 11 only
--   On success it converts three of the values to 64 KiB units (shr 0x10) and calls
--   0x8b36b370(map, ..., old_lo>>16, old_hi>>16, new>>16), i.e. a BLOCK move at 64 KiB
--   granularity inside a type-11 object.  Every rejection path returns EINVAL(22).
--
--   The repo's /dev/dmem0 window is 4 GiB of GPU physical memory behind the device pager
--   (docs/DMEM_WINDOW_14_10.md), which is exactly the kind of custom object a type-11 gate
--   would name.  55e only ever tried 673 on the 0x1002 GPU mmap backing object.
--
-- -- prior art: probes/phase17_new_vectors/55e_page_remap_673.lua (single shape, GPU object,
--   ret -1), docs/DEAD_ENDS.md "sys 673 page remap", probes/phase36_realargs/1397d (dmem
--   aperture limits), docs/sysent-names-13.60.csv row `673,blockpool_move,0x265f88`.
--
-- Discriminator: every failure returns 22, so the probe looks for a single 0.  The six
--   flavours separate "needs a device object" (dm/gc succeed) from "needs any mapping"
--   (anon/zero succeed) from "type 11 does not exist here" (everything 22).
--   uap[1]'s exact meaning is unknown (address vs length), so both readings are tried.

print("=== PROBE 1451a: SYS 673 CONTRACT + OBJECT TYPE ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v) local n=N(v) if n<0 then return -1 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex(v) if v==nil then return "????????" end return string.format("0x%08X", v) end
local function isva(v) return v > 0x10000 and v < 0x8000000000 end

local OPEN = mk(5)
local MMAP = mk(477)
local S673 = mk(673)
local GETPID = mk(20)

print(string.format("[0] pid=%d", sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))))

-- SIG_IGN: a nosys neighbour must not kill the run
do
    local sa = memory.alloc(0x80)
    for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
    pcall(function() memory.write_qword(sa, uint64(1)) end)
    for _, s in ipairs({5, 6, 7, 8, 12}) do
        pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    end
end

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, uint64(s:byte(i))) end) end
    pcall(function() memory.write_byte(b + #s, uint64(0)) end)
    return b
end

local fd_dmem0 = sgn(OPEN(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
local fd_gc    = sgn(OPEN(uint64(str_addr("/dev/gc")),    uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
local fd_zero  = sgn(OPEN(uint64(str_addr("/dev/zero")),  uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] fds dmem0=%d gc=%d zero=%d", fd_dmem0, fd_gc, fd_zero))
print("")

local LEN = 0x80000

local function anon(len)
    local va = N(MMAP(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if isva(va) then return va end
    return -1
end
local function devmap(fd, len, off, prot)
    if fd <= 0 then return -1 end
    local va = N(MMAP(uint64(0), uint64(len), uint64(prot), uint64(1), uint64(fd), uint64(off)))
    if isva(va) then return va end
    return -1
end

-- uap[1] as an address, uap[1] as a length, and the degenerate shapes
local function try_shapes(tag, base)
    if base <= 0 then print(string.format("   %s: no mapping", tag)) return 0 end
    local A = base
    local r = base % 0x10000
    if r ~= 0 then A = base + (0x10000 - r) end
    if A + 0x40000 > base + LEN then
        print(string.format("   %s: base=%s no room after alignment", tag, hex(base)))
        return 0
    end
    print(string.format("   %s: base=%s aligned=%s", tag, hex(base), hex(A)))
    local shapes = {
        {"addr-addr",  A,          A + 0x10000, A + 0x20000},
        {"addr-addr2", A,          A + 0x20000, A + 0x30000},
        {"addr-self",  A,          A + 0x10000, A},
        {"addr-zero",  A,          A,           0},
        {"len",        A,          0x10000,     A + 0x20000},
        {"all-zero-t", A,          A + 0x10000, 0},
    }
    local hits = 0
    for _, s in ipairs(shapes) do
        local ok, rv = pcall(function()
            return S673(uint64(s[2]), uint64(s[3]), uint64(s[4]), uint64(0), uint64(0), uint64(0))
        end)
        if not ok then
            print(string.format("      %-10s EXC (lua error, no call)", s[1]))
        else
            local n = N(rv)
            if n == 0 then hits = hits + 1 end
            print(string.format("      %-10s rv=%d %s%s", s[1], n,
                (n == -1 and es() or ""), (n == 0 and "   *** ACCEPTED ***" or "")))
        end
    end
    return hits
end

local total = 0

print("[A] anonymous 0x1002 mapping (8 pages of 64 KiB)")
total = total + try_shapes("A", anon(LEN))
print("")

print("[B] /dev/zero mapping")
total = total + try_shapes("B", devmap(fd_zero, LEN, 0, 3))
print("")

print("[C] /dev/gc mapping (dummy device window, all-FF)")
total = total + try_shapes("C", devmap(fd_gc, LEN, 0, 3))
print("")

print("[D] /dev/dmem0 mapping (GPU aperture, 4 GiB RW window)")
total = total + try_shapes("D", devmap(fd_dmem0, LEN, 0, 3))
print("")

print(string.format("[E] accepted shapes total=%d", total))
print(string.format("[F] survivor pid=%d", sgn(GETPID(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))))
print("")
print("=== PROBE 1451a COMPLETE ===")
