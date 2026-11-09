-- CRASH_CLASS: LOW
-- PROBE 530s: Submit struct variations (heap only, no phys alloc)
--
-- 530r crashed (zero output). Simplify: use heap fence buffer,
-- test different submit struct layouts.
--
-- Known: ioctl 0xC0108102 = submit, 16 bytes struct.
-- ps5-hen: submit_args = {pipe(u32), count(u32), cmds_ptr(u64)}
-- But pipe IDs and format might differ on 14.10.

print("=== PROBE 530s: SUBMIT ONLY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local devpath = memory.alloc(0x20)
local name = "/dev/gc"
for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
wd(N(devpath) + #name, 0)
local gc_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("gc=%d", gc_fd))

local sc_ioctl = mk(54)

-- Heap fence
local fence = memory.alloc(0x10)
wq(N(fence), uint64(0))

-- EVENT_WRITE_EOP command buffer (heap)
local cmd = memory.alloc(0x100)
wd(N(cmd) + 0x00, 0xC0044700)  -- EVENT_WRITE_EOP header
wd(N(cmd) + 0x04, 0x00000504)  -- event_type=4, index=5
local fence_n = N(fence)
wd(N(cmd) + 0x08, fence_n % 0x100000000)
wd(N(cmd) + 0x0C, math.floor(fence_n / 0x100000000) + 0x01000000)
wd(N(cmd) + 0x10, 0xBEEF0001)

-- INDIRECT_BUF descriptor
local desc = memory.alloc(0x10)
local cmd_n = N(cmd)
wd(N(desc) + 0, 0xC0023F00)
wd(N(desc) + 4, cmd_n % 0x100000000)
wd(N(desc) + 8, math.floor(cmd_n / 0x100000000))
wd(N(desc) + 12, 5)

local desc_n = N(desc)
local desc_lo = desc_n % 0x100000000
local desc_hi = math.floor(desc_n / 0x100000000)

local function try_sub(label, d0, d1, d2, d3)
    wq(N(fence), uint64(0))
    local sub = memory.alloc(0x10)
    wd(N(sub), d0)
    wd(N(sub) + 4, d1)
    wd(N(sub) + 8, d2)
    wd(N(sub) + 12, d3)
    local ok_s, rv_s = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
    end)
    local ret = rv_s and N(rv_s) or -999
    local dummy = 0
    for i = 1, 200000 do dummy = dummy + 1 end
    local fval = rd(N(fence)) or 0
    if fval < 0 then fval = fval + 0x100000000 end
    print(string.format("  %s: rv=%d fence=0x%X", label, ret, fval))
end

-- ============================================================
-- [A] Standard layout: {pipe, count, desc_lo, desc_hi}
-- ============================================================
print("[A] Standard layouts")
try_sub("p0c1", 0, 1, desc_lo, desc_hi)
try_sub("p1c1", 1, 1, desc_lo, desc_hi)

-- ============================================================
-- [B] Reversed: {count, pipe, desc_lo, desc_hi}
-- ============================================================
print("")
print("[B] Reversed")
try_sub("c1p0", 1, 0, desc_lo, desc_hi)
try_sub("c1p1", 1, 1, desc_lo, desc_hi)

-- ============================================================
-- [C] Ptr first: {desc_lo, desc_hi, count, pipe}
-- ============================================================
print("")
print("[C] Ptr first")
try_sub("ptr_c1_p0", desc_lo, desc_hi, 1, 0)
try_sub("ptr_c1_p1", desc_lo, desc_hi, 1, 1)

-- ============================================================
-- [D] Single cmd pointer (not indirect buf array):
-- Maybe the ioctl expects a DIRECT pointer to the PM4 cmd buffer?
-- ============================================================
print("")
print("[D] Direct cmd pointer")
local cmd_lo2 = cmd_n % 0x100000000
local cmd_hi2 = math.floor(cmd_n / 0x100000000)
try_sub("cmd_p0", 0, 1, cmd_lo2, cmd_hi2)
try_sub("cmd_5dw", 0, 5, cmd_lo2, cmd_hi2)

-- ============================================================
-- [E] With doorbell offset (0x5C) as pipe ID
-- ============================================================
print("")
print("[E] Doorbell as pipe")
try_sub("p5C_c1", 0x5C, 1, desc_lo, desc_hi)

-- ============================================================
-- [F] 8-byte submit? Maybe only {count, desc_ptr}
-- ============================================================
print("")
print("[F] Compact submit (fill 8 bytes, rest zero)")
try_sub("compact_a", 1, desc_lo, desc_hi, 0)  -- {count, desc_lo, desc_hi, 0}
try_sub("compact_b", desc_lo, desc_hi, 0, 0)  -- {desc_lo, desc_hi, 0, 0}

-- ============================================================
-- [G] Read submit struct after ioctl to see what kernel wrote back
-- ============================================================
print("")
print("[G] Submit readback")
wq(N(fence), uint64(0))
local sub = memory.alloc(0x20)
for i = 0, 0x1F, 4 do wd(N(sub) + i, 0xAAAAAAAA) end  -- marker
wd(N(sub), 0)
wd(N(sub) + 4, 1)
wd(N(sub) + 8, desc_lo)
wd(N(sub) + 12, desc_hi)

pcall(function() sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub))) end)

print("  after submit:")
for i = 0, 7 do
    local d = rd(N(sub) + i * 4) or 0
    if d < 0 then d = d + 0x100000000 end
    print(string.format("  [+%d] 0x%08X", i*4, d))
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)

print("")
print("=== 530s DONE ===")
