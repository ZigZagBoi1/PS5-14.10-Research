-- CRASH_CLASS: SAFE (read-only chain analysis)
-- PROBE 42i: detailed ropchain structure analysis
--
-- 42h2's slot mapping was wrong (used fixed stride from 41z).
-- This probe dumps the ENTIRE chain and identifies the actual
-- argument data pointers by matching the gadget pattern:
--   pop rax -> address loaded into rax
--   mov rax,[rax] -> dereference to get value
--   pop rdi -> destination address
--   mov [rdi],rax -> write value to destination
--
-- The chain is ~0x300 bytes. Each arg load uses ~0x30-0x40 bytes.

print("=== PROBE 42i: CHAIN STRUCTURE ANALYSIS ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_mmap = make_syscall(477)
local sc_getpid = make_syscall(20)
local sc_dynlib_get_info = make_syscall(593)

local pid = to_num(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("pid: " .. pid)

-- Get addresses
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")

if not rop_str then
    print("cannot find ropchain")
    print("first 300 chars: " .. pipe_str:sub(1, 300))
    return
end

local rop_base = uint64(rop_str)
local fn_ptr = fn_str and uint64(fn_str) or nil

print("ropchain: " .. rop_str)
print("fn_addr ptr: " .. (fn_str or "nil"))
print("ret_addr ptr: " .. (ret_str or "nil"))

-- Get eboot base
local info = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do safe_wd(info + off, 0) end
safe_wd(info, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info) end)
local eb_lo = safe_rd(info + 0x108)
local eb_hi = safe_rd(info + 0x10C)
print(string.format("eboot: 0x%X%08X", eb_hi, eb_lo))

-- GPU mmap for heap access
local gpu
pcall(function()
    gpu = sc_mmap(uint64(0), uint64(512 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64("0xFFFFFFFF"), uint64(0))
end)
if not gpu then print("GPU FAILED"); return end
print("GPU: " .. qw_hex(gpu))

-- Verify ropchain is readable
local test = safe_rq(rop_base)
if not test then print("ropchain NOT readable"); return end
print("")

-- Prime the chain with a getpid
pcall(function() sc_getpid() end)

--------------------------------------------------------------------
-- STEP 1: Dump entire chain (0x300 bytes)
--------------------------------------------------------------------
print("--- STEP 1: FULL CHAIN DUMP ---")

for off = 0, 0x2F8, 8 do
    local q = safe_rq(rop_base + off)
    if q then
        local hex, qh, ql = qw_hex(q)
        local tag = ""
        -- Eboot gadget?
        if qh == eb_hi then
            local eoff = ql - eb_lo
            if eoff >= 0 and eoff < 0x500000 then
                tag = string.format(" G:eboot+0x%X", eoff)
            end
        end
        -- Heap pointer? (in the 0x3_xxxxxxxx range near ropchain)
        local _, rh, rl = qw_hex(rop_base)
        if qh == rh and ql >= rl - 0x100000 and ql <= rl + 0x100000 then
            tag = tag .. " H:near_chain"
            -- Dereference to see what it points to
            local target = safe_rq(q)
            if target then
                local _, th, tl = qw_hex(target)
                local ttag = ""
                if th == eb_hi then
                    local eoff = tl - eb_lo
                    if eoff >= 0 and eoff < 0x500000 then
                        ttag = string.format("=eboot+0x%X", eoff)
                    end
                end
                tag = tag .. " *=" .. qw_hex(target) .. ttag
            end
        end
        print(string.format("  +0x%03X: %s%s", off, hex, tag))
    end
end
print("")

--------------------------------------------------------------------
-- STEP 2: Also dump fn_addr region
--------------------------------------------------------------------
print("--- STEP 2: FN_ADDR REGION ---")

if fn_ptr then
    for off = -0x20, 0x30, 8 do
        local addr = fn_ptr + off
        local q = safe_rq(addr)
        if q then
            local hex, qh, ql = qw_hex(q)
            local tag = ""
            if off == 0 then tag = " <-- fn_addr" end
            print(string.format("  fn%+3d: %s%s", off, hex, tag))
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 3: Parse the pipe string for more detail
-- The tostring output has structured info about the chain layout
--------------------------------------------------------------------
print("--- STEP 3: PIPE STRING PARSE ---")

-- Print key sections of the pipe string (avoid binary)
local lines = {}
for line in pipe_str:gmatch("[^\n]+") do
    -- Only print lines with readable ASCII
    local printable = true
    for i = 1, math.min(#line, 200) do
        local b = string.byte(line, i)
        if b < 32 or b > 126 then printable = false; break end
    end
    if printable and #line > 0 then
        lines[#lines + 1] = line
    end
end

print("pipe string (" .. #lines .. " printable lines):")
for i, line in ipairs(lines) do
    if i <= 50 then
        print("  " .. line:sub(1, 120))
    end
end

print("")
print("=== PROBE 42i COMPLETE ===")
