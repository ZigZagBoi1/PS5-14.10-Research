-- CRASH_CLASS: MODERATE
-- PROBE 1352a: the 532 commands an unprivileged process is actually allowed to run
--
-- Context: sys 532 is Sony's GPU/compute resource manager. Its entry does
--   priv_check(td, 0x2aa)
-- and when that fails only a fixed set of command codes is allowed through:
-- `lea ecx,[r14-0x18]; cmp ecx,7; jb 0xaf02a6` plus the two explicit compares
-- for 0x2f and 0x20 (results/kernel_handlers/asm/sys_532_deep.asm:118-131).
-- Everything else answers 0x800d0203 "command not found" for a game process,
-- which is exactly what the earlier 532 probes saw across the whole 0x00-0x46
-- range (results/phase17_new_vectors/433a_sys532_handle_map_20261022_235907.txt).
--
-- The allowed codes - 0x18..0x1F, 0x20, 0x2F - have never been called with a
-- real input struct: 430a only called 0x18 with a null input pointer
-- (0x800d0202) and 0x2F with no input (rv=0, status dword 0).
--
-- This probe runs every allowed code against a mapped 0x818-byte input page and
-- a sentinel-filled output page at five sizes, and reports the status, the first
-- output qwords and how many output dwords the call changed. A non-zero change
-- count is a copy-out path that no earlier probe exercised.
--
-- -- prior art:
--   results/phase17_new_vectors/430a_sys532_copyout_20261022_234902.txt
--   results/phase17_new_vectors/433a_sys532_handle_map_20261022_235907.txt
--   probes/phase17_new_vectors/430a_sys532_copyout.lua
--   results/kernel_handlers/analysis/sys_532_deep.md:35-48,255-292

print("=== PROBE 1352a: 532 UNPRIVILEGED COMMANDS ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

local sc532 = make_syscall(532)
local sc477 = make_syscall(477)
local getpid = make_syscall(20)
print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function mmap(px)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local out = mmap(0x4000)
local inp = mmap(0x4000)
print(string.format("  out=0x%X in=0x%X", out, inp))
if out == 0 or inp == 0 then print("[!] mmap failed"); return end

local function fill_out()
    for i = 0, 0xFF do safe_wd(out + i * 4, 0xDEADBEEF) end
end
local function fill_in(v)
    for i = 0, 0x3FF do safe_wd(inp + i * 4, v) end
end
local function changed_out()
    local n = 0
    for i = 0, 0xFF do
        if safe_rd(out + i * 4) ~= 0xDEADBEEF then n = n + 1 end
    end
    return n
end

local cmds = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x2F}
local sizes = {0, 0x18, 0x30, 0x40, 0x818}

print("")
print("[A] zeroed input page, 532(cmd, 0, out, in, size, 0)")
for _, cmd in ipairs(cmds) do
    for _, size in ipairs(sizes) do
        if size <= 0x801 or (cmd >= 0x1A and cmd <= 0x1D) then
            fill_in(0)
            fill_out()
            local ok, ret = pcall(function()
                return sc532(uint64(cmd), uint64(0), uint64(out), uint64(inp), uint64(size), uint64(0))
            end)
            local r = ok and sgn(ret) or "PCALL-FAIL"
            local n = changed_out()
            if n > 0 then
                print(string.format("  0x%02X s=0x%03X %s ch=%d %s %s %s %s", cmd, size, tostring(r), n,
                    sgn(safe_rd(out)), sgn(safe_rd(out + 4)), sgn(safe_rd(out + 8)), sgn(safe_rd(out + 12))))
            else
                print(string.format("  0x%02X s=0x%03X %s ch=0", cmd, size, tostring(r)))
            end
        end
    end
end

print("")
print("[B] input page filled with 0x80000000-style size guesses, size 0x818 where legal")
for _, cmd in ipairs(cmds) do
    local size = (cmd >= 0x1A and cmd <= 0x1D) and 0x818 or 0x801
    fill_in(0)
    -- a plausible header: arg-like dwords at +0, +4, +8, +0x10
    safe_wd(inp + 0, 0x18)
    safe_wd(inp + 4, 0x1)
    safe_wd(inp + 8, 0x18)
    safe_wd(inp + 0x10, 0x18)
    fill_out()
    local ok, ret = pcall(function()
        return sc532(uint64(cmd), uint64(0), uint64(out), uint64(inp), uint64(size), uint64(0))
    end)
    local r = ok and sgn(ret) or "PCALL-FAIL"
    print(string.format("  0x%02X s=0x%03X %s ch=%d %s %s", cmd, size, tostring(r), changed_out(),
        sgn(safe_rd(out)), sgn(safe_rd(out + 4))))
end

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1352a COMPLETE ===")
