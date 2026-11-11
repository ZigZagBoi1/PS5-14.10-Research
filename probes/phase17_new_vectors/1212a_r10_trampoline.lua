-- CRASH_CLASS: LOW (phase A) / HIGH (phase C)
-- PROBE 1212a: find a real "mov r10, rcx ; syscall" trampoline in libkernel and
-- check whether the fourth syscall argument can be controlled at all.
--
-- Why: the loader's syscall primitive is fcall(gettimeofday_wrapper + 7, number).
-- gettimeofday(struct timeval*, struct timezone*) has two arguments, so its
-- wrapper is "mov rax, 116 ; syscall ; jc error ; ret" and contains no
-- "mov r10, rcx". The kernel builds syscall argument 4 from r10, not rcx, so
-- through the stock stub argument 4 is whatever r10 happens to hold.
-- Evidence: aio_multi_wait (663) with mode = 0 raised EINVAL 22, which the
-- disassembly can only produce at the num bound (0x3b03a3) or the mode bound
-- "cmp r13d, 3 ; jae" (0x3b041c). The num was 2, which passes the bound
-- (lea eax,[rcx-0x81] = 0xFFFFFF81 > 0xFFFFFF7F -> ja skips the error), so the
-- mode bound fired on a value we never passed.
--
-- In the same image, 0x3b01f0 unpacks the uap array as
--   [rsi] -> rsi, [rsi+8] -> edx, [rsi+0x10] -> rcx, [rsi+0x18] -> r8d, [rsi+0x20] -> r9
-- with rdi = struct thread *, i.e. argument 4 of the syscall is uap[0x18] = r10.

print("=== PROBE 1212a: r10 / argument-4 channel ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function call(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then print(string.format("  [%s] PCALL-FAIL %s", tag, tostring(rv):sub(1,70))) return nil end
    local h,l = hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES()))
    return rv
end

local okb, base = pcall(function() return to_num(libkernel_base) end)
print(string.format("[0] libkernel_base=%s (%s)", okb and string.format("0x%X",base) or "nil", tostring(okb)))
if not okb or base == 0 then print("=== 1212a DONE ===") return end

-- libkernel is a PRX; its .text is inside the first 0x40000 bytes of the mapping
-- (the PS4 code path of this loader reads exactly that much for the same scan).
local text
local okr, res = pcall(function() return memory.read_buffer(base, 0x40000) end)
if not okr then print("read_buffer failed: " .. tostring(res):sub(1,80)) print("=== 1212a DONE ===") return end
text = res
print(string.format("[1] read 0x40000 bytes, len=%d", #text))

local function scan(patstr, label, limit)
    local okp, matches = pcall(function() return find_pattern(text, patstr) end)
    if not okp then print("  " .. label .. ": find_pattern failed " .. tostring(matches):sub(1,50)) return {} end
    if matches == nil then print("  " .. label .. ": nil") return {} end
    local n = 0
    local out = {}
    for i, off in ipairs(matches) do
        n = n + 1
        if n <= (limit or 6) then
            -- find_pattern offsets are 1-based (the PS4 path uses base + off - 1)
            out[n] = base + (off - 1)
            print(string.format("  %s[%d] off=0x%X va=0x%X", label, n, off, out[n]))
        end
    end
    print(string.format("  %s: %d match(es)", label, n))
    return out
end

-- A: full wrapper with a 4th argument: mov rax,imm32 ; mov r10,rcx ; syscall
local wrappers = scan("48 c7 c0 ? ? ? ? 49 89 ca 0f 05", "full", 8)
-- B: bare trampoline: mov r10,rcx ; syscall
local tramps = scan("49 89 ca 0f 05", "tramp", 8)

local target = nil
if #tramps > 0 then target = tramps[1] end
if not target and #wrappers > 0 then target = wrappers[1] + 7 end
print(string.format("[2] chosen trampoline = %s", target and string.format("0x%X", target) or "NONE"))
if not target then print("=== 1212a DONE ===") return end

-- fcall(addr, number) sets rax = number and jumps to addr with rdi..r9 from the
-- Lua arguments. The trampoline itself moves rcx into r10 before syscall.
local function raw(sysno)
    local okf, f = pcall(function() return fcall(target, sysno) end)
    if okf and f then return f end
    return function(a,b,c,d,e,g) return native.fcall_with_rax(target, sysno, a,b,c,d,e,g) end
end

local buf  = memory.alloc(0x100)
local ids  = memory.alloc(16)
local out  = memory.alloc(16)
local tmo  = memory.alloc(8)
wd(ids, 0) wd(ids+4, 0) wd(tmo, 0)

print("[3] argument-4 oracle on syscall 663 (aio_multi_wait)")
print("    disassembly: mode >= 3 must return EINVAL 22 at 0x3b041c;")
print("    mode 0/1/2 must get past it and fail later on the bogus id.")
local modes = {0,1,2,3,4,7,0xFFFFFFFF}
local stock = mk(663)
for _, m in ipairs(modes) do
    local okc, rv = pcall(function() return stock(uint64(ids),uint64(1),uint64(out),uint64(m),uint64(tmo)) end)
    local h,l = hi_lo(rv)
    print(string.format("  stock  mode=%10u -> 0x%08X_%08X err=%s", m, h, l, ES()))
end

local fixed = raw(663)
for _, m in ipairs(modes) do
    local okc, rv = pcall(function() return fixed(ids,1,out,m,tmo) end)
    local h,l = hi_lo(rv)
    print(string.format("  tramp  mode=%10u -> 0x%08X_%08X (raw rax; errno not set on this path)", m, h, l))
end

print("=== 1212a DONE ===")
