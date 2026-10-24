-- CRASH_CLASS: LOW
-- PROBE 514a: diagnostic — print between each step to find corruption source
--
-- 510a/512a/513a all produce 280 bytes of binary with no readable text.
-- 509a's header prints fine BEFORE thread ops corrupt the stream.
-- Hypothesis: some memory operation in the ELF probes corrupts TCP output
-- even without threading. This probe prints after EACH step to find which.

print("=== PROBE 514a: ELF diagnostic ===")
print("STEP_0: alive")

------------------------------------------------------------------ helpers
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
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

-- STEP 1: getpid
local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("STEP_1: pid=" .. pid)

-- STEP 2: dynlib_get_info for eboot (handle 0)
local sc593 = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
print("STEP_2: text=" .. string.format("0x%X%08X", text_hi or 0, text_lo or 0))

-- STEP 3: read text_addr as uint64
local text_addr = safe_rq(info + 0x108)
local data_addr = safe_rq(info + 0x118)
print("STEP_3: text_addr=" .. fmt_hex(text_addr) .. " data=" .. fmt_hex(data_addr))

-- STEP 4: small alloc for sys 674
local STRIDE = 72
local MAX_REC = 20
local vm_buf = memory.alloc(STRIDE * MAX_REC)
local vm_countp = memory.alloc(16)
safe_wq(vm_countp, uint64(0))
print("STEP_4: alloc done, buf=" .. fmt_hex(uint64(to_num(vm_buf))))

-- STEP 5: sys 674 call
local sc674 = make_syscall(674)
local ok674, ret674 = pcall(function()
    return sc674(uint64(to_num(vm_buf)), uint64(STRIDE), uint64(MAX_REC),
                 uint64(to_num(vm_countp)), uint64(0x40000000))
end)
local vm_ret = ok674 and to_num(ret674) or -999
local vm_count = safe_rd(vm_countp)
print("STEP_5: 674 ret=" .. vm_ret .. " count=" .. (vm_count or "nil"))

-- STEP 6: read first 3 VM records (if any)
if vm_count and vm_count > 0 then
    local show = math.min(vm_count, 3)
    for i = 0, show - 1 do
        local rec = vm_buf + i * STRIDE
        local s = safe_rq(rec)
        local e = safe_rq(rec + 8)
        local p = safe_rd(rec + 0x18)
        print(string.format("STEP_6_%d: %s-%s p=0x%X", i, fmt_hex(s), fmt_hex(e), p or 0))
    end
else
    print("STEP_6: no VM records")
end

-- STEP 7: read first dword at text_addr (should be readable — eboot is RX)
local d0 = safe_rd(text_addr)
print("STEP_7: text[0]=" .. string.format("0x%08X", d0 or 0))

-- STEP 8: scan backward for ELF magic (just 5 pages)
local PAGE = 0x4000
local found_elf = "none"
for step = 0, 4 do
    local addr = text_addr - uint64(step * PAGE)
    local magic = safe_rd(addr)
    if not magic then
        print(string.format("STEP_8: text-0x%X = UNREADABLE", step * PAGE))
        break
    end
    print(string.format("STEP_8: text-0x%X = 0x%08X", step * PAGE, magic))
    if magic == 0x464C457F then
        found_elf = fmt_hex(addr) .. " (ELF)"
        break
    elseif magic == 0x1D3D154F then
        found_elf = fmt_hex(addr) .. " (OELF)"
        break
    end
end
print("STEP_9: elf_scan=" .. found_elf)

-- STEP 10: sys 649 member query for eboot
local sc649 = make_syscall(649)
local out649 = memory.alloc(0x100)
for j = 0, 0xFC, 4 do safe_wd(out649 + j, 0) end
local ok649, ret649 = pcall(function()
    return sc649(uint64(0), uint64(1), uint64(to_num(out649)))
end)
local r649 = ok649 and to_num(ret649) or -999
local v0 = safe_rq(out649)
print("STEP_10: 649(0,1) ret=" .. r649 .. " val=" .. fmt_hex(v0))

-- STEP 11: check +0x128 field from dynlib_get_info
local f128 = safe_rq(info + 0x128)
if f128 then
    local f128_d = safe_rd(f128)
    print("STEP_11: +0x128=" .. fmt_hex(f128) .. " [0]=" .. string.format("0x%08X", f128_d or 0))
else
    print("STEP_11: +0x128=nil")
end

-- STEP 12: final pid check
local pid2 = to_num(sc20())
print("STEP_12: pid2=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 514a COMPLETE ===")
