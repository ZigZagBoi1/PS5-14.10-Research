-- CRASH_CLASS: LOW
-- PROBE 129b: Test native.fcall_with_rax and enumerate APIs
-- Lightweight probe to confirm what primitives are available

print("=== PROBE 129b: NATIVE API TEST ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: Check native table
print("--- SECTION A: NATIVE TABLE ---")
if native then
    for k, v in pairs(native) do
        print("  native." .. tostring(k) .. " = " .. type(v) .. " " .. tostring(v))
    end
else
    print("  native is nil")
end

-- Section B: Check fcall
print("")
print("--- SECTION B: FCALL ---")
if fcall then
    print("fcall type=" .. type(fcall))
    print("fcall(gadgets.ret) = " .. tostring(pcall(function() return fcall(gadgets.ret) end)))
else
    print("fcall is nil")
end

-- Section C: Check gadgets table
print("")
print("--- SECTION C: GADGETS ---")
for k, v in pairs(gadgets) do
    if type(v) == "table" then
        local parts = {}
        for k2, v2 in pairs(v) do
            parts[#parts+1] = tostring(k2) .. "=" .. tostring(v2)
        end
        print("  gadgets[\"" .. tostring(k) .. "\"] = {" .. table.concat(parts, ", ") .. "}")
    else
        print("  gadgets[\"" .. tostring(k) .. "\"] = " .. tostring(v))
    end
end

-- Section D: Check ropchain
print("")
print("--- SECTION D: ROPCHAIN ---")
if ropchain then
    print("ropchain type=" .. type(ropchain))
    for k, v in pairs(ropchain) do
        print("  ropchain." .. tostring(k) .. " = " .. type(v))
    end
else
    print("ropchain is nil")
end

-- Section E: Check libc_addrofs
print("")
print("--- SECTION E: LIBC_ADDROFS ---")
if libc_addrofs then
    for k, v in pairs(libc_addrofs) do
        print("  " .. tostring(k) .. " = " .. tostring(v))
    end
else
    print("libc_addrofs is nil")
end

-- Section F: Check eboot_addrofs
print("")
print("--- SECTION F: EBOOT_ADDROFS ---")
if eboot_addrofs then
    for k, v in pairs(eboot_addrofs) do
        print("  " .. tostring(k) .. " = " .. tostring(v))
    end
else
    print("eboot_addrofs is nil")
end

-- Section G: Test native.fcall_with_rax if available
print("")
print("--- SECTION G: FCALL_WITH_RAX TEST ---")
if native and native.fcall_with_rax then
    local stub = syscall.pipe.fn_addr
    print("stub=" .. tostring(stub))

    -- getpid
    local ok, gpid = pcall(native.fcall_with_rax, stub, 20)
    print("getpid: ok=" .. tostring(ok) .. " val=" .. tostring(gpid))

    -- socket(AF_INET6=28, SOCK_DGRAM=2, UDP=17)
    local ok2, sock = pcall(native.fcall_with_rax, stub, 97, 28, 2, 17)
    print("socket: ok=" .. tostring(ok2) .. " val=" .. tostring(sock))

    if ok2 and to_num(sock) >= 0 then
        -- close
        local ok3, cr = pcall(native.fcall_with_rax, stub, 6, to_num(sock))
        print("close: ok=" .. tostring(ok3) .. " val=" .. tostring(cr))
    end
elseif native and native.fcall then
    print("native.fcall available (no rax control)")
    local stub = syscall.pipe.fn_addr
    -- Try getpid via fcall
    local ok, val = pcall(native.fcall, stub)
    print("fcall(stub): ok=" .. tostring(ok) .. " val=" .. tostring(val))
else
    print("No native call interface")
end

-- Section H: Test syscall.pipe details
print("")
print("--- SECTION H: SYSCALL.PIPE ---")
local pipe_str = tostring(syscall.pipe)
print("pipe_str=" .. pipe_str)
print("fn_addr=" .. tostring(syscall.pipe.fn_addr))
print("syscall_no=" .. tostring(syscall.pipe.syscall_no))

-- Check syscall.close
if syscall.close then
    print("close.fn_addr=" .. tostring(syscall.close.fn_addr))
    print("close.syscall_no=" .. tostring(syscall.close.syscall_no))
end

-- Section I: Test create_pipe and basic ropchain
print("")
print("--- SECTION I: ROPCHAIN TEST ---")
local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

local chain = ropchain:new()
chain:push_syscall_with_ret(make_sc(20))  -- getpid
chain:restore_through_longjmp()
chain:execute_through_coroutine()
local rv = memory.read_qword(chain:get_last_retval_addr())
print("ropchain getpid=" .. tostring(rv) .. " (expected " .. pid .. ")")

-- Section J: Test Thrd_create
print("")
print("--- SECTION J: THRD_CREATE ---")
local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)
local thr_buf = memory.alloc(8)
memory.write_qword(thr_buf, 0)
local ok, ret = pcall(thrd_create_fn, thr_buf, gadgets.ret, uint64(0))
print("Thrd_create(ret_gadget, 0): ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok and to_num(ret) == 0 then
    sleep(0.1, 's')
    local tid = memory.read_qword(thr_buf)
    print("tid=" .. tostring(tid))
    pcall(thrd_join_fn, tid, uint64(0))
    print("joined")
end

print("canary: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 129b COMPLETE ===")
