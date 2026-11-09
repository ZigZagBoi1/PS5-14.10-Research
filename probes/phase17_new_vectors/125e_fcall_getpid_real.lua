-- CRASH_CLASS: MODERATE
-- PROBE 125e: Call getpid via native.fcall with real address
-- 125d found: syscall.getpid at 0x808404b57 (libkernel), gadgets table has 32 entries,
-- native.read_buffer works, native_cmd_handler is initialized.
-- native.fcall(fn_addr, rdi, rsi, rdx, rcx, r8, r9) calls fn_addr with those regs.
-- getpid() takes no args and returns PID.

print("=== PROBE 125e: FCALL GETPID REAL ===")

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

-- Get getpid address from syscall module
local gp_str = tostring(syscall.getpid)
local gp_addr_str = gp_str:match("address @ (0x[0-9a-fA-F]+)")
print("getpid_addr=" .. tostring(gp_addr_str))

-- Get key globals
print("libkernel_base=" .. tostring(libkernel_base))
print("eboot_base=" .. tostring(eboot_base))
print("native_cmd_handler=" .. tostring(native_cmd_handler))

-- Section A: Try calling getpid directly
print("")
print("--- SECTION A: FCALL GETPID ---")
if gp_addr_str then
    local gp_addr = uint64(gp_addr_str)
    print("calling native.fcall(" .. tostring(gp_addr) .. ")")
    local ok1, ret1 = pcall(native.fcall, gp_addr)
    print("fcall: ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
    if ok1 then
        local rv = to_num(ret1)
        print("returned=" .. rv .. " expected=" .. pid)
        if rv == pid then
            print("*** GETPID SUCCESS — NATIVE FCALL WORKS ***")
        end
    else
        print("error: " .. tostring(ret1))
    end
end

-- Section B: Try with gadgets['ret'] as a safe nop test
print("")
print("--- SECTION B: FCALL RET GADGET ---")
if gadgets and gadgets['ret'] then
    local ret_addr = uint64(gadgets['ret'])
    print("ret gadget=" .. tostring(ret_addr))
    local ok2, ret2 = pcall(native.fcall, ret_addr)
    print("fcall(ret): ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
end

-- Section C: Try fcall_with_rax for syscall
-- If we have a syscall;ret gadget we can do arbitrary syscalls
print("")
print("--- SECTION C: GADGET LIST ---")
if gadgets then
    for k, v in pairs(gadgets) do
        print(string.format("  [%s] = 0x%x", k, v))
    end
end

-- Section D: Try socket(AF_INET6, SOCK_DGRAM, 0) via native.fcall
-- socket is typically at libkernel_base + some offset
-- Let's find it from the syscall module
print("")
print("--- SECTION D: SYSCALL MODULE ---")
local sc_keys = {}
for k, v in pairs(syscall) do
    sc_keys[#sc_keys+1] = k
end
table.sort(sc_keys)
for _, k in ipairs(sc_keys) do
    local v = syscall[k]
    if type(v) == "function" then
        local s = tostring(v)
        local addr = s:match("address @ (0x[0-9a-fA-F]+)")
        if addr then
            print(string.format("  syscall.%s @ %s", k, addr))
        end
    end
end

print("=== PROBE 125e COMPLETE ===")
