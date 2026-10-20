-- CRASH_CLASS: MODERATE
-- PROBE 125d: Safe native.fcall test
-- 125c confirmed native_cmd_handler/native_invoke/native_cmd are initialized.
-- native.fcall crashed when called with fn_addr from pipe_str.
-- This probe tries: (1) native.read_buffer to confirm it works,
-- (2) find the actual getpid function address in libkernel,
-- (3) call native.fcall with the correct address.

print("=== PROBE 125d: FCALL SAFE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: Confirm native.read_buffer works
print("")
print("--- SECTION A: NATIVE READ ---")
local test_buf = memory.alloc(0x100)
memory.write_dword(test_buf, 0xDEADBEEF)

local ok1, data1 = pcall(native.read_buffer, uint64(test_buf), 4)
print("native.read_buffer: ok=" .. tostring(ok1))
if ok1 and data1 then
    local bytes = ""
    for i = 1, #data1 do bytes = bytes .. string.format("%02X ", data1:byte(i)) end
    print("  data: " .. bytes)
end

-- Section B: Get libkernel base and scan for getpid
print("")
print("--- SECTION B: MODULE BASES ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0x2001), uint64(info))
local lk_text_lo = to_num(memory.read_dword(info + 0x108))
local lk_text_hi = to_num(memory.read_dword(info + 0x10C))
local lk_text_sz = to_num(memory.read_dword(info + 0x110))
print(string.format("lk_text=0x%X%08X sz=0x%X", lk_text_hi, lk_text_lo, lk_text_sz))

-- Get eboot
memory.write_dword(info, 0x160)
make_syscall(593)(uint64(0), uint64(info))
local eb_lo = to_num(memory.read_dword(info + 0x108))
local eb_hi = to_num(memory.read_dword(info + 0x10C))
local eb_sz = to_num(memory.read_dword(info + 0x110))
print(string.format("eboot=0x%X%08X sz=0x%X", eb_hi, eb_lo, eb_sz))

-- Check globals
print("")
print("--- SECTION C: KEY GLOBALS ---")
print("gadgets type=" .. type(gadgets))
if type(gadgets) == "table" then
    local count = 0
    for k, v in pairs(gadgets) do
        count = count + 1
        if count <= 15 then
            print(string.format("  %s = %s", tostring(k), tostring(v)))
        end
    end
    print("total_gadgets=" .. count)
end

print("libkernel_base=" .. tostring(libkernel_base))
print("eboot_base=" .. tostring(eboot_base))

-- Section D: Check the lua.resolve_game for finding functions
print("")
print("--- SECTION D: RESOLVE FUNCTIONS ---")
if lua and lua.resolve_game then
    -- Try to find getpid
    local ok_gp, gp_addr = pcall(lua.resolve_game, "getpid")
    print("resolve_game('getpid'): ok=" .. tostring(ok_gp) .. " ret=" .. tostring(gp_addr))
end

if lua and lua.resolve_libc_clash_game_by_name then
    local ok2, addr2 = pcall(lua.resolve_libc_clash_game_by_name, "getpid")
    print("resolve_libc_clash('getpid'): ok=" .. tostring(ok2) .. " ret=" .. tostring(addr2))
end

-- Section E: Try native.fcall with getpid resolved address
print("")
print("--- SECTION E: FCALL GETPID ---")

-- If we have the address, try it
local getpid_addr = nil

-- Try resolving via syscall module
if syscall and syscall.getpid then
    -- Get the CClosure address of getpid
    local gp_str = tostring(syscall.getpid)
    print("syscall.getpid tostring=" .. gp_str:sub(1, 80))
end

-- Try native.fcall with libkernel getpid stub
-- On FreeBSD/PS5, getpid is a simple syscall wrapper
-- Let's use the known-working approach: call via syscall number
-- native.fcall(fn_addr, rdi, rsi, rdx, rcx, r8, r9)
-- We need a 'syscall; ret' gadget address
print("")
print("--- SECTION F: GADGET SEARCH ---")

-- Scan eboot .text for 0F 05 C3 (syscall; ret) in chunks
local eboot_base_addr = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local syscall_ret = nil

for off = 0, math.min(eb_sz, 0x80000) - 256, 256 do
    local ok, data = pcall(native.read_buffer, eboot_base_addr + off, 256)
    if ok and data then
        for i = 1, #data - 2 do
            if data:byte(i) == 0x0F and data:byte(i+1) == 0x05 and data:byte(i+2) == 0xC3 then
                syscall_ret = eboot_base_addr + off + i - 1
                print(string.format("syscall;ret @ eboot+0x%X", off + i - 1))
                break
            end
        end
        if syscall_ret then break end
    end
end

if syscall_ret then
    -- native.fcall_with_rax(fn_addr, rax, rdi, rsi, rdx, rcx, r8, r9)
    -- For getpid: rax=20, call syscall;ret gadget
    print("")
    print("--- SECTION G: FCALL GETPID VIA GADGET ---")
    local ok_fc, ret_fc = pcall(native.fcall_with_rax, syscall_ret, 20)
    print("fcall_with_rax(syscall_ret, 20): ok=" .. tostring(ok_fc) .. " ret=" .. tostring(ret_fc))
    if ok_fc then
        local rv = to_num(ret_fc)
        print("returned=" .. rv .. " expected_pid=" .. pid)
        if rv == pid then
            print("*** NATIVE FCALL GETPID SUCCESS ***")
        end
    else
        print("error: " .. tostring(ret_fc))
    end
end

print("=== PROBE 125d COMPLETE ===")
