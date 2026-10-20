-- CRASH_CLASS: LOW
-- PROBE 83d: Dump native.fcall bytecode to understand its interface
-- 83c crashed calling native.fcall(). Dump the Lua source to understand args.
-- Also dump initialize_kernel_rw, initialize_kernel_offsets, ipv6_kernel_rw.init

print("=== PROBE 83d: FCALL BYTECODE ===")

-- Helper to dump bytecode as hex
local function dump_bc(name, fn)
    local ok, bc = pcall(string.dump, fn)
    if not ok then
        print(name .. ": not lua (" .. tostring(bc) .. ")")
        return
    end
    print(name .. " len=" .. #bc)
    -- Print first 200 bytes as hex for analysis
    local hex = {}
    for i = 1, math.min(#bc, 200) do
        hex[#hex+1] = string.format("%02X", bc:byte(i))
    end
    print("HEX:" .. table.concat(hex))
    -- Also extract string constants from bytecode
    local strs = {}
    local i = 1
    while i <= #bc do
        -- Look for printable ASCII sequences >=4 chars
        local s = ""
        while i <= #bc and bc:byte(i) >= 32 and bc:byte(i) <= 126 do
            s = s .. bc:sub(i, i)
            i = i + 1
        end
        if #s >= 4 then strs[#strs+1] = s end
        i = i + 1
    end
    if #strs > 0 then
        print("STRINGS:")
        for _, s in ipairs(strs) do
            print("  " .. s)
        end
    end
end

dump_bc("native.fcall", native.fcall)
print("")
dump_bc("native.fcall_with_rax", native.fcall_with_rax)
print("")
dump_bc("native.read_buffer", native.read_buffer)
print("")
dump_bc("native.write_buffer", native.write_buffer)
print("")
dump_bc("native.setup_pivot_handler", native.setup_pivot_handler)
print("")
dump_bc("native.setup_cmd_handler", native.setup_cmd_handler)
print("")
dump_bc("native.create_cmd_handler", native.create_cmd_handler)
print("")
dump_bc("native.gen_fcall_chain", native.gen_fcall_chain)
print("")
dump_bc("initialize_kernel_rw", initialize_kernel_rw)
print("")
dump_bc("initialize_kernel_offsets", initialize_kernel_offsets)
print("")
dump_bc("ipv6_kernel_rw.init", ipv6_kernel_rw.init)
print("")
dump_bc("ipv6_kernel_rw.create_overlapped_ipv6_sockets", ipv6_kernel_rw.create_overlapped_ipv6_sockets)
print("")
dump_bc("find_proc_by_pid", find_proc_by_pid)
print("")
dump_bc("run_with_ps5_syscall_enabled", run_with_ps5_syscall_enabled)
print("")

-- Also dump thread.init and thread.run
if thread then
    dump_bc("thread.init", thread.init)
    print("")
    dump_bc("thread.run", thread.run)
end

-- Check if there's a "jailbreak" or "exploit" function
print("")
print("--- EXPLOIT FUNCTIONS ---")
local exploit_names = {"jailbreak", "exploit", "run_exploit", "do_exploit",
    "privilege_escalation", "escalate", "root", "get_root",
    "patch_kernel", "disable_security", "enable_debug",
    "debug_settings", "enable_debug_settings", "set_debug_flag",
    "kexploit", "kernel_exploit"}
for _, name in ipairs(exploit_names) do
    if _G[name] then
        print("FOUND: " .. name .. " type=" .. type(_G[name]))
    end
end

-- Check check_jailbroken
if check_jailbroken then
    dump_bc("check_jailbroken", check_jailbroken)
end

print("=== PROBE 83d COMPLETE ===")
