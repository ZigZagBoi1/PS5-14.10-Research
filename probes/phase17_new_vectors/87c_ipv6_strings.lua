-- CRASH_CLASS: LOW
-- PROBE 87c: Just dump bytecode strings from IPv6 kernel R/W functions

print("=== PROBE 87c ===")
print("pid=" .. tostring(syscall.getpid()))

local function dump_strings(name, func)
    print("")
    print("--- " .. name .. " ---")
    local ok, bc = pcall(string.dump, func)
    if not ok then print("not dumpable"); return end
    local strs = {}
    local order = {}
    for s in bc:gmatch("[%a_][%w_%.%:]+") do
        if #s > 2 and not strs[s] then
            strs[s] = true
            order[#order+1] = s
        end
    end
    for _, s in ipairs(order) do print("  " .. s) end
end

dump_strings("init", ipv6_kernel_rw.init)
dump_strings("create_overlapped", ipv6_kernel_rw.create_overlapped_ipv6_sockets)
dump_strings("get_fd_data_addr", ipv6_kernel_rw.get_fd_data_addr)
dump_strings("create_pipe_pair", ipv6_kernel_rw.create_pipe_pair)
dump_strings("ipv6_kread", ipv6_kernel_rw.ipv6_kread)
dump_strings("ipv6_kwrite", ipv6_kernel_rw.ipv6_kwrite)
dump_strings("copyin", ipv6_kernel_rw.copyin)
dump_strings("copyout", ipv6_kernel_rw.copyout)
dump_strings("read_buffer", ipv6_kernel_rw.read_buffer)
dump_strings("write_buffer", ipv6_kernel_rw.write_buffer)

-- Also dump initialize_kernel_rw if it exists
if initialize_kernel_rw then
    dump_strings("initialize_kernel_rw", initialize_kernel_rw)
end

-- Check global functions
print("")
print("--- GLOBALS ---")
local globals_to_check = {
    "initialize_kernel_rw", "initialize_kernel_offsets",
    "update_kernel_offsets", "run_with_ps5_syscall_enabled",
    "find_proc_by_pid", "get_current_proc"
}
for _, name in ipairs(globals_to_check) do
    local v = _G[name]
    if v then
        print(name .. "=" .. type(v))
        if type(v) == "function" then
            dump_strings(name, v)
        end
    end
end

print("=== PROBE 87c COMPLETE ===")
