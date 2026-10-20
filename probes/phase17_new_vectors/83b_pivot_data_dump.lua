-- CRASH_CLASS: LOW
-- PROBE 83b: Dump pivot/fcall/gadget data WITHOUT calling setup functions
-- 83a crashed on setup_pivot_handler(). This probe only reads state.

print("=== PROBE 83b: PIVOT DATA DUMP ===")

-- Dump pivot_handler_rop fully
print("--- PIVOT_HANDLER_ROP ---")
if native and native.pivot_handler_rop then
    local p = native.pivot_handler_rop
    for k, v in pairs(p) do
        local t = type(v)
        if t == "table" then
            local n = 0
            local sub = {}
            for k2, v2 in pairs(v) do
                n = n + 1
                if n <= 10 then sub[#sub+1] = tostring(k2) .. "=" .. tostring(v2) end
            end
            print("PHR:" .. tostring(k) .. " keys=" .. n .. " " .. table.concat(sub, ", "))
        else
            print("PHR:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    -- Deeper: fcall_stub inside pivot
    if p.fcall_stub then
        print("")
        print("--- FCALL_STUB ---")
        for k, v in pairs(p.fcall_stub) do
            print("FS:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

-- Dump fcall details
print("")
print("--- FCALL ---")
if fcall then
    if fcall.chain then
        print("chain:")
        for k, v in pairs(fcall.chain) do
            print("  C:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    if fcall.arg_addr then
        print("arg_addr:")
        for k, v in pairs(fcall.arg_addr) do
            print("  A:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    if fcall.__index then
        print("__index:")
        for k, v in pairs(fcall.__index) do
            print("  I:" .. tostring(k) .. " " .. type(v))
        end
    end
end

-- Game gadget table
print("")
print("--- HAMIDASHI GADGETS ---")
if gadget_table and gadget_table.hamidashi_creative then
    local gt = gadget_table.hamidashi_creative
    local count = 0
    for k, v in pairs(gt) do
        count = count + 1
        if count <= 50 then
            print("HG:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("total=" .. count)
end

-- Current gadget table ("c" might be the currently active one)
print("")
print("--- GADGET_TABLE.c ---")
if gadget_table and gadget_table.c then
    local gc = gadget_table.c
    local count = 0
    for k, v in pairs(gc) do
        count = count + 1
        if count <= 50 then
            print("GC:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("total=" .. count)
end

-- "f" table
print("")
print("--- GADGET_TABLE.f ---")
if gadget_table and gadget_table.f then
    local gf = gadget_table.f
    local count = 0
    for k, v in pairs(gf) do
        count = count + 1
        if count <= 50 then
            print("GF:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    print("total=" .. count)
end

-- Dump ps5_kernel_offset_list with table contents
print("")
print("--- PS5_KERNEL_OFFSET_LIST ---")
if ps5_kernel_offset_list then
    local idx = 0
    for k, v in pairs(ps5_kernel_offset_list) do
        idx = idx + 1
        if idx <= 15 then
            print("ENTRY " .. idx .. ":")
            if type(k) == "table" then
                for k2, v2 in pairs(k) do
                    print("  K." .. tostring(k2) .. "=" .. tostring(v2))
                end
            else
                print("  KEY=" .. tostring(k))
            end
            if type(v) == "table" then
                for k2, v2 in pairs(v) do
                    print("  V." .. tostring(k2) .. "=" .. tostring(v2))
                end
            else
                print("  VAL=" .. tostring(v))
            end
        end
    end
end

-- Try native.fcall (the function calling primitive)
print("")
print("--- NATIVE.FCALL ---")
if native and native.fcall then
    local ok, src = pcall(string.dump, native.fcall)
    print("fcall lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end

-- Try native.read_buffer / write_buffer
print("")
print("--- NATIVE RW BUFFERS ---")
if native.read_buffer then
    local ok, src = pcall(string.dump, native.read_buffer)
    print("native.read_buffer lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end
if native.write_buffer then
    local ok, src = pcall(string.dump, native.write_buffer)
    print("native.write_buffer lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end

-- Check thread table
print("")
print("--- THREAD ---")
if thread then
    print("initialized=" .. tostring(thread.initialized))
    if thread.fpu_ctrl_value then
        for k, v in pairs(thread.fpu_ctrl_value) do
            print("fpu:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    if thread.mxcsr_value then
        for k, v in pairs(thread.mxcsr_value) do
            print("mxcsr:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
    if thread.thr_handle_addr then
        for k, v in pairs(thread.thr_handle_addr) do
            print("thr_handle:" .. tostring(k) .. "=" .. tostring(v))
        end
    end
end

-- ipv6_kernel_rw.data
print("")
print("--- IPV6_KERNEL_RW.DATA ---")
if ipv6_kernel_rw and ipv6_kernel_rw.data then
    for k, v in pairs(ipv6_kernel_rw.data) do
        print("I6D:" .. tostring(k) .. "=" .. tostring(v))
    end
    print("data_empty=" .. tostring(next(ipv6_kernel_rw.data) == nil))
end

-- Check run_with_ps5_syscall_enabled
print("")
if run_with_ps5_syscall_enabled then
    local ok, src = pcall(string.dump, run_with_ps5_syscall_enabled)
    print("run_with_ps5_syscall_enabled lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end
if find_proc_by_pid then
    local ok, src = pcall(string.dump, find_proc_by_pid)
    print("find_proc_by_pid lua=" .. tostring(ok) .. " len=" .. (ok and #src or 0))
end

print("=== PROBE 83b COMPLETE ===")
