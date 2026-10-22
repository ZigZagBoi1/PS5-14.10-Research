# Private sys 622 leak-claim audit — 2026-10-21

This is an offline audit of retained 13.60 REA assembly/pseudocode and saved 14.10 captures. It establishes **no 14.10 kernel pointer or kernel R/W**.

## Fixed 25-byte copyout (the purported V6 leak)

The 13.60 function at RVA `0x7e0b70` calls `func_0x0060ec10(handle, 0x8001, &object, 0x3ffffff)` and proceeds only when that lookup succeeds. It then loads `source = *(object + 0x18)` and calls `copyout(source, *output_pointer, 0x19)` at RVAs `0x7e0c13`–`0x7e0c1e`. The fixed 25-byte length is real in the saved assembly (`results/kernel_handlers/asm/sys_622_deep.asm`), and the pseudocode identifies the same dataflow (`results/kernel_handlers/decompiled/sys_622_deep.c`, `sub_007e0b70`, retained Evidence `ev_ac7ac272d7ada7763761b5a7c4d493dbc810be703db04828f00509715d82e5ea`).

The claim that this **leaks uninitialized kernel heap bytes** is unproved. Neither the source allocation size nor its initialization state is established by that function. A short text name does not imply the backing allocation ends at its NUL byte. The handler also requires a live object of type `0x8001`; no saved 14.10 run demonstrates that lookup or a successful copyout. `results/54e_device_fuzz_20261018_091259.txt` shows `-1` for its tested sys 622 calls, and there is no `90a` result capture.

Before a 14.10 leak test, identify a reachable type-`0x8001` object and verify the copyout's command selector and output layout. A 25-byte nonzero output would still need independent byte-provenance and cross-boot validation to count as a kernel pointer.

## Callback storage (the purported V7 write)

The 13.60 `sub_007e22e0` function stores its single argument in the first empty slot of **eight fixed global qwords** at `0x03a34ff0` through `0x03a35028`; if all are occupied it returns `-1`. The caller does not choose a destination address in this function. The `TODO.md`/handler-note phrase “write-what-where” is therefore too strong. Whether a user process can reach the function through sys 622 and whether the stored value is later invoked are separate, unproved questions. The corresponding REA Evidence is `ev_016f490b7cd74797fd10e0503aaf641db5fe710b99137015d85831e98dbfee28`.

## Priority decision

Do not treat the sys 622 V6/V7 notes as a verified 14.10 exploit lead. The completed AIO object lifecycle has stronger 14.10 reachability evidence. Keep the bounded duplicate-delete experiment as the next prepared memory-safety discriminator; its result would still need independent read/write validation.
