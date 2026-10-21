# 14.10 PUP device reachability gate

The 13.60 extraction decrypted both outer 14.10 PUP entries, but the complete `kernel.bin` remains opaque. Repeating that outer decryption on 13.60 would return the same bytes. The remaining PUP hypothesis is whether the **14.10** console's security service can process the protected inner component from the current game-process context.

`probes/phase20_pup_device/110c_pup_device_access.lua` checks only the first prerequisite: `open("/dev/pup_update0", O_RDWR)` from the 14.10 Lua loader, with `/dev/null` as a syscall control, followed by close. It neither supplies a PUP nor issues an ioctl or updater call. A successful open would justify reviewing the exact inner-decryption API and privilege boundaries. A failed open blocks this route from this process, without distinguishing absence from access denial.

Status: prepared offline; **not run**. The 14.10 loader connected but returned no data to two benign pings at 09:00–09:01 EDT, so no new probe was sent. A clean ping is required before this check. This gate cannot itself disclose a kernel pointer or prove that the protected `kernel.bin` can be decrypted.
