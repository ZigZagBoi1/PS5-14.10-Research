# Named-object 557/558: direct kernel-pointer leak audit

Offline audit of the recorded 13.60 kernel text, not a 14.10 runtime finding. Input `docs/dumps_13.60/kernel_text.bin`, SHA-256 `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1`.

The sysent trampolines at RVAs `0x265da8` and `0x265db0` jump to `0xac7240` (`namedobj_create`, 557) and `0xac73c0` (`namedobj_delete`, 558). The existing [557 handler analysis](../results/kernel_handlers/analysis/sys_557.md) shows a 24-byte record containing a kernel pointer to the copied name and an eight-byte **caller-supplied** value. Success publishes an integer handle, not a pointer. Direct disassembly of 558 at `0xac73c0..0xac7460` shows lookup by `(id, subtype | 0x1000)`, removal from the current process namespace, release of the name and record, and status return `0` or `3`. It has no user copyout or pointer return in this bounded body.

The 14.10 saved `47a` returns from 557 are handle-shaped and cannot be counted as kernel addresses. The 111a section-B live capture created zero handles with its argument shape, then stopped; it did not test deletion of valid named records. The unrun 88a/96a handle-confusion probes might test object lifetime, but a deletion success or crash alone would not disclose a kernel pointer. A credible next hypothesis needs a specific consumer of the forced-`0x1000` named-record subtype that treats the caller's eight-byte value as a privileged pointer. None is identified here.

Conclusion: 557/558 are **not direct kernel-pointer disclosure interfaces** in the recorded 13.60 bodies. Their 14.10 implementation is unverified. Do not treat the familiar `0x4205` handle value as a KASLR leak.
