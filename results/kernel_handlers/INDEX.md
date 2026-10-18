# PS5 Firmware 13.60 Kernel Handler Analysis Index

All 145 Sony syscall handlers (sys 532-676) fully disassembled, decompiled, and analyzed.
Generated via REA 6.7.0 / Ghidra 12.1.4 automated pipeline.

## Coverage
- ASM files: 145
- Decompiled C: 145
- Analysis: 145

## Handler Summary

| Syscall | Description | Type | Files |
|---------|-------------|------|-------|
| 532_deep | # Deep Analysis: sys 532 (Syscall 0x214) - First Sony Syscall | deep | asm, c, md |
| 533 | create a page-aligned memory object and publish a descriptor | batch | asm, c, md |
| 534 | create a restricted alias descriptor for a type-0xe memory object | batch | asm, c, md |
| 535 | enumerate a target process’s loader/module handles | batch | asm, c, md |
| 536 | query one loader/module record in a target process | batch | asm, c, md |
| 537 | unimplemented syscall path with signal-related side effect | batch | asm, c, md |
| 538 | create an event-flag-style object (type 0x110) | batch | asm, c, md |
| 539 | delete/destroy a type-0x110 event object | batch | asm, c, md |
| 540 | open a named shared type-0x110 event object | batch | asm, c, md |
| 541 | close a type-0x110 event-object handle | batch | asm, c, md |
| 542 | wait on an event pattern with optional in/out timeout | batch | asm, c, md |
| 543 | poll an event pattern without blocking | batch | asm, c, md |
| 544 | set event bits and wake matching waiters | batch | asm, c, md |
| 545 | retain event bits with a caller-supplied AND mask | batch | asm, c, md |
| 546 | cancel/reset an event pattern and optionally return waiter count | batch | asm, c, md |
| 547 | query current-process virtual-memory region and protection | batch | asm, c, md |
| 548 | batch virtual-memory operations with deferred protection updates | batch | asm, c, md |
| 549 | create a counting-semaphore-style object (type 0x120) | batch | asm, c, md |
| 550 | delete/destroy a type-0x120 semaphore | batch | asm, c, md |
| 551 | open a named shared type-0x120 semaphore | batch | asm, c, md |
| 552 | close a type-0x120 semaphore handle | batch | asm, c, md |
| 553 | wait for a positive semaphore count with optional timeout | batch | asm, c, md |
| 554 | try to consume semaphore count without waiting | batch | asm, c, md |
| 555 | post a positive count to a semaphore | batch | asm, c, md |
| 556 | cancel/reset a semaphore and optionally return affected waiter count | batch | asm, c, md |
| 557 | create a generic named record with caller-selected subtype and opaque value | batch | asm, c, md |
| 558_deep | # deep_558.bin — code analysis | deep | asm, c, md |
| 559 | select/query a process allocation-context index with privilege check | batch | asm, c, md |
| 560 | initialize or compare a global 32-bit value | batch | asm, c, md |
| 561 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 562 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 563 | Enable per-thread performance monitoring | batch | asm, c, md |
| 564 | Disable per-thread performance monitoring | batch | asm, c, md |
| 565 | Configure one of six performance event selectors | batch | asm, c, md |
| 566 | Write saved performance-counter values | batch | asm, c, md |
| 567 | Read one performance counter for a current-process thread | batch | asm, c, md |
| 568 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 569 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 570 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 571 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 572 | Query a virtual-memory region with compatibility filtering | batch | asm, c, md |
| 573 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 574 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 575 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 576 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 577 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 578 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 579 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 580 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 581 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 582 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 583 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 584 | Unimplemented syscall: signal and ENOSYS path | batch | asm, c, md |
| 585 | Return whether the process root differs from a global root | batch | asm, c, md |
| 586 | Query or select a process budget/container class | batch | asm, c, md |
| 587 | Return full or filtered process credential metadata | batch | asm, c, md |
| 588 | # Handler 588 Analysis | batch | asm, c, md |
| 589 | # Handler 589 Analysis | batch | asm, c, md |
| 590 | # Handler 590 Analysis | batch | asm, c, md |
| 591 | # Handler 591 Analysis | batch | asm, c, md |
| 592 | # Handler 592 Analysis | batch | asm, c, md |
| 593 | # Handler 593 Analysis | batch | asm, c, md |
| 594 | # Handler 594 Analysis | batch | asm, c, md |
| 595 | # Handler 595 Analysis | batch | asm, c, md |
| 596 | # Handler 596 Analysis | batch | asm, c, md |
| 597 | # Handler 597 Analysis | batch | asm, c, md |
| 598 | # Handler 598 Analysis | batch | asm, c, md |
| 599 | # Handler 599 Analysis | batch | asm, c, md |
| 600 | # Handler 600 Analysis | batch | asm, c, md |
| 601_deep | # Deep RE: sys 601 — Process Control Multiplexer (16KB, narg=3) | deep | asm, c, md |
| 602 | # Handler 602 Analysis | batch | asm, c, md |
| 603 | # Handler 603 Analysis | batch | asm, c, md |
| 604 | # Handler 604 Analysis | batch | asm, c, md |
| 605 | # Handler 605 Analysis | batch | asm, c, md |
| 606 | # Handler 606 Analysis | batch | asm, c, md |
| 607 | # Handler 607 Analysis | batch | asm, c, md |
| 608 | # Handler 608 Analysis | batch | asm, c, md |
| 609 | # Handler 609 Analysis | batch | asm, c, md |
| 610 | # Handler 610 Analysis | batch | asm, c, md |
| 611 | # Handler 611 Analysis | batch | asm, c, md |
| 612 | # Handler 612 Analysis | batch | asm, c, md |
| 613 | # Handler 613 Analysis | batch | asm, c, md |
| 614 | # Handler 614 Analysis | batch | asm, c, md |
| 615 | # Handler 615 Analysis | batch | asm, c, md |
| 616 | static REA review | batch | asm, c, md |
| 617 | static REA review | batch | asm, c, md |
| 618 | static REA review | batch | asm, c, md |
| 619 | static REA review | batch | asm, c, md |
| 620 | static REA review | batch | asm, c, md |
| 621 | static REA review | batch | asm, c, md |
| 622_deep | # Deep Analysis: sys 622 (Device Control Multiplexer) | deep | asm, c, md |
| 623 | static REA review | batch | asm, c, md |
| 624 | static REA review | batch | asm, c, md |
| 625 | static REA review | batch | asm, c, md |
| 626 | static REA review | batch | asm, c, md |
| 627 | static REA review | batch | asm, c, md |
| 628 | static REA-oriented analysis | batch | asm, c, md |
| 629 | static REA-oriented analysis | batch | asm, c, md |
| 630_deep | # Deep RE: sys 630 — Jail/Mount Companion Handler (12KB, narg=1) | deep | asm, c, md |
| 631 | static REA-oriented analysis | batch | asm, c, md |
| 632 | static REA-oriented analysis | batch | asm, c, md |
| 633 | static REA-oriented analysis | batch | asm, c, md |
| 634 | static REA-oriented analysis | batch | asm, c, md |
| 635 | static REA-oriented analysis | batch | asm, c, md |
| 636 | static REA-oriented analysis | batch | asm, c, md |
| 637 | static REA-oriented analysis | batch | asm, c, md |
| 638 | reviewed static analysis | batch | asm, c, md |
| 639 | reviewed static analysis | batch | asm, c, md |
| 640 | reviewed static analysis | batch | asm, c, md |
| 641 | reviewed static analysis | batch | asm, c, md |
| 642 | reviewed static analysis | batch | asm, c, md |
| 643_deep | # deep_643.bin — REA code analysis | deep | asm, c, md |
| 644 | reviewed static analysis | batch | asm, c, md |
| 645 | reviewed static analysis | batch | asm, c, md |
| 646 | Credential-gated fixed-size output | batch | asm, c, md |
| 647 | Credential-gated executable SDK compiled-version query (ORBI metadata) | batch | asm, c, md |
| 648_deep | # Deep Analysis: sys 648 (Syscall 0x288) - GPU/Display Context Manager | deep | asm, c, md |
| 649 | sys_dynlib_get_obj_member: module-record selector query | batch | asm, c, md |
| 650 | Shared nosys implementation with signal delivery side effect | batch | asm, c, md |
| 651 | Alias of shared nosys implementation with signal delivery side effect | batch | asm, c, md |
| 652 | sys_process_terminate: privileged process termination and status collection | batch | asm, c, md |
| 653_deep | # Deep RE: sys 653 — GPU/Display Page Table Attribute Modifier (8KB, narg=1) | deep | asm, c, md |
| 654 | Validated 64 KiB VM object range operation | batch | asm, c, md |
| 655 | Validated VM object range reset companion | batch | asm, c, md |
| 656 | sys_dynlib_get_info_for_libdbg: gated module information query | batch | asm, c, md |
| 657 | batched memory commands | batch | asm, c, md |
| 658 | descriptor-backed synchronization path | batch | asm, c, md |
| 659 | dynamic module handle enumeration | batch | asm, c, md |
| 660 | dynamic module information version2 | batch | asm, c, md |
| 661 | disabled AIO entry routed to common unsupported-syscall handling | batch | asm, c, md |
| 662 | AIO batch delete | batch | asm, c, md |
| 663 | AIO batch wait | batch | asm, c, md |
| 664 | AIO batch poll | batch | asm, c, md |
| 665 | disabled AIO entry routed to common unsupported-syscall handling | batch | asm, c, md |
| 666 | Batch handle cancellation and completion propagation | batch | asm, c, md |
| 667 | Enumerate process/thread records with a count-only mode | batch | asm, c, md |
| 668 | Unsupported-operation forwarding wrapper | batch | asm, c, md |
| 669_deep | # deep_669.bin — code analysis | deep | asm, c, md |
| 670_deep | # deep_670.bin — code analysis | deep | asm, c, md |
| 671 | Query two nonnegative values for a selected resource class | batch | asm, c, md |
| 672 | Dynamic-linker library-list query for debugger support | batch | asm, c, md |
| 673 | Operate on two aligned ranges within one VM mapping | batch | asm, c, md |
| 674 | Enumerate virtual-memory descriptions (virtual_query_all) | batch | asm, c, md |
| 675 | Reset three global state fields | batch | asm, c, md |
| 676 | Request CPU-mode update through internal mode 2 | batch | asm, c, md |
