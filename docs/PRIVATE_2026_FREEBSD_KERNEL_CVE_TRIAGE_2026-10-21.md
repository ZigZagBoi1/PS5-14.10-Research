# FreeBSD 2026 kernel CVEs: 14.10 applicability gate

Status: offline source and local-capture review, 2026-10-21. No new console test for this note. Keep on `staging`.

## CVE-2026-7270 (`execve`)

The [FreeBSD advisory](https://lists.freebsd.org/archives/freebsd-security/2026-April/000448.html) describes an operator-precedence bug that overflows one `execve` argument buffer into adjacent argument buffers. It calls this a possible local privilege escalation on supported FreeBSD releases. The public exploit described by the [discoverer](https://github.com/califio/publications/blob/main/MADBugs/freebsd-CVE-2026-7270/blog.md) targets a privileged `sshd` execution path. Neither source proves that Sony's 14.10 fork has the vulnerable expression, exposes a comparable privileged execution path from this game process, or discloses a kernel pointer. `docs/CVE-2026-7270-ASSESSMENT.md` already records these PS5 gates. Do not treat this CVE as an immediate kernel R/W primitive.

## CVE-2026-45251 (`poll`/`select` file-object UAF)

The [FreeBSD advisory](https://lists.freebsd.org/archives/freebsd-security/2026-May/000453.html) describes a blocked `poll`/`select` thread that can retain a freed object after another thread closes its descriptor; only some descriptor types lacked cleanup. The advisory names process descriptors as an example, but does not claim ordinary sockets or kqueues are vulnerable. The retained 13.60 `docs/dumps_13.60/sysent_index.json` maps **all four slots 518–521** to the same `narg=0` handler at RVA `0x265760`, the common unsupported-syscall stub; its generated CSV labels for 519/520 are not sufficient to override those raw slot entries. The local 14.10 `pdfork(518)` capture (`results/phase17_new_vectors/120a_pdfork_capsicum_20261019_185541.txt`) stops at its first call and is followed by a refused connection. That is no evidence of a usable process descriptor, and a loader stop does not verify this UAF. Do not repeat `120a` as a process-descriptor baseline. A future race test needs a safely obtained eligible descriptor and a documented affected object type.

## Implication for the pointer goal

These two public CVEs are real FreeBSD issues, but current 14.10 evidence proves neither reaches the vulnerable code nor yields a kernel address. The 96a AIO duplicate-delete capture also supports normal handle removal. Keep the address-disclosure search separate from speculative race crashes: first obtain raw candidate bytes with object provenance, then repeat within one boot and compare across boots.
