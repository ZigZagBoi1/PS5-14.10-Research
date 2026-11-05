# SCM_RIGHTS hidden-FD impact assessment on PS5 14.10

**Status:** device-confirmed descriptor installation bug; no standalone LPE or
kernel memory primitive demonstrated.

This note separates three questions that previous records sometimes combined:

1. Does `SCM_RIGHTS` descriptor passing work? **Yes.**
2. Can a truncated receive install descriptors without reporting them? **Yes.**
3. Does that behavior provide kernel memory corruption or privilege escalation?
   **No, not by itself.** It could only amplify a separate bug in a privileged
   receiver.

The finding remains useful, but its next gate is the receiving service's API and
descriptor handling. Repeating self-process leak or exhaustion tests cannot
answer that question.

Tracking record: [issue #123](https://github.com/ZigZagBoi1/PS5-14.10-Research/issues/123).

## Confirmed device behavior

The clean `151e` run records three distinct hidden descriptors at fd 27, 28 and
29. Their shared-memory markers were `0xAAAA0001`, `0xAAAA0002` and
`0xAAAA0003`; a write of `0xBEEF1234` through a hidden descriptor was visible
after reopening the named object normally. The same run's close test reported
the predicted descriptor dead after the final reference was closed. This is a
real installed descriptor with normal lifetime, not a dangling `struct file`.

Direct evidence:

- [probe 151e](../probes/phase22_cve_hunt/151e_fd_leak_exploit.lua)
- [clean 151e capture](../results/phase22_cve_hunt/151e_fd_leak_exploit_20261022_061701.txt)
- [151d capture](../results/phase22_cve_hunt/151d_fd_leak_verify_20261022_060807.txt)

The `151d` run moved the next descriptor from 34 to 46 after five dropped
messages, but the run later emitted binary/crash output and had already consumed
substantial process resources. Use it as corroboration of fd-table growth, not
as a precise five-message allocation count. The clean `151e` marker and
round-trip observations are the stronger lifecycle evidence.

## This is not CVE-2019-5607

CVE-2019-5607 / FreeBSD-SA-19:17 concerns references acquired while
internalizing control messages and not released when a later internalization
step fails. The 14.10 behavior here occurs on the **receive truncation** path:
descriptors are successfully installed, but the generated ancillary message is
dropped before userland learns their numbers.

An exact-artifact audit used `kernel_1410.elf`, size 47,655,976 bytes, SHA-256
`cc1572fcc91f27b7093a3a689b651c0cffeecbdd85dbf9a406a520fa8b945f0f`.
The artifact is not committed to this repository, so the offsets below are a
reproducible static record rather than an in-repository binary fixture:

- the AF_UNIX send/internalize path at RVA `0x99bbb0` contains both the
  SA-19:17-style error cleanup and a second defensive control-chain cleanup;
- errors converge at `0x99c1f7`, scan prior `SOL_SOCKET/SCM_RIGHTS` messages at
  `0x99c220..0x99c24c`, and call `unp_freerights` at RVA `0x99aab0`;
- the receive externalizer at RVA `0x999e70` frees rights when its output-control
  pointer is null (`0x999f21..0x999f46`);
- descriptor installation is therefore reached only when ancillary output was
  requested and externalization succeeded.

That closes the historical refcount-wrap/UAF interpretation. The hidden-FD
finding is a different, narrower defect. See the corrected
[CVE-2019-5607 audit](CVE-2019-5607-BINARY-VERIFICATION.md).

## Exact trigger boundary

The distinction between receive APIs is decisive:

```text
read()/recv()             no ancillary output requested
                          rights are discarded/freed

recvmsg(), adequate cmsg  rights installed and fd numbers returned

recvmsg(), short cmsg     rights installed; ancillary result truncated;
                          hidden descriptors can remain
```

This matches the upstream design: `unp_externalize()` frees rights when the
caller supplies no control-output pointer. Modern FreeBSD additionally marks an
externalized control mbuf as `MT_EXTCONTROL`, allowing generic truncation
cleanup to close descriptors installed before copyout. The observed 14.10
behavior is consistent with an incomplete backport of that state transition.
The historical truncation report is
[FreeBSD kern/131876](https://groups.google.com/g/fa.freebsd.bugs/c/tKrwedwc5NQ),
and the current externalizer can be compared in the
[FreeBSD source tree](https://cgit.freebsd.org/src/tree/sys/kern/uipc_usrreq.c).

Consequently, sending `SCM_RIGHTS` to a service that performs ordinary
`read()`/`recv()` does not exercise the bug. A cross-process path first needs
evidence that the receiver calls `recvmsg()` with a non-null, undersized control
buffer.

## Reachable service boundary

Three `/system_tmp` stream endpoints accept connections from the game jail:

| Endpoint | Measured behavior | Missing evidence |
|---|---|---|
| `GnmCompositorRestricted` | One framed reply, then close | Receiver binary and whether it uses `read` or `recvmsg` |
| `AgcCompositorSppSocket` | Compositor-family endpoint | Same |
| `VrTracker2DomainSock` | Reads input and closes without a reply | Same |

The transport results are documented in
[SYSTEM_SOCKETS_14_10.md](SYSTEM_SOCKETS_14_10.md). Connection reachability is
not evidence that any endpoint accepts ancillary descriptors. Existing service
probes used ordinary writes and reads. The 8 KiB compositor test already gives
an unprivileged denial of service and must not be repeated as an SCM_RIGHTS
experiment.

## LPE and lateral-movement path matrix

| Candidate path | Additional requirement | Current verdict |
|---|---|---|
| Refcount wrap or file UAF | Missing `fdrop`/cleanup | **Closed.** Exact static audit finds the cleanup; `151e` observes normal lifetime. |
| Direct fd type confusion | Kernel treats the received object as another `fileops` type | **Closed by design.** The installed descriptor retains its real `struct file` and operations. |
| Steal a privileged receiver fd | Reverse the direction of `SCM_RIGHTS` | **Not provided.** Rights move sender to receiver, not receiver to sender. |
| Upgrade an attacker fd | Receiver credentials alter the open-file description | **Not provided.** Passing a descriptor does not add access rights. |
| Receiver fd-table exhaustion | Privileged receiver uses short-control `recvmsg` repeatedly | **Possible DoS only** until a second error-handling defect is shown. |
| High-fd array indexing | Receiver uses `clients[fd]` without a bound | **Plausible second bug; no evidence.** Requires receiver disassembly. |
| `FD_SET` overflow | Receiver passes an fd at or above `FD_SETSIZE` to an unchecked macro | **Plausible second bug; no evidence.** Requires receiver disassembly. |
| Unchecked `EMFILE` | `accept`, `open` or `socket` failure leaves stale state | **Plausible second bug; no evidence.** A crash alone would remain DoS. |
| Credential fail-open | Service expects `LOCAL_CREDS`, ancillary truncation removes it, and absence is trusted | **Conceptually direct; no service evidence.** Missing credentials must be rejected for the path to be safe. |
| Stale cmsg parsing | Receiver ignores `MSG_CTRUNC` or returned `msg_controllen` | **Possible application bug; untested.** Could misuse a stale integer as a descriptor. |
| Descriptor-number collision | Hidden installs overwrite an existing receiver fd | **Closed.** Allocation selects free slots; it does not replace live entries. |
| Fork/exec inheritance | Receiver later executes another image without closing the hidden fd | **Possible persistence only.** Still carries only the attacker's original capability. |
| Privileged close callback | Closing the supplied file triggers a second fileops/driver bug | **Theoretical second kernel bug.** Not specific to this truncation defect. |
| Kernel pointer or KASLR leak | Descriptor number encodes an address | **Closed.** An fd is a table index, not a pointer. |

The most credible escalation families are therefore application-level:

1. high descriptor numbers reaching unsafe indexing or `FD_SET`;
2. unchecked `EMFILE` paths;
3. missing or truncated peer credentials being treated as trusted;
4. stale ancillary parsing after `MSG_CTRUNC`.

Each requires a separate receiver defect. Hidden descriptors alone do not
provide read, write, execution, or elevated authority.

## Required gates before an LPE claim

All of the following must be demonstrated:

1. **Privilege boundary:** identify the endpoint's peer PID/UID/GID and show it
   is more privileged than the game process.
2. **Ancillary receive:** prove the peer uses `recvmsg()` with a non-null control
   buffer.
3. **Remote retention:** show one transferred descriptor remains installed
   after the service handles the request.
4. **Deterministic consumer:** identify how that hidden descriptor or the
   shifted next-fd value reaches service logic.
5. **Security effect:** show memory corruption, an authorization bypass, or a
   privileged operation, not only `EMFILE`, a black screen or service restart.
6. **Attacker observation/control:** demonstrate a result visible to the
   unprivileged process.

The repository currently establishes none of gates 2 through 6 for a system
service.

## One bounded discriminator

Before any exhaustion experiment, use a single-descriptor retention witness:

1. Create socketpair `A/B` in the unprivileged process.
2. Connect once to the candidate service and query peer credentials if the
   platform exposes `LOCAL_PEERCRED`.
3. Send one valid, already-measured service request with `B` attached as one
   `SCM_RIGHTS` entry.
4. Close the local `B` reference.
5. After the service finishes or closes the request connection, poll `A` for
   EOF/HUP.

Interpretation:

- EOF/HUP means no remote reference remains. It is a negative retention result,
  although it cannot distinguish `read()` from a correct `recvmsg()` receiver
  that closed the descriptor.
- No EOF/HUP after the protocol completes is positive evidence that the remote
  process retained `B`. It still does not prove the descriptor was hidden until
  the receiver's ancillary handling is known.

Safety limits are part of the experiment: one descriptor, one request, one
connection per endpoint, no fd flood, no 8 KiB compositor write, and no claim
from a crash or timeout. No implementation is included in this assessment.

## Artifacts that settle the lane statically

The preferred next evidence is the exact decrypted 14.10 implementation for:

- the owner of `GnmCompositorRestricted`;
- the owner of `AgcCompositorSppSocket`;
- the owner of `VrTracker2DomainSock`;
- the exact 14.10 `libSceComposite.sprx`, if it owns the client/server framing.

Audit imports and callsites for `recvmsg`, `read`, `LOCAL_CREDS`, `MSG_CTRUNC`,
`select`/`FD_SET`, fd-indexed arrays, `accept`/`open` error handling, `fork`/`exec`
and `closefrom`.

If all three receivers use ordinary `read`, the cross-process hidden-FD lane is
closed. If a receiver uses a short-control `recvmsg`, audit its fd consumers
before designing any further device test.

## Relation to the kernel-base oracle

The fault-context oracle in PR #191 establishes a per-boot kernel mapping/base
oracle. It is explicitly not a kernel read primitive. Combining that base with
hidden descriptor numbers does not create kernel memory access: the missing
component remains a separate kernel or privileged-service memory primitive.

## Claim discipline

Do not describe this finding as:

- CVE-2019-5607 surviving on 14.10;
- a file UAF or dangling descriptor;
- arbitrary fd injection into a known receiver slot;
- a sandbox escape, LPE, KASLR leak or kernel R/W;
- evidence that the compositor uses `recvmsg`.

The supported label is: **device-confirmed SCM_RIGHTS receive-truncation
descriptor leak, with conditional privileged-service amplification paths not
yet demonstrated.**
