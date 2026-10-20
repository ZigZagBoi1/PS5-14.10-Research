# Where a 14.10 kernel image can come from

No verified 14.10 kernel image exists in this repository. The captures labelled
13.60 are fixed address ranges of unknown completeness, so a handler audit or a
CVE diff against FreeBSD `r230171` cannot be done from them. This note records
what was tried to close that gap on 2026-10-20 and what each route actually
yields.

## The update client is plain HTTP, and it names its own paths

The console's system-update check resolves `pc.ps5.update.playstation.net`
through the configured DNS. Pointing that name at a local listener is enough to
read the request line, because the client speaks unencrypted HTTP on port 80.

Captured with the console's DNS set to the research host
(`results/webkit/server_20261020_172532.log`, 2026-10-20T16:32:54Z):

```
GET /update/ps5/official/tJMRE80IbXnE9YuG0jzTXgKEjIMoabr6/list/uk/updatelist.xml
    ?DeviceId=275b8fe74c6abb9354f0e9ed827722430020736a8e0f7a0ff9a9b5efbe334021
    &sdk_version=14.10.00.03-00.00.00.0.1[&force=new]
```

- The path token for 14.10 today is `tJMRE80IbXnE9YuG0jzTXgKEjIMoabr6`. The token
  used by older public tooling and PUP lists,
  `tJMRE80IbXnE9YuG0jzTXgJE1Zq8Mn6u`, now returns `404`.
- `DeviceId` is a 64-hex-character console identifier; `sdk_version` identifies
  the running system software. Both are stable across retries.
- The client retries the pair (`…&force=new` and the plain form) about every
  40 ms while the check is failing.

With the name redirected, the console reports that the update check failed. That
is expected: the request reached the research host, not Sony.

## The captured request does not replay off-console

Every shape tried from a PC against Sony returns `404 Not Found` with a
10-byte body from `AkamaiNetStorage`:

| request | result |
| --- | --- |
| the captured `updatelist.xml` path, verbatim, over HTTP | 404 |
| the same path over HTTPS | 404 |
| `/update/ps5/official/<token>/ps5UPDATE.PUP`, HTTP and HTTPS | 404 |

So the token is necessary but not sufficient: the edge scopes the response by
something a PC does not present (region edge selection, device registration, or
a header the console adds). Capturing the path therefore does not produce a
downloadable PUP.

## Even a PUP would not give a kernel image

The update file is encrypted per system software version. `ps5-pup-decrypt`
works by asking the console to decrypt a PUP placed at the USB root, and its
documentation limits it to the same version or the same `.XX` line — it needs
code execution on the console to run at all, which is the thing being sought.
`ps5-pup-unpacker` only unpacks a PUP that is already decrypted.

## What is left

A decrypted 13.60 or 14.xx kernel dump from a console that already has kernel
access. None is public: searches on 2026-10-20 returned scene news and the
firmware-tracking thread (`gbatemp.net/threads/ps5-exploit-guide.613891/`, which
lists 14.10 as the current system software) but no image. Until one exists,
kernel work on this firmware is limited to behaviour that can be observed
through syscalls, which is what the probe series records.
