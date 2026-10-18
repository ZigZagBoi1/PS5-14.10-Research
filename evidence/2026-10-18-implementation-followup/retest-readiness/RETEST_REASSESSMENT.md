# Focused retest reassessment and live error-metadata check

2026-10-18. Source pin 7e25a1174b5a3086b7e90d860d85f8ab7bad7a70. Read the actual prepared 53a/53b/53c sources, current RETEST_PLAN_53.md, saved results and recovered loader-source/runtime evidence. Original files unchanged.

## Actions completed

1. Produced COVERAGE_627_676.json with all 50 selectors and exact references into the explicitly reviewed completed 51b log. Twelve have recorded returns: 628, 632, 633, 634, 637, 640, 643, 646, 647, 648, 652, 676. Remaining rows mean no return in that particular completed log, not never attempted anywhere. Successful ABI coverage is not established by a return. No numerical sweep was run.
2. Reassessed the three prepared sources against the new loader evidence. The old review label 'no defects found' is not adopted as a readiness finding.
3. Ran one bounded Lua metadata check at 07:07:20 UTC (03:07:20 America/New_York), examining only types of specifically named errno-related globals/table entries. No accessor, syscall callable, native dispatcher or memory API was invoked. End marker and peer EOF received. Exact script/frame/sender/session/raw response preserved in errno-metadata/.

## New live observation

The current runtime exposes no raw global errno/get_errno/strerror/perror; no __error, __errno_location or errno entry in libc_addrofs; and no __error/errno/get_errno entry in syscall. libc_addrofs.strerror is a table. These exact named lookups do not establish absence of every possible error interface. strerror formats a supplied error number; its presence alone does not retrieve current errno. No unknown address, guessed accessor or string formatter was invoked.

The recovered native-return path does not by itself establish a reliable captured thread-local error value. A Lua pcall success says that Lua-visible execution returned; it does not establish kernel success. A message-header rtm_errno field is distinct from the calling thread's errno.

## Prepared-source findings

| Source | Exact locations | Readiness finding / required correction |
|---|---|---|
| 53a_aio_retest.lua | :47–56 | Inherited AIO selector/name mapping and mostly null arguments. This tests wrapper return/survival, not a validated Sony AIO request. Need attributable ABI/prototype/context before interpreting operational results. |
| 53a_aio_retest.lua | :14–22,78 | Reduces return to signed32 numeric output; does not preserve raw high/low halves or independently retrieve errno. Preserve full wrapper return and Lua error separately in any replacement. |
| 53a_aio_retest.lua | :7 | Advises continuing after an unreturned index, although missing output does not establish failure cause or restored state. Do not treat lack of tail as a reason to automatically advance through more unknown calls. |
| 53b_afroute_retest.lua | :4 | Still attributes the old 108-byte record to an echo. This contradicts the corrected audit: attribution is unresolved. |
| 53b_afroute_retest.lua | :75–94,191 | Assumes routing header field positions and tries 120/92/152-byte header variants. No independently established Sony layout is supplied. Header-size variation is not a clean schema-validated retest. |
| 53b_afroute_retest.lua | :119–123,140–147,200 | Parses header errno, not thread errno; treats any positive write as delivery progress; prints at most 160 response bytes. Clean request attribution would need exact/full send receipt, full response bytes, validated schema/length and correlation fields. None implies disclosure by itself. |
| 53c_kldstat_retest.lua | :115–151 | Varies candidate selectors and assumed structure versions/file IDs, includes null-pointer call, and parses unverified layout. This is candidate probing rather than a supported typed module query. |
| 53c_kldstat_retest.lua | :159 onward | Adds kernel-symbol queries and pointer scanning. This extends beyond clarifying an incomplete module-query log. Separate those questions rather than run the bundle as one clean retest. |
| All three | make_syscall and signed32 helpers | Recovered loader source provides a coherent selector/marshaling model, but does not authenticate a Sony prototype or expose reliable errno capture. New loaded Lua chunks establish structure more strongly than the former CClosure inference; native machine-code/build identity remains unresolved. |

53d is not proposed: current pipe.__call reports Lua and serializes as Lua bytecode. The historical presumed C-function-field mutation premise does not identify a valid target. No object mutation was performed.

## Disposition

**Do not run 53a–53c unchanged as 'clean retests with proper error capture'.** This is an implementation/evidence-quality finding, not a conclusion that AIO is blocked, AF_ROUTE patched, module queries unavailable or the console secure. The reopened questions remain valid. No kernel retest was executed in this pass.

The missing inputs are specific: an attributable platform ABI/layout for the selected operation and a verified way to record the native error result without replacing missing evidence with guessed numbers/addresses. The native error accessor is not exposed under the named entries checked in this session; a matching existing library symbol/source interface may resolve it. No broad search, kernel dump, memory scan or new exploit is substituted.

Historical acquisition authenticity and 14.10 sysent correspondence remain unchanged. Current runtime metadata and source receipts do not authenticate historical dumps or a firmware/build. All new output is separate; original source/evidence remains unchanged and repository clean. No push performed.
