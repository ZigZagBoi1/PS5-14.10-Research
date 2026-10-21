# WebKit crash corpus — replaying public regression tests on the 14.10 guide browser

## Why

The 14.10 User's Guide runs a WebKit built around Safari 17.0 (September 2023), inside a firmware
shipped in 2026. Nothing in this repository measures what that engine does with the three years of
crash fixes WebKit landed after it was cut. WebKit's own layout tests reproduce those crashes, they
are public, and each one can be replayed on the console as a yes/no question.

The engine's feature surface is the filter that decides which of them are worth replaying: p163
measured the JIT off, WebAssembly absent, `SharedArrayBuffer` absent, and no WebGL, WebAudio,
IndexedDB, ServiceWorker, WebRTC or WebCodecs. A test that needs one of those cannot reach the bug
it guards — it loads, throws, and the runner reports it as a pass. Those are pruned rather than
wasted on console time.

## Pipeline

`tools/webkit_crash_corpus.py` has three stages. Only commit metadata and public test files are
fetched; nothing is executed here.

| stage | what it does | why |
|---|---|---|
| `harvest` | commit search `crash repo:WebKit/WebKit committer-date:>2023-09-20`, keeping commits whose subject matches a crash vocabulary and not a resync/import | finds the fixes that landed after the 17.0 branch point |
| `resolve` | one API call per commit for the files that commit *added* under `LayoutTests` | a test that the fix commit added, not a path mentioned in passing by a WPT resync |
| `fetch` | downloads each test once, 160 KB cap | bounds the corpus |

```bash
python tools/webkit_crash_corpus.py harvest --pages 10
python tools/webkit_crash_corpus.py resolve --limit 400
python tools/webkit_crash_corpus.py fetch --limit 400
python tools/webkit_crash_corpus.py list
```

State lives in `results/webkit/corpus/index.json` (`commits`, `tests`, `skipped`) and the files
themselves are third-party test content kept for local replay; they are not committed.

Current state: 534 crash commits resolved, 124 tests kept, 35 skipped for features the console does
not have.

## Runner protocol

`probes/phase13_webkit/p166-corpus-runner.js` loads each case in its own iframe and reports it
with beacons, so the log alone says how far the run got:

| marker | meaning |
|---|---|
| `V166-<session>-BEFORE-<i>` | case `<i>` is about to load |
| `V166-<session>-OK-<i>-<file>` | the case loaded and the iframe was removed |
| `V166-<session>-ERR-<i>` | the case threw or errored |
| `V166-<session>-STALL-<i>` | the case did not load in time |
| `V166-<session>-GAP-<i>` | the frame was removed without reporting: the death happened during teardown |
| `V166-<session>-CORPUS-DONE-<i>` | the batch finished |

`?start=N&count=M&timeout=ms` selects the batch. The server keeps the resume point per run in
`results/webkit/state.json`, keyed by the session tag the runner stamps on every beacon, so two
loads of the runner in one log cannot be confused for each other. A case that was opened and never
closed is the one the WebProcess died on: the server marks it skipped once the run has gone quiet
and the next guide load resumes at the following case, so a run that dies at case *N* continues at
*N+1* after the guide is reopened.

## Console results

| run | cases | outcome |
|---|---|---|
| 2026-10-20 08:24 | 0–24 | 25/25 OK |
| 2026-10-20 08:28 | 25–29 | 5/5 OK |
| 2026-10-20 08:28+ | 30 | died: `OK-30` then silence, six times, in isolation and in batch |

Case 30 is `fast/scrolling/mac/event-dispatcher-timer-close-crash.html` (2026-08-23, "Heap-use-after-free
of RemoteLayerTreeEventDispatcher's RunLoop::Timer on the scrolling thread"). It was the only case
that killed the browser in every attempt.

The cause is not the upstream use-after-free. The console's browser kills the WebProcess on a popup
request: a refused `window.open` dies a few tens of milliseconds after the refusal, and a
`<a target="_blank">` click that really opens a window dies too, with the popup document already
served: see [Finding 5](WEBKIT_FINDINGS.md#finding-5-a-popup-request-kills-the-consoles-webprocess).
The upstream test needs a real popup window to arm the display-link observer, so it never reaches
the code it exercises on this console either way.

The runner therefore stubs `window.open` for the two cases that use it. The stub is injected by the
server when `results/webkit/corpus/stub.json` holds `{"open": true}` and announces itself with a
`V166-POPUP-STUB` beacon, so a case that ran with a stubbed popup is never counted as an
unmodified pass.

## The JSC corpus (p172)

The 124 layout tests above are a mix of layout and engine tests. `JSTests` is the denser set to
replay: its `stress/` and `regress/` cases are written for a bare JS engine, they need no layout,
and a large fraction of them exist because a crash was fixed. `tools/webkit_crash_corpus.py` has a
`jsc-` stage that does the same job for them:

```bash
python tools/webkit_crash_corpus.py jsc-harvest --pages 4
python tools/webkit_crash_corpus.py jsc-resolve --limit 400
python tools/webkit_crash_corpus.py jsc-fetch --limit 600
python tools/webkit_crash_corpus.py jsc-build
```

`jsc-harvest` walks the commits that touched `JSTests/stress` and `JSTests/regress` after
2023-09-20 (397 from four pages of 100 per tree), `jsc-resolve` keeps the `.js` files those commits
*added* under the same unsupported-feature filter (`564` kept, `5` skipped), `jsc-fetch` downloads
them once into `results/webkit/corpus/jsc_src/`, and `jsc-build` writes one self-contained page per
case under `results/webkit/corpus/` (`jsc-<n>-<subject>.html`) plus the index `jsc.json`. 518 pages
are built; 46 sources are dropped because they call `$vm`, the `jsc` shell's private inspector,
which has no equivalent in the browser. 398 of the 518 contain `shouldBe` calls and so report a real
answer; the rest only execute their code, which is still what the crash test needs. The pages and
sources are third-party test content and stay uncommitted, and `tools/test_webkit_crash_corpus.py`
pins the builder's behaviour.

Each page carries a shell shim so a test written for `jsc` runs unmodified: `shouldBe`,
`shouldNotBe`, `shouldThrow`, `shouldBeTrue`, `shouldBeFalse`, `shouldBeUndefined`, `shouldBeNull`,
`shouldBeEqualToString`, `shouldNotThrow`, `noInline`, `print`, `debug`, `evalScript`,
`referenceError`, `testLoopCount = 200` and an `onerror` handler that returns true. The body runs
inside `try`/`catch` and reports `ok`/`fail` counts; a `ReferenceError` for a shell-only helper is
caught and shown in a `<pre>`, so the page still finishes and still beacons.

`probes/phase13_webkit/p172-jsc-corpus-runner.js` is the same iframe runner as p166 with a different
list and marker prefix:

| marker | meaning |
|---|---|
| `V172-<session>-BEFORE-<i>` | case `<i>` is about to load |
| `V172-<session>-OK-<i>-<file>` | the case loaded and the iframe was removed |
| `V172-<session>-GAP-<i>` | the frame went away without reporting: the death happened in teardown |
| `V172-<session>-CORPUS-DONE-<i>` | the batch finished |

`?start=N&count=M` defaults to 40 cases per load: long enough that one guide load is worth the
manual step, short enough that a single death does not throw away much. The resume point is the
server's, so a death at case *N* continues at *N+1* on the next load.

Verified locally before any console time: Chromium loaded the runner and beacons arrived for six
cases (`BEFORE`, `OK`, `GAP` each) while the cursor advanced `0 -> 6`; the case pages themselves
reported `ok`/`fail` counts and, where a shell helper is missing, their catch block instead of
dying.

## Limits

- One console reload per crash. The guide browser has no inspector, so a death is characterised by
  markers and timing only.
- The corpus is a screen, not a proof. A case that reports OK has not been shown to be safe; it has
  been shown not to crash this build under this harness.
- Features the console lacks are pruned, so the corpus says nothing about bugs that need them.
