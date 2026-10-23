# The public Relapse browser stage on 14.10

[Relapse](https://github.com/ntfargo/Relapse-Exploit) is the public PS5 chain for
firmware 7.00 through 13.60. Its README states the shape:

> Browser stage uses JSC info leaks and a structured clone object pool mismatch to
> corrupt a typedarray. The kernel stage combines a address leak with an
> `aio_multi_wait` uaf race to establish kernel r/w.

Two halves. This note measures the first half against 14.10's own
JavaScriptCore, which is the engine the User's Guide runs.

## Prior work in this repository

The scope-leak gate was already tested here: `probes/phase13_webkit/p160-relapse-test.js`
and commit `73fc070` ("Live test: Relapse WebKit stage-1 scope-leak dead on 14.10",
PR #32) reported that the `super`/`Proxy` entry primitive no longer fires, and the
sibling repository reproduced it independently (54/54 attempts, scope receiver
`undefined`). What this note adds is the full public stage run end to end, an
offline comparison against a 2023 JavaScriptCore build, a six-shape matrix that
separates "the `super` path is broken" from "one behaviour changed", and the
kernel-half measurement.

## How it was run

`src/webkit.js` from the public repository (20,965 bytes) was served to the guide
as a classic script — the file has no imports, and only `export function
establishPrimitive` has to lose its `export`. The page called
`establishPrimitive(cb)` and beaconed every event:

```html
<script>
function mark(t){ (new Image()).src = '/beacon/RELAPSE-' + encodeURIComponent(String(t)) + '?t=' + Date.now(); }
</script>
<script src="/corpus/relapse-webkit.js"></script>
<script>
establishPrimitive(function (tag, detail) { mark('EV:' + tag + '|' + detail); });
</script>
```

Two harness details cost a run each and are worth recording:

- the probe server serves `.js` as `text/html`, so the stage has to be loaded as a
  classic `<script src>`; a `type="module"` import fails with
  `'text/html' is not a valid JavaScript MIME type`;
- `results/webkit/corpus/stub.json` must hold `{"open": false}`. When it holds
  `true` the server prepends a fake-`document` shim to every corpus page, and the
  page then runs against a fabricated DOM and never reaches its first marker.

## What happened

The stage runs. It groomed, attempted, and retried, 27 times in the first
observation window, ending every attempt at the same gate:

```
RELAPSE-EV:Attempt|11
RELAPSE-EV:Retry|setup failed: Error: Scope not leaked. attempt 11
RELAPSE-EV:Attempt|12
RELAPSE-EV:Retry|setup failed: Error: Scope not leaked. attempt 12
```

Nothing crashed, nothing hung, the guide stayed responsive throughout. The engine
accepted every object shape the stage built and refused one specific behaviour.

## The gate

`src/webkit.js` line 212, verbatim:

```js
function leakScopeObject() {
  class Leaker {
    leak() {
      return super.foo;
    }
  }
  Leaker.prototype.__proto__ = new Proxy({}, {
    get: function (target, property, receiver) {
      return receiver;
    },
  });
  const leak = Leaker.prototype.leak;
  return (function () {
    return leak();
  })();
}
```

and the caller at line 227:

```js
leakedScope = leakScopeObject();
if (leakedScope === undefined || leakedScope === null)
  throw new Error("Scope not leaked.");
```

`super.foo` reaches the proxy's `get`, which returns the receiver. On the engine
the chain was written for, that receiver is not an ordinary object: the call
returns an internal scope object, which the next stage turns into an unbacked
`Symbol` string for the address leak.

## The measurement

| Shape | JavaScriptCore 7617 (2023, offline Release `jsc`) | Guide on 14.10 |
|---|---|---|
| Relapse's exact `leakScopeObject()` | `object:[object Undefined]`, keys `leak` | `undefined` |
| `super.foo`, `get` returns a real property (control) | `41` | `41` |
| `get`-termed accessor, `get` returns the receiver | `object:[object Object]` | `object:[object Object]` |
| `static` method, `super.foo` | `function` | `function` |
| prototype-chain `get`, returns the receiver | `object:[object Object]` | `object:[object Object]` |

The control matters: `super` through a proxy still resolves and still returns
what the trap returns. What changed is the one behaviour Relapse needs — the
receiver of a `super` property access being the scope object.

Offline, `~/webkit-7617` is a 2023 checkout of the same engine family; running
`leakScopeObject()` verbatim under its Release `jsc` returns an object whose own
properties include `leak`. On 14.10 the identical function returns `undefined`.

## What this means

- The public browser half of Relapse is **not present** in 14.10's
  JavaScriptCore: the stage retries forever at `Scope not leaked.`, which is the
  same gate p160 hit. The offline comparison places the change: a 2023 build
  returns the scope object for the identical function, 14.10 returns `undefined`,
  and the surrounding `super`/`Proxy` behaviour is unchanged.
- The public kernel half is a different matter, and this is the part that had no
  14.10 result before. `aio_multi_wait` (syscall 663) exists and calls correctly:
  submit with 669, wait with 663, and a completed request returns
  `states = 0x3` while observing mode returns `0x10003` (probes 460a-469a). The
  handler's own ABI is five slots `(ids, count 1..128, states, mode, timeout)`
  and it allocates 0x38-byte waiter records, which is the object the public
  race operates on.
- What is missing is the half that turns a browser bug into an address leak and
  a corrupted typed array. Without it the kernel race cannot be aimed, because
  nothing in the process can read a kernel pointer.

## Reproducing

1. fetch `src/webkit.js` from the Relapse repository into
   `results/webkit/corpus/relapse-webkit.js` and delete `export ` before
   `function establishPrimitive`;
2. write `results/webkit/corpus/relapse.html` as shown above;
3. set `results/webkit/corpus/stub.json` to `{"open": false}`;
4. serve with `tools/webkit_server.py --port 443 --tls --cert ug_cert.pem
   --key ug_key.pem --dns --dns-domains manuals.playstation.net --default
   p_relapse_test.js --corpus results/webkit/corpus` and open the User's Guide;
5. read `results/webkit/server_<stamp>.log` for `RELAPSE-EV:` lines.

The scope matrix used for the table above is `p_leakscope.js` plus a page that
runs the six shapes and beacons one line per shape.
