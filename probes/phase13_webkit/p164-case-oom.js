// CRASH_CLASS: HIGH
// p164 case: oom. Allocates until the WebProcess is killed by the system.
// Used only to prove the oracle reports death as "no SURVIVED beacon".
// Expect the console toast "not enough free system memory".
(function () {
  var keep = [];
  for (;;) {
    keep.push(new Array(1 << 20).fill(1));
  }
})();
