// Finding 12 follow-up: does the rebuilt face set land in the stale vector?
// The victim rule is removed inside the getter; the recalc clears and rebuilds
// every CSS-connected face, so the slot the victim vacated is reused by one of
// the filler families. If the resolved array reports a filler family where the
// victim was, the dangling reference is pointing at an object we chose.
location.replace('/corpus/ffset-swap.html?t=' + Date.now());
