// Runs the six super/proxy scope-leak shapes and beacons one SCOPE- line each.
// The page is docs/RELAPSE_14_10.md's matrix; any row that returns a scope-like
// object instead of a plain receiver would be a live primitive on this engine.
location.replace('/corpus/leakscope2.html?v=2');
