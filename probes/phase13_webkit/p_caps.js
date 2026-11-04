// CRASH_CLASS: LOW
// PROBE 854a entry: capability fingerprint page.
//
// Apple freezes the UA at AppleWebKit/605.1.15, so the UA cannot tell us which
// engine revision the guide ships. Feature presence can: the guide is the only
// WebKit we can execute, and the feature matrix pins the build to a branch
// point. Everything here is pure feature detection, so it cannot kill the
// WebProcess.

location.replace('/corpus/wk-caps.html?t=' + Date.now());
