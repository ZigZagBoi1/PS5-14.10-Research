var wins = workspace.windowList();
var target = null;
for (var i = 0; i < wins.length; i++) {
    var w = wins[i];
    try { if (w.pid == CHIAKIPID && w.width > 100) { target = w; } } catch(e) {}
}
if (target) {
    try { target.keepAbove = true; } catch(e) {}
    try { target.requestActivate(); } catch(e) {}
    workspace.activeWindow = target;
    workspace.raiseWindow(target);
}
