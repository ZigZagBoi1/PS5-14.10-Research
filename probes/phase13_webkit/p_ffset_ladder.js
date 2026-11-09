// Finding 12 / issue #143: escalating reclaim ladder for the FontFaceSet UAF.
// Step 0 is the bare trigger (remove the victim style, no reclaim). Each later
// step allocates that many fresh FontFace objects inside the same getter, which
// is the window between the free and WebKit's next dereference of the victim.
location.replace('/corpus/ffset-ladder.html?t=' + Date.now());
