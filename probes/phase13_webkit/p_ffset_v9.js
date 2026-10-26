// Finding 12 / issue #143: entry page for the verbatim v9 trigger.
// Reads its arms from /corpus/ffset-config.json (cache-busted) so one manual
// page open can measure several configurations as the page reloads itself.
location.replace('/corpus/ffset-v9.html?t=' + Date.now());
