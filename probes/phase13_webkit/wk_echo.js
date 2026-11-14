// Worker-side probe (served as /raw/wk_echo.js, application/javascript).
function wb(tag) {
  try { fetch('/beacon/' + encodeURIComponent(tag) + '?t=' + Date.now(), { mode: 'no-cors' }).catch(function() {}); } catch (e) {}
}
wb('WK-RAW-ALIVE caches=' + (typeof caches) + ' storage=' + (typeof navigator.storage) + ' perms=' + (typeof navigator.permissions));
onmessage = function (e) {
  wb('WK-RAW-MSG got=' + e.data);
  try { postMessage('echo:' + e.data); } catch (err) {}
};
