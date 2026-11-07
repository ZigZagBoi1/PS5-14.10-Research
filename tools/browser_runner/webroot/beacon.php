<?php
// Beacon capture endpoint for PS5 WebKit probes
// Handles both formats:
//   GET /beacon/P567-TAG-extra?t=123  (new Image.src format)
//   GET /beacon?m=message             (old XHR format)
//   POST /beacon/tag                  (body format)

$tag = isset($_GET['tag']) ? $_GET['tag'] : '';
$msg = isset($_GET['m']) ? $_GET['m'] : '';
$t   = isset($_GET['t']) ? $_GET['t'] : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = file_get_contents('php://input');
    if ($tag) {
        $msg = "$tag: $body";
    } else {
        $msg = $body;
    }
} elseif ($tag) {
    $msg = $tag;
}

// Log to file and stdout
$ts = date('Y-m-d H:i:s.') . substr(microtime(), 2, 3);
$ip = $_SERVER['REMOTE_ADDR'];
$msg = str_replace(array("\r", "\n"), array('\\r', '\\n'), $msg);
$line = "[$ts] BEACON $ip: $msg\n";

$logDir = __DIR__ . '/../beacon_logs';
if (!is_dir($logDir)) mkdir($logDir, 0755, true);
$logFile = $logDir . '/beacons_' . date('Ymd') . '.log';
file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);

// Also log to Apache error log for real-time monitoring
error_log("PS5-BEACON: $msg");

// Return 1x1 transparent GIF (for Image.src beacons)
header('Content-Type: image/gif');
header('Content-Length: 43');
header('Cache-Control: no-store');
echo base64_decode('R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==');
