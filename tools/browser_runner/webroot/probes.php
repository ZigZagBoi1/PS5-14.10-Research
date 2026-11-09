<?php
// Serve probe JS files from the probes directories
$file = isset($_GET['file']) ? basename($_GET['file']) : '';
if (!$file || !preg_match('/^p\d+[a-z_]*\.js$/', $file)) {
    http_response_code(404);
    exit('Not found');
}

// Search probe directories
$dirs = [
    __DIR__ . '/../../probes/phase23_info_leak/',
    __DIR__ . '/../../probes/phase13_webkit/',
];

// Also check direct mapping (p567_feature_detect.js etc.)
foreach ($dirs as $dir) {
    // Try exact match
    $path = $dir . $file;
    if (file_exists($path)) {
        header('Content-Type: application/javascript; charset=utf-8');
        header('Cache-Control: no-store');
        readfile($path);
        exit;
    }
    // Try glob match for probe name prefix
    $prefix = preg_replace('/\.js$/', '', $file);
    $matches = glob($dir . $prefix . '*.js');
    if ($matches) {
        header('Content-Type: application/javascript; charset=utf-8');
        header('Cache-Control: no-store');
        readfile($matches[0]);
        exit;
    }
}

http_response_code(404);
echo 'Probe not found: ' . htmlspecialchars($file);
