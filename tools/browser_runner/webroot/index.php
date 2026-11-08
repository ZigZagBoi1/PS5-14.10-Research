<?php
// PS5 probe launcher — served when the PS5 opens User Guide
// URL: https://manuals.playstation.net/document/en/ps5/

// Check if a specific probe is requested
$probe = isset($_GET['p']) ? basename($_GET['p']) : '';

// Default: serve p568 (Canvas UAF reclaim) — p567 feature detect done
if (!$probe) {
    $probe = 'p568';
}

$htmlFile = __DIR__ . "/../{$probe}.html";
if (file_exists($htmlFile)) {
    readfile($htmlFile);
    exit;
}

// Fallback: probe selection page
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <title>PS5 Probe Server</title>
  <style>
    body { background: #111; color: #eee; font-family: monospace; padding: 20px; }
    a { color: #0af; font-size: 18px; display: block; margin: 10px 0; }
  </style>
</head>
<body>
  <h2>PS5 WebKit Probe Server</h2>
  <p>Select a probe to run:</p>
  <a href="?p=p567">P567: Feature Detection (BigInt, Wasm, Workers)</a>
  <a href="?p=p568">P568: 768B ArrayBuffer Reclaim (Canvas UAF)</a>
  <a href="?p=p569">P569: FontFace + Canvas UAF Combo</a>
  <hr>
  <a href="?p=p553">P553: Canvas UAF Original</a>
  <a href="?p=p550">P550: Canvas UAF Transform Leak</a>
  <script>
    new Image().src = '/beacon/INDEX-LOADED?t=' + Date.now();
  </script>
</body>
</html>
