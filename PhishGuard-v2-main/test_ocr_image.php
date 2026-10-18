<?php

$tesseract = 'C:\Program Files\Tesseract-OCR\tesseract.exe';

$dir = __DIR__ . '/uploads/';

$files = glob($dir . 'scan_*');
if (!$files) {
    echo "No uploaded images found in: " . $dir;
    exit;
}

usort($files, fn($a, $b) => filemtime($b) - filemtime($a));
$latest = $files[0];

echo "Testing OCR on: " . basename($latest) . "<br><br>";

$command = '"' . $tesseract . '" "' . $latest . '" stdout 2>&1';
echo "Command: <code>" . htmlspecialchars($command) . "</code><br><br>";

$text = shell_exec($command);
echo "Result:<br><pre>" . htmlspecialchars((string) $text) . "</pre>";