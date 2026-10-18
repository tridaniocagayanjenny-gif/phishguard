<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once "../db.php";
require_once "vt_helper.php";

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'You must be logged in.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Invalid request method.']);
    exit;
}

$userId = (int) $_SESSION['user_id'];
$file = $_FILES['image'] ?? null;

if (!$file) {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'No image was uploaded.']);
    exit;
}

if ($file['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Unable to upload the image.']);
    exit;
}

if ($file['size'] > 10 * 1024 * 1024) {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'The image must not exceed 10 MB.']);
    exit;
}

$allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$detectedType = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

if (!in_array($detectedType, $allowedTypes, true)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Only JPG, PNG, and WEBP images are supported.']);
    exit;
}

$uploadDir = "../uploads/";

if (!is_dir($uploadDir) && !mkdir($uploadDir, 0777, true)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Unable to create the upload directory.']);
    exit;
}

$extension = match ($detectedType) {
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp',
};

$fileName = uniqid('scan_', true) . '.' . $extension;
$filePath = $uploadDir . $fileName;

if (!move_uploaded_file($file['tmp_name'], $filePath)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Unable to save the uploaded image.']);
    exit;
}

$processedPath = null;
$realUpload = realpath($filePath);

if ($realUpload !== false && extension_loaded('gd')) {
    $img = null;
    $ext = strtolower(pathinfo($realUpload, PATHINFO_EXTENSION));

    if ($ext === 'jpg' || $ext === 'jpeg') {
        $img = @imagecreatefromjpeg($realUpload);
    } elseif ($ext === 'png') {
        $img = @imagecreatefrompng($realUpload);
    } elseif ($ext === 'webp') {
        $img = @imagecreatefromwebp($realUpload);
    }

    if ($img !== false && $img !== null) {
        $w = imagesx($img);
        $h = imagesy($img);
        $scale = 3;

        $bigger = imagecreatetruecolor($w * $scale, $h * $scale);
        $white  = imagecolorallocate($bigger, 255, 255, 255);
        imagefill($bigger, 0, 0, $white);

        imagecopyresampled($bigger, $img, 0, 0, 0, 0, $w * $scale, $h * $scale, $w, $h);
        imagefilter($bigger, IMG_FILTER_GRAYSCALE);
        imagefilter($bigger, IMG_FILTER_CONTRAST, -30);

        $processedPath = $uploadDir . 'proc_' . $fileName;
        imagepng($bigger, $processedPath, 9);

        imagedestroy($bigger);
        imagedestroy($img);

        $filePath = $processedPath;
    }
}

function ocr_image(string $filePath): string
{
    $tesseract = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe';

    if (!file_exists($tesseract)) return '';

    $real = realpath($filePath);
    if ($real === false) return '';

    $command = '"' . $tesseract . '" "' . $real . '" stdout --psm 6 2>NUL';
    $output = shell_exec($command);

    if (!is_string($output)) return '';

    $output = preg_replace('/\s*\n\s*/', '', $output);
    $output = preg_replace('/\s+/', ' ', $output);

    return trim($output);
}

$text = ocr_image($filePath);

function extract_url_from_text(string $text): string
{
    $tlds = 'com|net|org|ph|io|co|ly|cc|me|info|xyz|tk|ml|'
          . 'ga|cf|gq|top|work|click|zip|ua|ru|cn|biz|'
          . 'online|site|store|app';

    $pattern = '#\b([a-z][a-z0-9\-]{2,}\.)+'
             . '(?:' . $tlds . ')'
             . '(?:/[a-z0-9\-_\./%]+)?#i';

    if (!preg_match_all($pattern, $text, $matches)) return '';

    $candidates = [];

    foreach ($matches[0] as $raw) {
        $url = rtrim($raw, '.,;:!?)');
        if (strlen($url) < 6) continue;

        $hostPart     = explode('/', $url)[0];
        $firstSegment = explode('.', $hostPart)[0];

        if (strlen($firstSegment) < 3) continue;

        $url = preg_replace('/(?<=\/)\d(?=[a-z])/i', '', $url);
        $candidates[] = $url;
    }

    if (empty($candidates)) return '';

    usort($candidates, fn($a, $b) => strlen($b) - strlen($a));

    return $candidates[0];
}

function analyze_url(string $url): array
{
    global $pdo;

    $score   = 0;
    $reasons = [];

    $forParsing = preg_match('#^https?://#i', $url) ? $url : 'https://' . $url;
    $parts = parse_url($forParsing);

    if ($parts === false || empty($parts['host'])) return [$score, $reasons];

    $host  = strtolower($parts['host']);
    $path  = strtolower($parts['path'] ?? '');
    $lower = strtolower($url);

    if (stripos($url, 'http://') === 0) {
        $score += 15;
        $reasons[] = 'The link uses HTTP instead of HTTPS.';
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $score += 35;
        $reasons[] = 'The link uses a raw IP address.';
    }

    foreach (['.exe','.apk','.scr','.bat','.cmd','.msi','.jar','.vbs','.ps1'] as $ext) {
        if (str_ends_with($path, $ext)) {
            $score += 30;
            $reasons[] = 'The link points to a dangerous file (' . $ext . ').';
            break;
        }
    }

    foreach ([
        'login','signin','verify','verification','validate',
        'secure','account','password','otp','confirm',
        'unlock','suspended','wallet','payment','billing',
        'claim','reward','prize','urgent','update'
    ] as $word) {
        if (str_contains($lower, $word)) {
            $score += 12;
            $reasons[] = 'The link contains the suspicious term "' . $word . '".';
        }
    }

    foreach ([
        'paypal','gcash','maya','paymaya','bdo','bpi',
        'metrobank','unionbank','landbank','facebook',
        'instagram','google','microsoft','apple','amazon',
        'docusign','metamask','binance'
    ] as $brand) {
        if (str_contains($lower, $brand)) {
            $score += 10;
            $reasons[] = 'The link uses the brand name "' . $brand . '".';
            break;
        }
    }

    if (str_contains($url, '@')) {
        $score += 25;
        $reasons[] = 'The link uses an @ symbol that hides the real destination.';
    }

    if (substr_count($host, '.') >= 3) {
        $score += 10;
        $reasons[] = 'The link uses multiple subdomain levels.';
    }

    foreach (['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work','.click','.biz','.online','.site','.store'] as $tld) {
        if (str_ends_with($host, $tld)) {
            $score += 20;
            $reasons[] = 'The link uses a suspicious domain extension (' . $tld . ').';
            break;
        }
    }

    if (strlen($url) > 75) {
        $score += 8;
        $reasons[] = 'The link is unusually long.';
    }

    if (preg_match('#/(?:libraries|joomla|wp-content|wp-admin|administrator|\.git|config|backup|admin)#i', $path)) {
        $score += 15;
        $reasons[] = 'The link exposes a system path pattern.';
    }

    $blacklist = check_dangerous_sites($pdo, $url);

    if ($blacklist['matched']) {
        if ($blacklist['risk_level'] === 'DANGEROUS') {
            $score += 80;
            $reasons[] = 'This URL is on the PhishGuard blacklist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
        } else {
            $score += 40;
            $reasons[] = 'This URL is on the PhishGuard watchlist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
        }
    }

    return [$score, $reasons];
}

function keyword_score(string $text): array
{
    $keywords = [
        'verify','verification','login','password','otp',
        'account','bank','gcash','maya','click here',
        'urgent','suspended','locked','confirm','claim',
        'payment','send money'
    ];

    $score   = 0;
    $reasons = [];

    foreach ($keywords as $keyword) {
        if (stripos($text, $keyword) !== false) {
            $score += 12;
            $reasons[] = 'The image contains suspicious wording related to "' . $keyword . '".';
        }
    }

    return [$score, $reasons];
}

$risk        = 0;
$reasons     = [];
$detectedUrl = '';

if ($text !== '') {
    $detectedUrl = extract_url_from_text($text);

    if ($detectedUrl !== '') {
        [$urlScore, $urlReasons] = analyze_url($detectedUrl);
        $risk     += $urlScore + 15;
        $reasons   = array_merge($reasons, $urlReasons);
        $reasons[] = 'A link was found inside the image: ' . $detectedUrl;
    } else {
        [$kwScore, $kwReasons] = keyword_score($text);
        $risk     += $kwScore;
        $reasons   = array_merge($reasons, $kwReasons);
    }
}

$risk = min($risk, 100);

if ($risk >= 70) {
    $result = 'DANGEROUS';
} elseif ($risk >= 35) {
    $result = 'SUSPICIOUS';
} else {
    $result = 'SAFE';
}

if ($text === '') {
    $explanation = 'No readable text was detected. The image could not be fully analyzed.';
} elseif (empty($reasons)) {
    $explanation = 'No obvious phishing-related wording was detected in the extracted text.';
} else {
    $explanation = implode(' ', array_unique($reasons));
}

$inputValue = $text !== '' ? $text : 'Image scan: ' . $fileName;

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare("
        INSERT INTO scans
        (user_id, scan_type, input_value, result, risk_score, explanation, source)
        VALUES (?, 'image', ?, ?, ?, ?, 'web')
    ");

    $stmt->execute([$userId, $inputValue, $result, $risk, $explanation]);

    $scanId = (int) $pdo->lastInsertId();
    $threatReported = false;

    if ($result !== 'SAFE') {
        $threatStmt = $pdo->prepare("
            INSERT INTO threat_reports
            (threat_type, threat_value, result, risk_score, source)
            VALUES ('image', ?, ?, ?, 'web')
        ");

        $threatStmt->execute([$inputValue, $result, $risk]);
        $threatReported = true;
    }

    $pdo->commit();

    echo json_encode([
        'success'         => true,
        'scan_id'         => $scanId,
        'result'          => $result,
        'risk_score'      => $risk,
        'explanation'     => $explanation,
        'ocr_text'        => $text,
        'detected_url'    => $detectedUrl,
        'saved'           => true,
        'threat_reported' => $threatReported
    ]);

} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('PhishGuard Image database error: ' . $e->getMessage());

    http_response_code(500);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'The image was analyzed but could not be saved.',
        'saved'       => false
    ]);
}