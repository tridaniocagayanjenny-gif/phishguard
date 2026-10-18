<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once "../db.php";
require_once "../helpers.php";
require_once "vt_helper.php";

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'result' => 'ERROR',
        'risk_score' => 0,
        'explanation' => 'You must be logged in.'
    ]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'result' => 'ERROR',
        'risk_score' => 0,
        'explanation' => 'Invalid request method.'
    ]);
    exit;
}

$userId = (int) $_SESSION['user_id'];
$decodedData = trim($_POST['decoded_data'] ?? '');

if ($decodedData === '') {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'result' => 'ERROR',
        'risk_score' => 0,
        'explanation' => 'No QR code could be detected in the image.'
    ]);
    exit;
}

if (strlen($decodedData) > 5000) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'result' => 'ERROR',
        'risk_score' => 0,
        'explanation' => 'The QR code data is too long.'
    ]);
    exit;
}

$riskScore = 0;
$reasons   = [];
$lowerData = strtolower($decodedData);
$qrUrl     = '';

if (filter_var($decodedData, FILTER_VALIDATE_URL)) {

    $qrUrl = $decodedData;

    $parts = parse_url($decodedData);

    $scheme = strtolower($parts['scheme'] ?? '');
    $host   = strtolower($parts['host'] ?? '');

    if ($scheme !== 'https') {
        $riskScore += 20;
        $reasons[] = 'The QR code opens a link that does not use HTTPS.';
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $riskScore += 35;
        $reasons[] = 'The QR code points directly to an IP address.';
    }

    if (strlen($decodedData) > 150) {
        $riskScore += 10;
        $reasons[] = 'The QR link contains an unusually long address.';
    }

    $hostParts = explode('.', $host);

    if (count($hostParts) >= 4) {
        $riskScore += 15;
        $reasons[] = 'The link contains multiple subdomains.';
    }

    if (substr_count($host, '.') >= 3) {
        $riskScore += 10;
        $reasons[] = 'The domain structure requires additional verification.';
    }

    foreach ([
        'login', 'verify', 'verification', 'secure', 'account',
        'update', 'password', 'wallet', 'otp', 'claim',
        'reward', 'prize', 'free', 'urgent', 'suspended',
        'bank', 'gcash', 'maya', 'paymaya', 'phishing', 'scam'
    ] as $term) {
        if (strpos($lowerData, $term) !== false) {
            $riskScore += 8;
            $reasons[] = 'The QR link contains the suspicious term "' . $term . '".';
        }
    }

    if (strpos($decodedData, '@') !== false) {
        $riskScore += 20;
        $reasons[] = 'The URL contains an @ symbol, which can be used to disguise destinations.';
    }

    if (substr_count($decodedData, '//') > 1) {
        $riskScore += 15;
        $reasons[] = 'The URL contains multiple protocol separators.';
    }

} else {

    foreach ([
        'otp', 'password', 'pin', 'verify', 'verification',
        'urgent', 'claim', 'reward', 'prize', 'gcash',
        'maya', 'paymaya', 'bank', 'account', 'login',
        'suspended', 'phishing', 'scam', 'malware'
    ] as $term) {
        if (strpos($lowerData, $term) !== false) {
            $riskScore += 10;
            $reasons[] = 'The QR data contains the suspicious term "' . $term . '".';
        }
    }

    if (strlen($decodedData) > 500) {
        $riskScore += 15;
        $reasons[] = 'The QR code contains an unusually large amount of data.';
    }
}

if ($qrUrl !== '') {

    $blacklist = check_dangerous_sites($pdo, $qrUrl);

    if ($blacklist['matched']) {
        if ($blacklist['risk_level'] === 'DANGEROUS') {
            $riskScore += 80;
            $reasons[] = 'This URL is on the PhishGuard blacklist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
        } else {
            $riskScore += 40;
            $reasons[] = 'This URL is on the PhishGuard watchlist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
        }
    }
}

$riskScore = min(100, max(0, $riskScore));

if ($riskScore >= 70) {
    $result = 'DANGEROUS';
} elseif ($riskScore >= 35) {
    $result = 'SUSPICIOUS';
} else {
    $result = 'SAFE';
}

if (empty($reasons)) {
    $explanation = 'No obvious phishing indicators were detected in the QR code data. Continue verifying the destination before proceeding.';
} else {
    $explanation = implode(' ', array_unique($reasons));
}

$inputValue = $decodedData;
$src = detectSource();

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare("
        INSERT INTO scans
        (user_id, scan_type, input_value, result, risk_score, explanation, source, app_client)
        VALUES (:user_id, 'qr', :input_value, :result, :risk_score, :explanation, :source, :app_client)
    ");

    $stmt->execute([
        ':user_id'     => $userId,
        ':input_value' => $inputValue,
        ':result'      => $result,
        ':risk_score'  => $riskScore,
        ':explanation' => $explanation,
        ':source'      => $src['source'],
        ':app_client'  => $src['app_client'],
    ]);

    $scanId = (int) $pdo->lastInsertId();

    $threatReported = false;

    if ($result !== 'SAFE') {
        $threatStmt = $pdo->prepare("
            INSERT INTO threat_reports
            (threat_type, threat_value, result, risk_score, source, app_client)
            VALUES ('qr', :threat_value, :result, :risk_score, :source, :app_client)
        ");

        $threatStmt->execute([
            ':threat_value' => $inputValue,
            ':result'       => $result,
            ':risk_score'   => $riskScore,
            ':source'       => $src['source'],
            ':app_client'   => $src['app_client'],
        ]);

        $threatReported = true;
    }

    $pdo->commit();

    echo json_encode([
        'success'         => true,
        'scan_id'         => $scanId,
        'result'          => $result,
        'risk_score'      => $riskScore,
        'explanation'     => $explanation,
        'decoded_data'    => $decodedData,
        'saved'           => true,
        'threat_reported' => $threatReported
    ]);

} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('PhishGuard QR database error: ' . $e->getMessage());

    http_response_code(500);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'The QR result was analyzed but could not be saved.',
        'saved'       => false
    ]);
}