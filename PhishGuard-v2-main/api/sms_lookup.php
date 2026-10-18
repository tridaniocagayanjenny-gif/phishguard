<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once "../db.php";
require_once "../helpers.php";
require_once "vt_helper.php";

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode([
        'success' => false, 'result' => 'ERROR', 'risk_score' => 0,
        'explanation' => 'You must be logged in.'
    ]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false, 'result' => 'ERROR', 'risk_score' => 0,
        'explanation' => 'Invalid request method.'
    ]);
    exit;
}

$userId  = (int) $_SESSION['user_id'];
$sender  = trim($_POST['sender'] ?? '');
$message = trim($_POST['message'] ?? '');

if ($sender === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Please enter the SMS sender.']);
    exit;
}

if ($message === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'Please enter the SMS message.']);
    exit;
}

if (strlen($sender) > 100) {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'The sender value is too long.']);
    exit;
}

if (strlen($message) > 5000) {
    http_response_code(400);
    echo json_encode(['success' => false, 'result' => 'ERROR', 'risk_score' => 0, 'explanation' => 'The SMS message is too long.']);
    exit;
}

$senderLower  = strtolower($sender);
$messageLower = strtolower($message);
$combinedText = $senderLower . ' ' . $messageLower;

$riskScore = 0;
$reasons   = [];

$stmt = $pdo->prepare("
    SELECT sender_name, sender_type, organization, verified, notes
    FROM sms_senders
    WHERE LOWER(sender_name) = LOWER(?)
    LIMIT 1
");
$stmt->execute([$sender]);
$senderRecord = $stmt->fetch();

if ($senderRecord) {
    if ((int) $senderRecord['verified'] !== 1) {
        $riskScore += 15;
        $reasons[] = 'The sender exists in the database but is not verified.';
    }
} else {
    $riskScore += 12;
    $reasons[] = 'The sender is not currently listed in the PhishGuard sender database.';
}

/* High-risk phrase patterns — boosted weights */
foreach ([
    'send your otp' => 50, 'share your otp' => 50, 'give your otp' => 50,
    'provide your otp' => 50, 'enter your otp' => 40, 'otp code' => 40,
    'one time password' => 45, 'one-time password' => 45,
    'share your pin' => 50, 'send your pin' => 50, 'enter your pin' => 40,
    'share your password' => 50, 'send your password' => 50, 'confirm your password' => 40,
    'verify your account' => 35, 'verify your identity' => 30,
    'account will be suspended' => 45, 'account has been suspended' => 45,
    'account is suspended' => 45, 'account will be locked' => 45,
    'account has been locked' => 45,
    'unauthorized transaction' => 35, 'unauthorized activity' => 35, 'unusual activity' => 30,
    'click this link' => 35, 'click the link' => 35, 'open this link' => 30,
    'login immediately' => 35, 'verify immediately' => 35, 'act immediately' => 30,
    'limited time' => 20, 'claim your reward' => 35, 'claim your prize' => 45,
    'you have won' => 45, 'you won' => 45, 'free cash' => 45,
    'free money' => 45, 'cash prize' => 40, 'full name' => 15,
    'home address' => 15, 'within 24 hours' => 30, 'within 48 hours' => 25,
    'within 12 hours' => 30, 'within 1 hour' => 35,
    'final notice' => 40, 'permanently disabled' => 45,
    'compromised' => 45, 'will be deleted' => 45,
    'avoid legal action' => 40, 'avoid a penalty' => 40,
] as $pattern => $points) {
    if (strpos($messageLower, $pattern) !== false) {
        $riskScore += $points;
        $reasons[] = 'The message contains a high-risk phrase: "' . $pattern . '".';
    }
}

$asksForSensitive = preg_match('/\b(otp|one[\s-]?time\s?(pin|password|code)?|pin|password|cvv|verification code)\b/i', $message);
$asksToSend       = preg_match('/\b(send|share|provide|give|reply|enter|submit|confirm)\b/i', $message);
$asksForPersonal  = preg_match('/\b(full name|name|address|birthday|birthdate|mother\'?s maiden name|id number|account number|card number)\b/i', $message);

if ($asksForSensitive && $asksToSend) {
    $riskScore += 50;
    $reasons[] = 'The message asks you to send or share authentication information (OTP, PIN, or password).';
}

if ($asksForSensitive && $asksForPersonal) {
    $riskScore += 25;
    $reasons[] = 'The message combines sensitive security information with a request for personal details.';
}

$mentionsPrize   = preg_match('/\b(won|winner|prize|reward|congratulations|jackpot|lucky|raffle)\b/i', $message);
$mentionsUrgency = preg_match('/\b(within\s+\d+\s+(hour|hours|hr|hrs|day|days|minute|minutes)|immediately|urgent|act now|limited time|expires?|final notice|last chance)\b/i', $message);

if ($mentionsPrize && $mentionsUrgency) {
    $riskScore += 40;
    $reasons[] = 'The message combines a prize or reward claim with an artificial urgency deadline.';
}

if ($mentionsPrize && !$mentionsUrgency) {
    $riskScore += 15;
    $reasons[] = 'The message mentions a prize, reward, or winnings.';
}

foreach ([
    'gcash', 'maya', 'paymaya', 'paypal', 'bpi', 'bdo',
    'metrobank', 'unionbank', 'security bank', 'landbank',
    'eastwest', 'rcbc', 'pnb', 'gotyme', 'seabank'
] as $brand) {
    if (strpos($messageLower, $brand) !== false) {
        $riskScore += 8;
        $reasons[] = 'The message references a financial service or payment brand: "' . $brand . '".';
        break;
    }
}

$suspiciousTermCount = 0;
foreach ([
    'urgent', 'immediately', 'suspended', 'blocked', 'locked',
    'verify', 'verification', 'security alert', 'security notice',
    'update your account', 'confirm your account', 'login',
    'password', 'otp', 'pin', 'reward', 'prize', 'winner',
    'claim', 'cash', 'refund'
] as $term) {
    if (strpos($combinedText, $term) !== false) {
        $suspiciousTermCount++;
        $riskScore += 4;
        $reasons[] = 'The message contains the suspicious term "' . $term . '".';
    }
}

if ($suspiciousTermCount >= 3) {
    $riskScore += 20;
    $reasons[] = 'The message contains multiple phishing-related warning terms.';
}

if (preg_match('/https?:\/\/|www\./i', $message)) {
    $riskScore += 15;
    $reasons[] = 'The SMS contains a web link that should be verified before opening.';
}

if (preg_match('#https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|tiny\.cc|rb\.gy|lnkd\.in)/#i', $message)) {
    $riskScore += 20;
    $reasons[] = 'The SMS contains a shortened link, which hides the real destination.';
}

if (preg_match('/https?:\/\/[^ ]+@/i', $message)) {
    $riskScore += 20;
    $reasons[] = 'The message contains a potentially deceptive URL structure.';
}

if (preg_match('/\b(click|tap|open|visit|go to)\b/i', $message) && preg_match('/https?:\/\/|www\./i', $message)) {
    $riskScore += 12;
    $reasons[] = 'The SMS combines an action request with a web link.';
}

if (preg_match('/\b\d{4,8}\b/', $message)) {
    if (strpos($messageLower, 'otp') !== false || strpos($messageLower, 'pin') !== false
        || strpos($messageLower, 'code') !== false || strpos($messageLower, 'password') !== false) {
        $riskScore += 15;
        $reasons[] = 'The message appears to request or reference a security code.';
    }
}

$hasNeverShare = preg_match('/\b(never|do not|don\'?t|dont)\s+(share|give|disclose|reveal)\b/i', $message);

if ($hasNeverShare && $asksForSensitive && !$asksToSend) {
    $riskScore = max(0, $riskScore - 25);
}

$smsUrl = '';

if (preg_match(
    '#(?:https?://)?[a-z0-9][a-z0-9\-\.]*\.(?:com|net|org|ph|io|co|ly|cc|me|info|xyz|tk|ml|ga|cf|gq|top|work|click|zip|ua|ru|cn|biz|online|site|store|app)(?:/[^\s"\']*)?#i',
    $message,
    $urlMatch
)) {
    $smsUrl = rtrim($urlMatch[0], '.,;:!?)');

    if (strlen($smsUrl) >= 6) {
        $blacklist = check_dangerous_sites($pdo, $smsUrl);

        if ($blacklist['matched']) {
            if ($blacklist['risk_level'] === 'SAFE') {
                $riskScore = 0;
                $reasons = ['A link in the SMS is on the PhishGuard trusted list.'];
            } elseif ($blacklist['risk_level'] === 'DANGEROUS') {
                $riskScore += 80;
                $reasons[] = 'A link in the SMS is on the PhishGuard blacklist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
            } else {
                $riskScore += 40;
                $reasons[] = 'A link in the SMS is on the PhishGuard watchlist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
            }
        }

        $reasons[] = 'A link was found in the SMS: ' . $smsUrl;
    }
}

$riskScore = min(100, max(0, $riskScore));

if ($riskScore >= 60) {
    $result = 'DANGEROUS';
} elseif ($riskScore >= 30) {
    $result = 'SUSPICIOUS';
} else {
    $result = 'SAFE';
}

if (empty($reasons)) {
    $explanation = 'No obvious phishing indicators were detected in the SMS. Continue verifying unexpected messages before taking action.';
} else {
    $explanation = implode(' ', array_unique($reasons));
}

$inputValue = "Sender: " . $sender . "\nMessage: " . $message;
$src = detectSource();

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare("
        INSERT INTO scans
        (user_id, scan_type, input_value, result, risk_score, explanation, source, app_client)
        VALUES (:user_id, 'sms', :input_value, :result, :risk_score, :explanation, :source, :app_client)
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
            VALUES ('sms', :threat_value, :result, :risk_score, :source, :app_client)
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
        'sender'          => $sender,
        'message'         => $message,
        'detected_url'    => $smsUrl,
        'saved'           => true,
        'threat_reported' => $threatReported
    ]);

} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('PhishGuard SMS database error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'The SMS was analyzed but could not be saved.',
        'saved'       => false
    ]);
}