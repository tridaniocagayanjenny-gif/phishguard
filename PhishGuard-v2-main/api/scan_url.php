<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once '../config.php';
require_once '../db.php';
require_once "../helpers.php";
require_once "vt_helper.php";

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'You must be logged in.'
    ]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'Invalid request method.'
    ]);
    exit;
}

$userId = (int) $_SESSION['user_id'];
$url    = trim($_POST['url'] ?? '');

if ($url === '') {
    http_response_code(400);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'Please enter a URL.'
    ]);
    exit;
}

if (!preg_match('/^https?:\/\//i', $url)) {
    $url = 'https://' . $url;
}

if (!filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'Please enter a valid URL.'
    ]);
    exit;
}

if (strlen($url) > 2000) {
    http_response_code(400);
    echo json_encode([
        'success'     => false,
        'result'      => 'ERROR',
        'risk_score'  => 0,
        'explanation' => 'The URL is too long.'
    ]);
    exit;
}

$score       = 0;
$reasons     = [];
$detectedUrls = [];

$blacklist = check_dangerous_sites($pdo, $url);

if ($blacklist['matched'] && $blacklist['risk_level'] === 'SAFE') {

    $score   = 0;
    $result  = 'SAFE';
    $reasons = ['This URL is on the PhishGuard trusted list: ' . $blacklist['notes']];

    $explanation = implode(' ', array_unique($reasons));

    saveUrlScan($pdo, $userId, $url, $result, $score, $reasons);

    echo json_encode([
        'success'     => true,
        'url'         => $url,
        'result'      => $result,
        'verdict'     => $result,
        'risk_score'  => $score,
        'score'       => $score,
        'explanation' => $explanation,
        'reason'      => $explanation,
        'detected'    => [],
        'html'        => buildResultHtml($url, $result, $score, $explanation, [])
    ]);
    exit;
}

$lowerUrl = strtolower($url);
$parts    = parse_url($url);

$scheme  = strtolower($parts['scheme'] ?? '');
$host    = strtolower($parts['host'] ?? '');
$path    = strtolower($parts['path'] ?? '');
$query   = strtolower($parts['query'] ?? '');
$fullUrl = $lowerUrl;

$SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
    'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'rb.gy', 'tiny.cc', 'tr.im', 'v.gd', 'shorte.st',
    'adf.ly', 'bc.vc', 'soo.gd', 's2r.co', 'clck.ru',
    'bit.do', 'mcaf.ee', 'po.st', 'qr.ae', 'x.co'
];

$SCAM_KEYWORDS = [
    'balance'         => 'Promises account balance (scam bait)',
    'cash out'        => 'Cash out bait (common scam)',
    'cashout'         => 'Cash out bait (common scam)',
    'claim'           => 'Claim reward bait',
    'winner'          => 'Fake winner notification',
    'congrats'        => 'Fake congratulations message',
    'congratulations' => 'Fake congratulations message',
    'prize'           => 'Fake prize offer',
    'reward'          => 'Fake reward offer',
    'you won'         => 'Fake "you won" message',
    'free money'      => 'Free money scam',
    'free cash'       => 'Free cash scam',
    'promo'           => 'Suspicious promo bait',
    'gcash'           => 'Mentions GCash (possible scam)',
    'paymaya'         => 'Mentions Maya (possible scam)',
    'gotyme'          => 'Mentions GoTyme (possible scam)',
    'shopee pay'      => 'Mentions ShopeePay (possible scam)',
    'spin'            => 'Gambling/spin bait',
    'jackpot'         => 'Jackpot scam',
    'lucky'           => 'Lucky draw scam',
    'selected'        => 'Fake "you are selected" message',
    'chosen'          => 'Fake "you are chosen" message',
    'exclusive'       => 'Fake exclusive offer',
    'limited time'    => 'Urgency tactic (common scam)',
    'act now'         => 'Urgency tactic (common scam)'
];

$SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.top', '.work', '.click', '.zip', '.online',
    '.link', '.live', '.icu', '.buzz', '.rest',
    '.monster', '.quest', '.cyou', '.sbs', '.cfd'
];

$isShortener = false;
foreach ($SHORTENER_DOMAINS as $s) {
    if ($host === $s || substr($host, -strlen('.' . $s)) === '.' . $s) {
        $isShortener = true;
        break;
    }
}

if ($isShortener) {
    $score += 35;
    $reasons[] = 'Shortened URL hides the real destination (' . $host . ').';

    $resolved = expandShortUrl($url);

    if ($resolved !== null && $resolved !== $url) {
        $detectedUrls[] = $resolved;
        $resolvedLower  = strtolower($resolved);
        $resolvedParts  = parse_url($resolved);
        $resolvedHost   = strtolower($resolvedParts['host'] ?? '');

        $reasons[] = 'Real destination: ' . $resolved;

        foreach ($SUSPICIOUS_TLDS as $tld) {
            if (substr($resolvedHost, -strlen($tld)) === $tld) {
                $score += 25;
                $reasons[] = 'Resolved URL uses suspicious TLD (' . $tld . ').';
                break;
            }
        }

        foreach ($SCAM_KEYWORDS as $kw => $desc) {
            if (strpos($resolvedLower, $kw) !== false) {
                $score += 20;
                $reasons[] = 'Resolved URL contains scam keyword: "' . $kw . '" — ' . $desc;
            }
        }
    } else {
        $reasons[] = 'Could not expand the shortened URL to verify its destination.';
        $score += 10;
    }
}

if ($scheme === 'http') {
    $score += 15;
    $reasons[] = 'The website uses HTTP instead of HTTPS.';
}

if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP)) {
    $score += 35;
    $reasons[] = 'The URL uses a direct IP address instead of a domain name.';
}

foreach (['.exe', '.apk', '.scr', '.bat', '.cmd', '.msi', '.jar', '.vbs', '.ps1', '.zip'] as $extension) {
    if (strpos($path, $extension) !== false) {
        $score += 30;
        $reasons[] = 'The URL points to a potentially dangerous file type: ' . $extension . '.';
        break;
    }
}

foreach ([
    'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification',
    'validate', 'secure', 'security', 'account', 'password', 'passcode',
    'otp', 'confirm', 'confirmation', 'unlock', 'suspended', 'suspension',
    'wallet', 'payment', 'billing'
] as $word) {
    if (strpos($fullUrl, $word) !== false) {
        $score += 12;
        $reasons[] = 'The URL contains the suspicious term "' . $word . '".';
    }
}

foreach ($SCAM_KEYWORDS as $kw => $desc) {
    if (strpos($fullUrl, $kw) !== false && !$isShortener) {
        $score += 20;
        $reasons[] = 'Scam keyword in URL: "' . $kw . '" — ' . $desc;
    }
}

foreach ($SUSPICIOUS_TLDS as $tld) {
    if (substr($host, -strlen($tld)) === $tld) {
        $score += 25;
        $reasons[] = 'Suspicious top-level domain (' . $tld . ') often used in scams.';
        break;
    }
}

foreach ([
    'paypal', 'gcash', 'maya', 'paymaya', 'bdo', 'bpi', 'metrobank',
    'unionbank', 'landbank', 'securitybank', 'facebook', 'instagram',
    'google', 'microsoft', 'apple', 'amazon'
] as $brand) {
    if (strpos($fullUrl, $brand) !== false) {
        $score += 10;
        $reasons[] = 'The URL contains a recognizable brand name: ' . $brand . '.';

        foreach (['login', 'verify', 'verification', 'secure', 'account', 'password', 'otp', 'confirm', 'unlock'] as $word) {
            if (strpos($fullUrl, $word) !== false) {
                $score += 25;
                $reasons[] = 'A brand name is combined with a suspicious "' . $word . '" pattern.';
                break;
            }
        }

        break;
    }
}

if (strpos($fullUrl, '@') !== false) {
    $score += 25;
    $reasons[] = 'The URL contains an @ symbol, which can hide the actual destination.';
}

if (substr_count($host, '.') >= 3) {
    $score += 10;
    $reasons[] = 'The domain contains multiple subdomain levels.';
}

if (strlen($url) > 150) {
    $score += 10;
    $reasons[] = 'The URL is unusually long.';
}

if (preg_match('/%[0-9a-f]{2}/i', $url)) {
    $score += 5;
    $reasons[] = 'The URL contains encoded characters.';
}

if (strpos($fullUrl, 'example') !== false) {
    $score += 5;
    $reasons[] = 'The domain appears to use a reserved example/testing domain.';
}

if ($blacklist['matched']) {
    if ($blacklist['risk_level'] === 'DANGEROUS') {
        $score += 80;
        $reasons[] = 'This URL is on the PhishGuard blacklist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
    } else {
        $score += 40;
        $reasons[] = 'This URL is on the PhishGuard watchlist (' . $blacklist['category'] . '): ' . $blacklist['notes'];
    }
}

$score = min(100, $score);

if ($score >= 70) {
    $result = 'DANGEROUS';
} elseif ($score >= 35) {
    $result = 'SUSPICIOUS';
} else {
    $result = 'SAFE';
}

$explanation = empty($reasons)
    ? 'No obvious phishing indicators were detected. This does not guarantee that the website is completely safe.'
    : implode(' ', array_unique($reasons));

saveUrlScan($pdo, $userId, $url, $result, $score, $reasons);

echo json_encode([
    'success'     => true,
    'url'         => $url,
    'result'      => $result,
    'verdict'     => $result,
    'risk_score'  => $score,
    'score'       => $score,
    'explanation' => $explanation,
    'reason'      => $explanation,
    'detected'    => $detectedUrls,
    'html'        => buildResultHtml($url, $result, $score, $explanation, $detectedUrls)
]);

function expandShortUrl(string $url): ?string
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 8);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; PhishGuard/1.0)');

    curl_exec($ch);

    $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    curl_close($ch);

    if (!$finalUrl || $httpCode >= 400) {
        return null;
    }

    return $finalUrl;
}

function buildResultHtml(string $url, string $result, int $score, string $explanation, array $detected): string
{
    $safeUrl  = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    $safeExp  = htmlspecialchars($explanation, ENT_QUOTES, 'UTF-8');
    $resultLc = strtolower($result);

    $html  = '<div class="pg-result-block">';
    $html .= '<div class="pg-result-header">';
    $html .= '<div>';
    $html .= '<div class="pg-result-label">ANALYSIS RESULT</div>';
    $html .= '<div class="pg-result-verdict ' . $resultLc . '">' . htmlspecialchars($result) . '</div>';
    $html .= '</div>';
    $html .= '<div class="pg-result-score">' . (int) $score . '%</div>';
    $html .= '</div>';
    $html .= '<div class="pg-result-reason">' . $safeExp . '</div>';

    if (!empty($detected)) {
        $html .= '<div class="pg-detected-urls" style="margin-top:12px;padding:10px;border-radius:8px;background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.22);">';
        $html .= '<strong style="display:block;margin-bottom:6px;color:#38bdf8;">Detected destination:</strong>';
        foreach ($detected as $du) {
            $html .= '<div style="font-family:monospace;font-size:12px;color:#cbd5e1;word-break:break-all;">' . htmlspecialchars($du) . '</div>';
        }
        $html .= '</div>';
    }

    $html .= '</div>';

    return $html;
}

/* Check kung URL scan ito para maglagay ng Preview Button */
let previewBtnHtml = '';
if (data.scan_type === 'url' || (data.explanation && data.explanation.includes('URL'))) {
    const previewUrl = encodeURIComponent(form.querySelector('input[name="url"]').value);
    previewBtnHtml = `
        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(148,163,184,0.15);">
            <a href="mini_browser.php?url=${previewUrl}&result=${data.result}&explanation=${encodeURIComponent(data.explanation)}&from=scanner.php" 
               class="pg-btn" 
               style="width: 100%; text-decoration: none; background: rgba(56,189,248,0.1); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3); box-shadow: none;">
                <i class="fa-solid fa-eye"></i> Preview Link in Mini Browser
            </a>
        </div>
    `;
}

function saveUrlScan(PDO $pdo, int $userId, string $url, string $result, int $score, array $reasons): void
{
    $explanation = empty($reasons)
        ? 'No obvious phishing indicators were detected. This does not guarantee that the website is completely safe.'
        : implode(' ', array_unique($reasons));

    $src = function_exists('detectSource') ? detectSource() : ['source' => 'web', 'app_client' => 'web'];

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare("
            INSERT INTO scans
            (user_id, scan_type, input_value, result, risk_score, explanation, source, app_client)
            VALUES (:user_id, 'url', :input_value, :result, :risk_score, :explanation, :source, :app_client)
        ");

        $stmt->execute([
            ':user_id'     => $userId,
            ':input_value' => $url,
            ':result'      => $result,
            ':risk_score'  => $score,
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
                VALUES ('url', :threat_value, :result, :risk_score, :source, :app_client)
            ");

            $threatStmt->execute([
                ':threat_value' => $url,
                ':result'       => $result,
                ':risk_score'   => $score,
                ':source'       => $src['source'],
                ':app_client'   => $src['app_client'],
            ]);

            $threatReported = true;
        }

        $pdo->commit();

    } catch (PDOException $e) {

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log('PhishGuard URL database error: ' . $e->getMessage());
    }
}