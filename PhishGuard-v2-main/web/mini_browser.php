<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require_once '../config.php';
require_once '../db.php';

$pageTitle    = 'Mini Browser';
$pageSubtitle = 'Preview links safely inside PhishGuard';
$userName     = $_SESSION['full_name'] ?? 'User';
$userInitial  = strtoupper(substr($userName, 0, 1));

$urlToLoad = trim($_GET['url'] ?? '');
$isBlocked = false;
$blockReason = '';
$riskLevel = 'SAFE';

if ($urlToLoad !== '') {
    
    // I-ensure na may https:// or http://
    if (!preg_match('#^https?://#i', $urlToLoad)) {
        $urlToLoad = 'http://' . $urlToLoad;
    }

    $host = strtolower(parse_url($urlToLoad, PHP_URL_HOST) ?? '');
    $fullUrl = strtolower($urlToLoad);

    try {
        // 1. Check sa Dangerous Sites Table
        $stmt = $pdo->query("SELECT url_pattern, category, notes FROM dangerous_sites WHERE is_active = 1");
        foreach ($stmt->fetchAll() as $row) {
            $pattern = strtolower($row['url_pattern']);
            if ($pattern !== '' && (strpos($host, $pattern) !== false || strpos($fullUrl, $pattern) !== false)) {
                $isBlocked = true;
                $blockReason = 'Blacklisted: ' . $row['notes'];
                $riskLevel = 'DANGEROUS';
                break;
            }
        }

        // 2. Check sa Threat Reports (Kung na-scan na before)
        if (!$isBlocked) {
            $threat = $pdo->prepare("SELECT result, explanation FROM threat_reports WHERE threat_value LIKE ? ORDER BY risk_score DESC LIMIT 1");
            $threat->execute(['%' . $host . '%']);
            $existing = $threat->fetch();
            if ($existing && $existing['result'] === 'DANGEROUS') {
                $isBlocked = true;
                $blockReason = 'Previously flagged by PhishGuard: ' . $existing['explanation'];
                $riskLevel = 'DANGEROUS';
            }
        }

        // 3. Local Heuristics (kung wala pa sa DB)
        if (!$isBlocked) {
            $score = 0;
            $reasons = [];

            if (stripos($urlToLoad, 'http://') === 0) { $score += 15; $reasons[] = 'Uses HTTP instead of HTTPS.'; }
            if (filter_var($host, FILTER_VALIDATE_IP)) { $score += 35; $reasons[] = 'Uses raw IP address.'; }
            
            foreach (['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work','.click','.biz','.info','.online','.site'] as $tld) {
                if (str_ends_with($host, $tld)) { $score += 25; $reasons[] = 'Suspicious domain extension ('.$tld.').'; break; }
            }

            foreach (['login','verify','secure','account','update','password','wallet','otp','claim','refund','gcash','paypal','bdo','metamask','binance'] as $word) {
                if (strpos($fullUrl, $word) !== false) { $score += 15; $reasons[] = 'Contains suspicious word: "'.$word.'".'; }
            }

            if ($score >= 70) {
                $isBlocked = true;
                $riskLevel = 'DANGEROUS';
                $blockReason = implode(' ', array_unique($reasons));
            } elseif ($score >= 35) {
                $riskLevel = 'SUSPICIOUS';
                $blockReason = implode(' ', array_unique($reasons));
            }
        }

    } catch (PDOException $e) {
        // Ignore DB errors, treat as safe
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mini Browser | PhishGuard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/style.css">
    <style>
        .pg-mb-wrap {
            display: flex; flex-direction: column; height: calc(100vh - 200px); min-height: 560px;
            border: 1px solid rgba(148, 163, 184, 0.14); border-radius: 18px; background: #0f1b30; overflow: hidden;
        }
        .pg-mb-bar {
            display: flex; align-items: center; gap: 10px; padding: 12px 14px;
            background: #0d1830; border-bottom: 1px solid rgba(148, 163, 184, 0.14);
        }
        .pg-mb-url {
            flex: 1; position: relative; min-width: 0;
        }
        .pg-mb-url i { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); color: #22c55e; font-size: 12px; }
        .pg-mb-url input {
            width: 100%; height: 42px; padding: 0 14px 0 38px; border-radius: 11px;
            border: 1px solid rgba(148, 163, 184, 0.18); background: rgba(2, 6, 23, 0.6);
            color: #f8fafc; font-size: 13px; font-family: monospace; outline: none;
        }
        .pg-mb-go {
            height: 42px; padding: 0 20px; border-radius: 11px; border: 0;
            background: linear-gradient(135deg, #2563eb, #38bdf8); color: #fff;
            font-size: 12px; font-weight: 700; cursor: pointer;
        }
        .pg-mb-frame-area { flex: 1; position: relative; background: #ffffff; }
        .pg-mb-frame { width: 100%; height: 100%; border: 0; }
        .pg-mb-blocked {
            position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center;
            gap: 16px; padding: 40px; text-align: center; background: #0f1b30; z-index: 10;
        }
        .pg-mb-blocked-icon { width: 84px; height: 84px; border-radius: 22px; display: flex; align-items: center; justify-content: center; font-size: 34px; background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; }
        .pg-mb-blocked h3 { color: #f8fafc; font-weight: 800; margin: 0; }
        .pg-mb-blocked p { color: #94a3b8; font-size: 13px; max-width: 500px; }
        .pg-mb-reason { padding: 10px 16px; border-radius: 10px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.25); color: #fca5a5; font-size: 12px; font-weight: 600; }
        .pg-mb-warn { background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.25); color: #fcd34d; }
    </style>
</head>
<body>
<div class="pg-layout">
    <?php require_once 'includes/sidebar.php'; ?>
    <main class="pg-main">
        <?php require_once 'includes/topbar.php'; ?>
        <div class="pg-content">
            <div class="pg-section-head" style="margin-bottom:14px;">
                <div>
                    <h2>Mini Browser</h2>
                    <p>Preview links safely inside PhishGuard.</p>
                </div>
            </div>
            <div class="pg-mb-wrap">
                <form method="GET" action="mini_browser.php" class="pg-mb-bar">
                    <div class="pg-mb-url">
                        <i class="fa-solid fa-lock"></i>
                        <input type="text" name="url" placeholder="Type a URL and press Go" value="<?= htmlspecialchars($urlToLoad) ?>" autocomplete="off">
                    </div>
                    <button type="submit" class="pg-mb-go">Go</button>
                </form>
                <div class="pg-mb-frame-area">
                    <?php if ($urlToLoad === ''): ?>
                        <div class="pg-mb-blocked" style="background: #0f1b30; color: #64748b;">
                            <i class="fa-solid fa-shield-halved" style="font-size: 40px; color: #38bdf8;"></i>
                            <h3>Ready to browse safely</h3>
                            <p>Type a URL in the bar above. PhishGuard will check it against the blacklist first.</p>
                        </div>
                    <?php elseif ($isBlocked): ?>
                        <div class="pg-mb-blocked">
                            <div class="pg-mb-blocked-icon"><i class="fa-solid fa-shield-xmark"></i></div>
                            <h3>Blocked — This URL is DANGEROUS</h3>
                            <p>PhishGuard automatically blocked this URL for your safety. The preview was not loaded.</p>
                            <div class="pg-mb-reason"><?= htmlspecialchars($blockReason) ?></div>
                        </div>
                    <?php else: ?>
                        <?php if ($riskLevel === 'SUSPICIOUS'): ?>
                            <div style="padding: 10px 16px; background: rgba(245, 158, 11, 0.1); border-bottom: 1px solid rgba(245, 158, 11, 0.2); color: #fcd34d; font-size: 12px; position: relative; z-index: 5;">
                                <i class="fa-solid fa-triangle-exclamation"></i> Suspicious URL — <?= htmlspecialchars($blockReason) ?>
                            </div>
                        <?php endif; ?>
                        <iframe src="<?= htmlspecialchars($urlToLoad) ?>" class="pg-mb-frame" sandbox="allow-same-origin allow-scripts allow-forms" referrerpolicy="no-referrer"></iframe>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </main>
</div>
</body>
</html>