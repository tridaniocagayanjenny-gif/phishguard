<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

require_once "../db.php";

$userName = $_SESSION['full_name'] ?? 'User';
$userInitial = strtoupper(substr($userName, 0, 1));

$totalScans = 0;
$safeScans = 0;
$suspiciousScans = 0;
$dangerousScans = 0;
$recentScans = [];

try {
    $userId = $_SESSION['user_id'];

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ?");
    $stmt->execute([$userId]);
    $totalScans = (int)$stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ? AND result = 'SAFE'");
    $stmt->execute([$userId]);
    $safeScans = (int)$stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ? AND result = 'SUSPICIOUS'");
    $stmt->execute([$userId]);
    $suspiciousScans = (int)$stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM scans WHERE user_id = ? AND result = 'DANGEROUS'");
    $stmt->execute([$userId]);
    $dangerousScans = (int)$stmt->fetchColumn();

    $stmt = $pdo->prepare("
        SELECT scan_type, input_value, result, risk_score, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 6
    ");
    $stmt->execute([$userId]);
    $recentScans = $stmt->fetchAll();

} catch (PDOException $e) {
    $recentScans = [];
}

function resultBadge($result)
{
    $class = strtolower($result);

    return '<span class="pg-badge pg-badge-' . htmlspecialchars($class) . '">' .
        htmlspecialchars($result) .
        '</span>';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Dashboard | PhishGuard</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <link
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
        rel="stylesheet"
    >

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>
</head>

<body>

<div class="pg-layout">

 <?php require_once 'includes/sidebar.php'; ?>

    <main class="pg-main">

        <?php require_once 'includes/topbar.php'; ?>

        <div class="pg-content">

            <section class="pg-hero">

                <span class="pg-eyebrow">
                    <i class="fa-solid fa-shield-check"></i>
                    Protection Center
                </span>

                <h1>
                    Stay one step ahead of online scams.
                </h1>

                <p>
                    PhishGuard helps identify suspicious links, QR codes,
                    screenshots, fake receipts, and unknown SMS senders
                    before they become a security problem.
                </p>

            </section>

            <section class="pg-stats">

                <div class="pg-stat">

                    <div class="pg-stat-top">
                        <span class="pg-stat-icon">
                            <i class="fa-solid fa-shield-halved"></i>
                        </span>

                        <i class="fa-solid fa-chart-line" style="color:#475569;"></i>
                    </div>

                    <div class="pg-stat-label">Total Scans</div>
                    <div class="pg-stat-value"><?= $totalScans ?></div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-top">
                        <span class="pg-stat-icon">
                            <i class="fa-solid fa-circle-check"></i>
                        </span>
                    </div>

                    <div class="pg-stat-label">Safe Results</div>
                    <div class="pg-stat-value"><?= $safeScans ?></div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-top">
                        <span class="pg-stat-icon">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                        </span>
                    </div>

                    <div class="pg-stat-label">Suspicious Results</div>
                    <div class="pg-stat-value"><?= $suspiciousScans ?></div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-top">
                        <span class="pg-stat-icon">
                            <i class="fa-solid fa-bug"></i>
                        </span>
                    </div>

                    <div class="pg-stat-label">Dangerous Results</div>
                    <div class="pg-stat-value"><?= $dangerousScans ?></div>

                </div>

            </section>

            <div class="pg-section-head">

                <div>
                    <h2>Security Scan Center</h2>
                    <p>Select a scanner to analyze a possible threat.</p>
                </div>

                <a href="scanner.php" class="pg-btn">
                    Open Scanner
                    <i class="fa-solid fa-arrow-right"></i>
                </a>

            </div>

            <section class="pg-scanner-grid">

                <a href="scanner.php?type=url" class="pg-scanner-card">

                    <div class="pg-scanner-icon">
                        <i class="fa-solid fa-link"></i>
                    </div>

                    <h3>URL Guard</h3>

                    <p>
                        Analyze suspicious links and identify common
                        phishing indicators.
                    </p>

                    <span class="pg-arrow">
                        <i class="fa-solid fa-arrow-right"></i>
                    </span>

                </a>

                <a href="scanner.php?type=image" class="pg-scanner-card">

                    <div class="pg-scanner-icon">
                        <i class="fa-solid fa-image"></i>
                    </div>

                    <h3>Image & OCR</h3>

                    <p>
                        Analyze screenshots, messages, receipts,
                        and other uploaded images.
                    </p>

                    <span class="pg-arrow">
                        <i class="fa-solid fa-arrow-right"></i>
                    </span>

                </a>

                <a href="scanner.php?type=qr" class="pg-scanner-card">

                    <div class="pg-scanner-icon">
                        <i class="fa-solid fa-qrcode"></i>
                    </div>

                    <h3>QR Scanner</h3>

                    <p>
                        Check QR codes that may redirect to
                        suspicious payment or phishing pages.
                    </p>

                    <span class="pg-arrow">
                        <i class="fa-solid fa-arrow-right"></i>
                    </span>

                </a>

                <a href="scanner.php?type=sms" class="pg-scanner-card">

                    <div class="pg-scanner-icon">
                        <i class="fa-solid fa-message"></i>
                    </div>

                    <h3>SMS Lookup</h3>

                    <p>
                        Check sender identities and assess
                        potentially suspicious messages.
                    </p>

                    <span class="pg-arrow">
                        <i class="fa-solid fa-arrow-right"></i>
                    </span>

                </a>

            </section>

            <section class="pg-grid-2">

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>Recent Security Activity</h3>
                        </div>

                        <a href="history.php" style="color:#38bdf8;font-size:10px;">
                            View All
                        </a>

                    </div>

                    <div class="pg-table-wrap">

                        <table class="pg-table">

                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Input</th>
                                    <th>Result</th>
                                    <th>Risk</th>
                                    <th>Date</th>
                                </tr>
                            </thead>

                            <tbody>

                            <?php if (!$recentScans): ?>

                                <tr>
                                    <td colspan="5" style="text-align:center;color:#64748b;padding:30px;">
                                        No scans yet.
                                    </td>
                                </tr>

                            <?php else: ?>

                                <?php foreach ($recentScans as $scan): ?>

                                    <tr>

                                        <td>
                                            <?= htmlspecialchars(strtoupper($scan['scan_type'])) ?>
                                        </td>

                                        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;">
                                            <?= htmlspecialchars($scan['input_value']) ?>
                                        </td>

                                        <td>
                                            <?= resultBadge($scan['result']) ?>
                                        </td>

                                        <td>
                                            <?= (int)$scan['risk_score'] ?>%
                                        </td>

                                        <td>
                                            <?= htmlspecialchars(date('M d, Y H:i', strtotime($scan['created_at']))) ?>
                                        </td>

                                    </tr>

                                <?php endforeach; ?>

                            <?php endif; ?>

                            </tbody>

                        </table>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">
                        <h3>Daily Safety Alert</h3>
                    </div>

                    <div class="pg-card-body">

                        <div class="pg-alert">

                            <div class="pg-alert-icon">
                                <i class="fa-solid fa-bell"></i>
                            </div>

                            <div>

                                <h4>Protect your OTP</h4>

                                <p>
                                    Never share your OTP, PIN, password,
                                    or verification code with anyone,
                                    even if they claim to be from your bank
                                    or e-wallet provider.
                                </p>

                            </div>

                        </div>

                        <div style="height:15px;"></div>

                        <div class="pg-alert">

                            <div class="pg-alert-icon">
                                <i class="fa-solid fa-lock"></i>
                            </div>

                            <div>

                                <h4>Verify before you trust</h4>

                                <p>
                                    If a message asks you to click a link,
                                    make a payment, or verify your account,
                                    scan it with PhishGuard first.
                                </p>

                            </div>

                        </div>

                    </div>

                </div>

            </section>

            <div class="pg-footer">
                PhishGuard • AI-Powered Phishing Detection System
            </div>

        </div>

    </main>

</div>

<script src="../assets/js/app.js"></script>

</body>
</html>