<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$pageTitle = 'Recent Scans';
$pageSubtitle = 'Your latest security scans from the last 48 hours';

require_once '../db.php';

$userId = $_SESSION['user_id'];

$userName = $_SESSION['full_name'] ?? 'User';
$userInitial = strtoupper(substr($userName, 0, 1));

$stmt = $pdo->prepare("
    SELECT id, scan_type, input_value, result, risk_score, explanation, source, created_at
    FROM scans
    WHERE user_id = ?
    AND created_at >= DATE_SUB(NOW(), INTERVAL 48 HOUR)
    ORDER BY created_at DESC
");

$stmt->execute([$userId]);
$scans = $stmt->fetchAll();

$total = count($scans);
$safe = 0;
$suspicious = 0;
$dangerous = 0;

foreach ($scans as $scan) {
    if ($scan['result'] === 'SAFE') {
        $safe++;
    } elseif ($scan['result'] === 'SUSPICIOUS') {
        $suspicious++;
    } elseif ($scan['result'] === 'DANGEROUS') {
        $dangerous++;
    }
}

function formatScanType($type)
{
    return match ($type) {
        'url' => 'URL Scan',
        'image' => 'Image Scan',
        'qr' => 'QR Scan',
        'sms' => 'SMS Lookup',
        default => ucfirst($type)
    };
}

function truncateInput($value, $length = 65)
{
    $value = trim($value);

    if (strlen($value) <= $length) {
        return $value;
    }

    return substr($value, 0, $length) . '...';
}

function timeAgo($date)
{
    $timestamp = strtotime($date);
    $difference = time() - $timestamp;

    if ($difference < 60) {
        return 'Just now';
    }

    if ($difference < 3600) {
        return floor($difference / 60) . ' min ago';
    }

    if ($difference < 86400) {
        return floor($difference / 3600) . ' hr ago';
    }

    return floor($difference / 86400) . ' day ago';
}

?>
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Recent Scans | PhishGuard</title>

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

</head>

<body>

<div class="pg-layout">

    <?php require_once 'includes/sidebar.php'; ?>

    <main class="pg-main">

        <?php require_once 'includes/topbar.php'; ?>

        <section class="pg-content">

            <div class="pg-hero">

                <div>

                    <div class="pg-eyebrow">
                        <i class="fa-solid fa-wave-square"></i>
                        48-HOUR SCAN TERMINAL
                    </div>

                    <h1>Recent Security Activity</h1>

                    <p>
                        Review links, images, QR codes, and SMS sender checks
                        analyzed by PhishGuard during the last 48 hours.
                    </p>

                </div>

                <a href="scanner.php" class="pg-btn">
                    <i class="fa-solid fa-plus"></i>
                    New Scan
                </a>

            </div>

            <div class="pg-stats">

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-layer-group"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">TOTAL SCANS</div>
                        <div class="pg-stat-value"><?= $total ?></div>
                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-circle-check"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">SAFE</div>
                        <div class="pg-stat-value"><?= $safe ?></div>
                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">SUSPICIOUS</div>
                        <div class="pg-stat-value"><?= $suspicious ?></div>
                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-circle-xmark"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">DANGEROUS</div>
                        <div class="pg-stat-value"><?= $dangerous ?></div>
                    </div>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>
                        <h3>48-Hour Scan Terminal</h3>
                        <span>Latest security analysis activity</span>
                    </div>

                    <a href="history.php" class="pg-btn pg-btn-secondary">
                        <i class="fa-solid fa-clock-rotate-left"></i>
                        Full History
                    </a>

                </div>

                <div class="pg-card-body">

                    <?php if (!$scans): ?>

                        <div class="pg-empty-state">

                            <div class="pg-empty-icon">
                                <i class="fa-solid fa-shield-halved"></i>
                            </div>

                            <h3>No Recent Scans</h3>

                            <p>
                                Your last 48 hours of security activity will
                                appear here after you perform a scan.
                            </p>

                            <a href="scanner.php" class="pg-btn">
                                <i class="fa-solid fa-radar"></i>
                                Start Scanning
                            </a>

                        </div>

                    <?php else: ?>

                        <div class="pg-table-wrap">

                            <table class="pg-table">

                                <thead>

                                    <tr>
                                        <th>TYPE</th>
                                        <th>INPUT</th>
                                        <th>RESULT</th>
                                        <th>RISK</th>
                                        <th>TIME</th>
                                    </tr>

                                </thead>

                                <tbody>

                                <?php foreach ($scans as $scan): ?>

                                    <?php

                                    $resultClass = strtolower($scan['result']);

                                    $icon = match ($scan['scan_type']) {
                                        'url' => 'fa-link',
                                        'image' => 'fa-image',
                                        'qr' => 'fa-qrcode',
                                        'sms' => 'fa-comment-sms',
                                        default => 'fa-shield-halved'
                                    };

                                    ?>

                                    <tr>

                                        <td>

                                            <div class="pg-table-type">

                                                <span class="pg-table-icon">
                                                    <i class="fa-solid <?= $icon ?>"></i>
                                                </span>

                                                <?= htmlspecialchars(formatScanType($scan['scan_type'])) ?>

                                            </div>

                                        </td>

                                        <td>

                                            <div
                                                class="pg-input-preview"
                                                title="<?= htmlspecialchars($scan['input_value']) ?>"
                                            >
                                                <?= htmlspecialchars(truncateInput($scan['input_value'])) ?>
                                            </div>

                                        </td>

                                        <td>

                                            <span class="pg-badge pg-badge-<?= $resultClass ?>">
                                                <?= htmlspecialchars($scan['result']) ?>
                                            </span>

                                        </td>

                                        <td>

                                            <strong>
                                                <?= (int)$scan['risk_score'] ?>%
                                            </strong>

                                        </td>

                                        <td>

                                            <span
                                                class="pg-time"
                                                title="<?= htmlspecialchars($scan['created_at']) ?>"
                                            >
                                                <?= htmlspecialchars(timeAgo($scan['created_at'])) ?>
                                            </span>

                                        </td>

                                    </tr>

                                <?php endforeach; ?>

                                </tbody>

                            </table>

                        </div>

                    <?php endif; ?>

                </div>

            </div>

        </section>

    </main>

</div>

<script src="../assets/js/app.js"></script>

</body>
</html>