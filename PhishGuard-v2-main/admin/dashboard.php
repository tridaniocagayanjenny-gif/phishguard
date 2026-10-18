<?php

session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: ../web/login.php');
    exit;
}
$pageTitle = 'Admin Dashboard';
$pageSubtitle = 'Monitor PhishGuard security activity and system status';

require_once '../db.php';

$adminName = $_SESSION['full_name'] ?? 'Administrator';
$initial = strtoupper(substr($adminName, 0, 1));

$userCount = (int)$pdo->query("
    SELECT COUNT(*) FROM users
")->fetchColumn();

$scanCount = (int)$pdo->query("
    SELECT COUNT(*) FROM scans
")->fetchColumn();

$safeCount = (int)$pdo->query("
    SELECT COUNT(*) FROM scans
    WHERE result = 'SAFE'
")->fetchColumn();

$suspiciousCount = (int)$pdo->query("
    SELECT COUNT(*) FROM scans
    WHERE result = 'SUSPICIOUS'
")->fetchColumn();

$dangerousCount = (int)$pdo->query("
    SELECT COUNT(*) FROM scans
    WHERE result = 'DANGEROUS'
")->fetchColumn();

$todayScans = (int)$pdo->query("
    SELECT COUNT(*) FROM scans
    WHERE created_at >= CURDATE()
")->fetchColumn();

$recentScans = $pdo->query("
    SELECT
        scans.id,
        scans.scan_type,
        scans.input_value,
        scans.result,
        scans.risk_score,
        scans.source,
        scans.created_at,
        users.full_name,
        users.email
    FROM scans
    LEFT JOIN users ON users.id = scans.user_id
    ORDER BY scans.created_at DESC
    LIMIT 12
")->fetchAll();

$recentUsers = $pdo->query("
    SELECT id, full_name, email, role, created_at
    FROM users
    ORDER BY created_at DESC
    LIMIT 8
")->fetchAll();

$typeStats = $pdo->query("
    SELECT scan_type, COUNT(*) AS total
    FROM scans
    GROUP BY scan_type
    ORDER BY total DESC
")->fetchAll();

$alertCount = (int)$pdo->query("
    SELECT COUNT(*)
    FROM safety_alerts
    WHERE is_active = 1
")->fetchColumn();

function scanTypeLabel($type)
{
    return match ($type) {
        'url' => 'URL / Link',
        'image' => 'Image / OCR',
        'qr' => 'QR Code',
        'sms' => 'SMS Lookup',
        default => ucfirst($type)
    };
}

function scanIcon($type)
{
    return match ($type) {
        'url' => 'fa-link',
        'image' => 'fa-image',
        'qr' => 'fa-qrcode',
        'sms' => 'fa-comment-sms',
        default => 'fa-shield-halved'
    };
}

function truncateValue($value, $length = 48)
{
    $value = trim($value);

    if (strlen($value) <= $length) {
        return $value;
    }

    return substr($value, 0, $length) . '...';
}

function formatDate($date)
{
    return date('M d, Y • h:i A', strtotime($date));
}

$dangerRate = $scanCount > 0
    ? round(($dangerousCount / $scanCount) * 100, 1)
    : 0;

$suspiciousRate = $scanCount > 0
    ? round(($suspiciousCount / $scanCount) * 100, 1)
    : 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Admin Dashboard | PhishGuard</title>

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

    <?php require_once "includes/sidebar.php"; ?>

    <main class="pg-main">

        <?php require_once "includes/topbar.php"; ?>

        <section class="pg-content">

            <div class="pg-admin-hero">

                <div>

                    <div class="pg-eyebrow">
                        <i class="fa-solid fa-shield-halved"></i>
                        ADMIN SECURITY CENTER
                    </div>

                    <h1>System Overview</h1>

                    <p>
                        Monitor users, scan activity, threat levels, and
                        security alerts across the PhishGuard platform.
                    </p>

                </div>

                <div class="pg-admin-status">

                    <div class="pg-status-dot"></div>

                    <div>
                        <strong>All Systems Operational</strong>
                        <span>PhishGuard services are running</span>
                    </div>

                </div>

            </div>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-users"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">REGISTERED USERS</div>
                        <div class="pg-stat-value">
                            <?= $userCount ?>
                        </div>
                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-radar"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">TOTAL SCANS</div>
                        <div class="pg-stat-value">
                            <?= $scanCount ?>
                        </div>
                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-calendar-day"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">SCANS TODAY</div>
                        <div class="pg-stat-value">
                            <?= $todayScans ?>
                        </div>
                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-bell"></i>
                    </div>

                    <div>
                        <div class="pg-stat-label">ACTIVE ALERTS</div>
                        <div class="pg-stat-value">
                            <?= $alertCount ?>
                        </div>
                    </div>

                </div>

            </div>

            <div class="pg-admin-grid">

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>Threat Distribution</h3>
                            <span>Current scan result overview</span>
                        </div>

                        <i class="fa-solid fa-chart-pie pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-threat-summary">

                            <div class="pg-threat-item">

                                <div class="pg-threat-label">
                                    <span class="pg-threat-dot safe"></span>
                                    SAFE
                                </div>

                                <strong><?= $safeCount ?></strong>

                            </div>

                            <div class="pg-threat-item">

                                <div class="pg-threat-label">
                                    <span class="pg-threat-dot suspicious"></span>
                                    SUSPICIOUS
                                </div>

                                <strong><?= $suspiciousCount ?></strong>

                            </div>

                            <div class="pg-threat-item">

                                <div class="pg-threat-label">
                                    <span class="pg-threat-dot dangerous"></span>
                                    DANGEROUS
                                </div>

                                <strong><?= $dangerousCount ?></strong>

                            </div>

                        </div>

                        <div class="pg-threat-bars">

                            <div class="pg-admin-bar-row">

                                <div>
                                    <span>Safe</span>
                                    <strong>
                                        <?= $scanCount > 0 ? round(($safeCount / $scanCount) * 100, 1) : 0 ?>%
                                    </strong>
                                </div>

                                <div class="pg-admin-bar">
                                    <span
                                        style="width:<?= $scanCount > 0 ? ($safeCount / $scanCount) * 100 : 0 ?>%;"
                                    ></span>
                                </div>

                            </div>

                            <div class="pg-admin-bar-row">

                                <div>
                                    <span>Suspicious</span>
                                    <strong><?= $suspiciousRate ?>%</strong>
                                </div>

                                <div class="pg-admin-bar">
                                    <span
                                        style="width:<?= $suspiciousRate ?>%;"
                                    ></span>
                                </div>

                            </div>

                            <div class="pg-admin-bar-row">

                                <div>
                                    <span>Dangerous</span>
                                    <strong><?= $dangerRate ?>%</strong>
                                </div>

                                <div class="pg-admin-bar">
                                    <span
                                        style="width:<?= $dangerRate ?>%;"
                                    ></span>
                                </div>

                            </div>

                        </div>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>Scan Types</h3>
                            <span>Platform usage by scanner</span>
                        </div>

                        <i class="fa-solid fa-layer-group pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-scan-type-list">

                            <?php if (!$typeStats): ?>

                                <div class="pg-admin-empty">
                                    No scan activity yet.
                                </div>

                            <?php else: ?>

                                <?php foreach ($typeStats as $stat): ?>

                                    <div class="pg-scan-type-row">

                                        <div class="pg-scan-type-name">

                                            <span class="pg-table-icon">
                                                <i class="fa-solid <?= scanIcon($stat['scan_type']) ?>"></i>
                                            </span>

                                            <span>
                                                <?= htmlspecialchars(scanTypeLabel($stat['scan_type'])) ?>
                                            </span>

                                        </div>

                                        <strong>
                                            <?= (int)$stat['total'] ?>
                                        </strong>

                                    </div>

                                <?php endforeach; ?>

                            <?php endif; ?>

                        </div>

                    </div>

                </div>

            </div>

            <div class="pg-card" id="scan-monitor">

                <div class="pg-card-header">

                    <div>
                        <h3>Latest Scan Activity</h3>
                        <span>Most recent security analysis across all users</span>
                    </div>

                    <div class="pg-live-indicator">
                        <span></span>
                        LIVE DATA
                    </div>

                </div>

                <div class="pg-card-body">

                    <?php if (!$recentScans): ?>

                        <div class="pg-empty-state">

                            <div class="pg-empty-icon">
                                <i class="fa-solid fa-radar"></i>
                            </div>

                            <h3>No Scan Activity</h3>

                            <p>
                                Scan records will appear here when users
                                analyze suspicious content.
                            </p>

                        </div>

                    <?php else: ?>

                        <div class="pg-table-wrap">

                            <table class="pg-table">

                                <thead>

                                    <tr>
                                        <th>TYPE</th>
                                        <th>USER</th>
                                        <th>INPUT</th>
                                        <th>RESULT</th>
                                        <th>RISK</th>
                                        <th>SOURCE</th>
                                        <th>DATE</th>
                                    </tr>

                                </thead>

                                <tbody>

                                <?php foreach ($recentScans as $scan): ?>

                                    <?php
                                    $resultClass = strtolower($scan['result']);
                                    ?>

                                    <tr>

                                        <td>

                                            <div class="pg-table-type">

                                                <span class="pg-table-icon">
                                                    <i class="fa-solid <?= scanIcon($scan['scan_type']) ?>"></i>
                                                </span>

                                                <?= htmlspecialchars(scanTypeLabel($scan['scan_type'])) ?>

                                            </div>

                                        </td>

                                        <td>

                                            <div class="pg-admin-user">

                                                <strong>
                                                    <?= htmlspecialchars($scan['full_name'] ?? 'Unknown User') ?>
                                                </strong>

                                                <span>
                                                    <?= htmlspecialchars($scan['email'] ?? 'N/A') ?>
                                                </span>

                                            </div>

                                        </td>

                                        <td>

                                            <div
                                                class="pg-input-preview"
                                                title="<?= htmlspecialchars($scan['input_value']) ?>"
                                            >
                                                <?= htmlspecialchars(truncateValue($scan['input_value'])) ?>
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

                                            <span class="pg-source-badge">
                                                <?= htmlspecialchars(strtoupper($scan['source'])) ?>
                                            </span>

                                        </td>

                                        <td>

                                            <span class="pg-time">
                                                <?= htmlspecialchars(formatDate($scan['created_at'])) ?>
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

            <div class="pg-admin-grid">

                <div class="pg-card" id="users">

                    <div class="pg-card-header">

                        <div>
                            <h3>Recent Users</h3>
                            <span>Latest registered accounts</span>
                        </div>

                        <i class="fa-solid fa-users pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-user-list">

                            <?php foreach ($recentUsers as $user): ?>

                                <div class="pg-user-row">

                                    <div class="pg-user-mini-avatar">
                                        <?= htmlspecialchars(strtoupper(substr($user['full_name'], 0, 1))) ?>
                                    </div>

                                    <div class="pg-user-info">

                                        <strong>
                                            <?= htmlspecialchars($user['full_name']) ?>
                                        </strong>

                                        <span>
                                            <?= htmlspecialchars($user['email']) ?>
                                        </span>

                                    </div>

                                    <span class="pg-role-badge">
                                        <?= htmlspecialchars(strtoupper($user['role'])) ?>
                                    </span>

                                </div>

                            <?php endforeach; ?>

                            <?php if (!$recentUsers): ?>

                                <div class="pg-admin-empty">
                                    No registered users yet.
                                </div>

                            <?php endif; ?>

                        </div>

                    </div>

                </div>

                <div class="pg-card" id="threats">

                    <div class="pg-card-header">

                        <div>
                            <h3>Threat Monitor</h3>
                            <span>Security status summary</span>
                        </div>

                        <i class="fa-solid fa-triangle-exclamation pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-threat-monitor">

                            <div class="pg-threat-monitor-item">

                                <div class="pg-threat-monitor-icon safe">
                                    <i class="fa-solid fa-check"></i>
                                </div>

                                <div>
                                    <strong>Safe Scans</strong>
                                    <span><?= $safeCount ?> total detections</span>
                                </div>

                            </div>

                            <div class="pg-threat-monitor-item">

                                <div class="pg-threat-monitor-icon suspicious">
                                    <i class="fa-solid fa-exclamation"></i>
                                </div>

                                <div>
                                    <strong>Suspicious Scans</strong>
                                    <span><?= $suspiciousCount ?> require attention</span>
                                </div>

                            </div>

                            <div class="pg-threat-monitor-item">

                                <div class="pg-threat-monitor-icon dangerous">
                                    <i class="fa-solid fa-xmark"></i>
                                </div>

                                <div>
                                    <strong>Dangerous Scans</strong>
                                    <span><?= $dangerousCount ?> high-risk detections</span>
                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>

            <div class="pg-card" id="alerts">

                <div class="pg-card-header">

                    <div>
                        <h3>Safety Alert Status</h3>
                        <span>Current user-facing security alerts</span>
                    </div>

                    <i class="fa-solid fa-bell pg-card-header-icon"></i>

                </div>

                <div class="pg-card-body">

                    <div class="pg-alert-status">

                        <div class="pg-alert-status-icon">
                            <i class="fa-solid fa-bell"></i>
                        </div>

                        <div>

                            <strong>
                                <?= $alertCount ?> Active Safety Alert<?= $alertCount === 1 ? '' : 's' ?>
                            </strong>

                            <span>
                                These alerts can be displayed to users
                                through the PhishGuard safety center.
                            </span>

                        </div>

                    </div>

                </div>

            </div>

        </section>

    </main>

</div>

<script src="../assets/js/app.js"></script>

</body>
</html>