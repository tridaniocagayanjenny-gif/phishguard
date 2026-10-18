<?php

session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: ../web/login.php');
    exit;
}

require_once '../db.php';

$adminName = $_SESSION['full_name'] ?? 'Administrator';
$initial = strtoupper(substr($adminName, 0, 1));

$filterType = $_GET['type'] ?? '';
$filterResult = $_GET['result'] ?? '';
$search = trim($_GET['search'] ?? '');

$allowedTypes = ['url', 'image', 'qr', 'sms'];
$allowedResults = ['SAFE', 'SUSPICIOUS', 'DANGEROUS'];

$where = [];
$params = [];

if (in_array($filterType, $allowedTypes, true)) {
    $where[] = 'scans.scan_type = ?';
    $params[] = $filterType;
}

if (in_array($filterResult, $allowedResults, true)) {
    $where[] = 'scans.result = ?';
    $params[] = $filterResult;
}

if ($search !== '') {
    $where[] = '(
        scans.input_value LIKE ?
        OR users.full_name LIKE ?
        OR users.email LIKE ?
    )';

    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
}

$whereSql = $where
    ? 'WHERE ' . implode(' AND ', $where)
    : '';

$perPage = 20;
$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page - 1) * $perPage;

$countStmt = $pdo->prepare("
    SELECT COUNT(*)
    FROM scans
    LEFT JOIN users ON users.id = scans.user_id
    $whereSql
");
$countStmt->execute($params);
$totalFiltered = (int)$countStmt->fetchColumn();

$totalPages = max(1, (int)ceil($totalFiltered / $perPage));

if ($page > $totalPages) {
    $page = $totalPages;
    $offset = ($page - 1) * $perPage;
}

$stmt = $pdo->prepare("
    SELECT
        scans.id,
        scans.scan_type,
        scans.input_value,
        scans.result,
        scans.risk_score,
        scans.explanation,
        scans.source,
        scans.created_at,
        scans.app_client,
        users.full_name,
        users.email
    FROM scans
    LEFT JOIN users
        ON users.id = scans.user_id
    $whereSql
    ORDER BY scans.created_at DESC
    LIMIT $perPage OFFSET $offset
");

$stmt->execute($params);

$scans = $stmt->fetchAll();

$startRow = $totalFiltered > 0 ? $offset + 1 : 0;
$endRow = min($offset + $perPage, $totalFiltered);

$totalScans = (int)$pdo->query("
    SELECT COUNT(*)
    FROM scans
")->fetchColumn();

$safeCount = (int)$pdo->query("
    SELECT COUNT(*)
    FROM scans
    WHERE result = 'SAFE'
")->fetchColumn();

$suspiciousCount = (int)$pdo->query("
    SELECT COUNT(*)
    FROM scans
    WHERE result = 'SUSPICIOUS'
")->fetchColumn();

$dangerousCount = (int)$pdo->query("
    SELECT COUNT(*)
    FROM scans
    WHERE result = 'DANGEROUS'
")->fetchColumn();

$todayScans = (int)$pdo->query("
    SELECT COUNT(*)
    FROM scans
    WHERE created_at >= CURDATE()
")->fetchColumn();

$typeStats = $pdo->query("
    SELECT
        scan_type,
        COUNT(*) AS total
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

function truncateValue($value, $length = 55)
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

function resultClass($result)
{
    return strtolower($result);
}

function buildScanPageUrl($pageNum, $queryBase)
{
    $queryBase['page'] = $pageNum;
    return 'scans.php?' . http_build_query($queryBase);
}

$queryBase = $_GET;
unset($queryBase['page']);

?>
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Scan Monitor | PhishGuard</title>

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <style>
        .pg-pagination {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            padding: 16px 20px;
            border-top: 1px solid #e2e8f0;
            background: #ffffff;
        }

        .pg-pagination-info {
            font-size: 12px;
            color: #64748b;
        }

        .pg-pagination-info strong {
            color: #0f172a;
        }

        .pg-pagination-controls {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }

        .pg-page-btn {
            min-width: 36px;
            height: 36px;
            padding: 0 10px;
            border-radius: 9px;
            border: 1px solid #dbe3ec;
            background: #ffffff;
            color: #475569;
            font-size: 12px;
            font-weight: 700;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s ease;
        }

        .pg-page-btn:hover {
            background: #f0f9ff;
            color: #0284c7;
            border-color: #7dd3fc;
        }

        .pg-page-btn.active {
            background: #0ea5e9;
            color: #ffffff;
            border-color: #0ea5e9;
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.28);
        }

        .pg-page-btn.disabled {
            opacity: 0.4;
            pointer-events: none;
        }

        .pg-page-dots {
            color: #94a3b8;
            padding: 0 4px;
            font-weight: 700;
            user-select: none;
        }

        @media (max-width: 650px) {
            .pg-pagination {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>

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
                        <i class="fa-solid fa-magnifying-glass-chart"></i>
                        SCAN MONITOR
                    </div>

                    <h1>Security Scan Activity</h1>

                    <p>
                        Review URL, image, QR, and SMS security scans
                        performed across the PhishGuard platform.
                    </p>

                </div>

                <div class="pg-admin-status">

                    <div class="pg-status-dot"></div>

                    <div>
                        <strong>Monitoring Active</strong>
                        <span>Scan records are being monitored</span>
                    </div>

                </div>

            </div>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-radar"></i>
                    </div>

                    <div>

                        <div class="pg-stat-label">
                            TOTAL SCANS
                        </div>

                        <div class="pg-stat-value">
                            <?= $totalScans ?>
                        </div>

                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-calendar-day"></i>
                    </div>

                    <div>

                        <div class="pg-stat-label">
                            SCANS TODAY
                        </div>

                        <div class="pg-stat-value">
                            <?= $todayScans ?>
                        </div>

                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                    </div>

                    <div>

                        <div class="pg-stat-label">
                            SUSPICIOUS
                        </div>

                        <div class="pg-stat-value">
                            <?= $suspiciousCount ?>
                        </div>

                    </div>

                </div>

                <div class="pg-stat">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-skull-crossbones"></i>
                    </div>

                    <div>

                        <div class="pg-stat-label">
                            DANGEROUS
                        </div>

                        <div class="pg-stat-value">
                            <?= $dangerousCount ?>
                        </div>

                    </div>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>

                        <h3>
                            Scan Filters
                        </h3>

                        <span>
                            Search and filter security scan records
                        </span>

                    </div>

                    <i class="fa-solid fa-filter pg-card-header-icon"></i>

                </div>

                <div class="pg-card-body">

                    <form method="GET">

                        <div class="pg-scan-filter-grid">

                            <div>

                                <label class="pg-filter-label">
                                    Search
                                </label>

                                <input
                                    type="search"
                                    name="search"
                                    class="pg-filter-input"
                                    placeholder="Search URL, user, email, or scan value..."
                                    value="<?= htmlspecialchars($search) ?>"
                                >

                            </div>

                            <div>

                                <label class="pg-filter-label">
                                    Scan Type
                                </label>

                                <select
                                    name="type"
                                    class="pg-filter-input"
                                >

                                    <option value="">
                                        All Scan Types
                                    </option>

                                    <option
                                        value="url"
                                        <?= $filterType === 'url' ? 'selected' : '' ?>
                                    >
                                        URL / Link
                                    </option>

                                    <option
                                        value="image"
                                        <?= $filterType === 'image' ? 'selected' : '' ?>
                                    >
                                        Image / OCR
                                    </option>

                                    <option
                                        value="qr"
                                        <?= $filterType === 'qr' ? 'selected' : '' ?>
                                    >
                                        QR Code
                                    </option>

                                    <option
                                        value="sms"
                                        <?= $filterType === 'sms' ? 'selected' : '' ?>
                                    >
                                        SMS Lookup
                                    </option>

                                </select>

                            </div>

                            <div>

                                <label class="pg-filter-label">
                                    Result
                                </label>

                                <select
                                    name="result"
                                    class="pg-filter-input"
                                >

                                    <option value="">
                                        All Results
                                    </option>

                                    <option
                                        value="SAFE"
                                        <?= $filterResult === 'SAFE' ? 'selected' : '' ?>
                                    >
                                        Safe
                                    </option>

                                    <option
                                        value="SUSPICIOUS"
                                        <?= $filterResult === 'SUSPICIOUS' ? 'selected' : '' ?>
                                    >
                                        Suspicious
                                    </option>

                                    <option
                                        value="DANGEROUS"
                                        <?= $filterResult === 'DANGEROUS' ? 'selected' : '' ?>
                                    >
                                        Dangerous
                                    </option>

                                </select>

                            </div>

                            <div class="pg-filter-actions">

                                <button
                                    type="submit"
                                    class="pg-primary-button"
                                >
                                    <i class="fa-solid fa-filter"></i>
                                    Filter
                                </button>

                                <a
                                    href="scans.php"
                                    class="pg-secondary-button"
                                >
                                    <i class="fa-solid fa-rotate-left"></i>
                                    Clear
                                </a>

                            </div>

                        </div>

                    </form>

                </div>

            </div>

            <div class="pg-admin-grid">

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>

                            <h3>
                                Scan Result Summary
                            </h3>

                            <span>
                                Current security analysis results
                            </span>

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

                                <strong>
                                    <?= $safeCount ?>
                                </strong>

                            </div>

                            <div class="pg-threat-item">

                                <div class="pg-threat-label">
                                    <span class="pg-threat-dot suspicious"></span>
                                    SUSPICIOUS
                                </div>

                                <strong>
                                    <?= $suspiciousCount ?>
                                </strong>

                            </div>

                            <div class="pg-threat-item">

                                <div class="pg-threat-label">
                                    <span class="pg-threat-dot dangerous"></span>
                                    DANGEROUS
                                </div>

                                <strong>
                                    <?= $dangerousCount ?>
                                </strong>

                            </div>

                        </div>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>

                            <h3>
                                Scan Types
                            </h3>

                            <span>
                                Scanner usage
                            </span>

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
                                                <?= htmlspecialchars(
                                                    scanTypeLabel($stat['scan_type'])
                                                ) ?>
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

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>

                        <h3>
                            All Security Scans
                        </h3>

                        <span>
                            Showing <?= number_format($startRow) ?>&ndash;<?= number_format($endRow) ?>
                            of <?= number_format($totalFiltered) ?> scan record(s)
                        </span>

                    </div>

                    <div class="pg-live-indicator">
                        <span></span>
                        LIVE DATA
                    </div>

                </div>

                <div class="pg-card-body">

                    <?php if (!$scans): ?>

                        <div class="pg-empty-state">

                            <div class="pg-empty-icon">
                                <i class="fa-solid fa-radar"></i>
                            </div>

                            <h3>
                                No Scan Records Found
                            </h3>

                            <p>
                                No scans match the current search or filters.
                            </p>

                        </div>

                    <?php else: ?>

                        <div class="pg-table-wrap">

                            <table class="pg-table">

                                <thead>

                                    <tr>

                                        <th>ID</th>
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

                                <?php foreach ($scans as $scan): ?>

                                    <?php
                                    $result = resultClass($scan['result']);
                                    ?>

                                    <tr>

                                        <td>

                                            <strong>
                                                #<?= (int)$scan['id'] ?>
                                            </strong>

                                        </td>

                                        <td>

                                            <div class="pg-table-type">

                                                <span class="pg-table-icon">
                                                    <i class="fa-solid <?= scanIcon($scan['scan_type']) ?>"></i>
                                                </span>

                                                <?= htmlspecialchars(
                                                    scanTypeLabel($scan['scan_type'])
                                                ) ?>

                                            </div>

                                        </td>

                                        <td>

                                            <div class="pg-admin-user">

                                                <strong>
                                                    <?= htmlspecialchars(
                                                        $scan['full_name'] ?? 'Unknown User'
                                                    ) ?>
                                                </strong>

                                                <span>
                                                    <?= htmlspecialchars(
                                                        $scan['email'] ?? 'N/A'
                                                    ) ?>
                                                </span>

                                            </div>

                                        </td>

                                        <td>

                                            <div
                                                class="pg-input-preview"
                                                title="<?= htmlspecialchars($scan['input_value']) ?>"
                                            >
                                                <?= htmlspecialchars(
                                                    truncateValue(
                                                        $scan['input_value'],
                                                        55
                                                    )
                                                ) ?>
                                            </div>

                                        </td>

                                        <td>

                                            <span class="pg-badge pg-badge-<?= $result ?>">
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
                                                <?php
                                                $client = $scan['app_client'] ?? null;

                                                if ($client === 'android_app') {
                                                    echo 'APP';
                                                } elseif ($client === 'mobile_browser') {
                                                    echo 'MOBILE';
                                                } elseif ($client === 'desktop_browser') {
                                                    echo 'WEB';
                                                } else {
                                                    echo strtoupper($scan['source'] ?? 'UNKNOWN');
                                                }
                                                ?>
                                            </span>

                                        </td>

                                        <td>

                                            <span class="pg-time">
                                                <?= htmlspecialchars(
                                                    formatDate($scan['created_at'])
                                                ) ?>
                                            </span>

                                        </td>

                                    </tr>

                                <?php endforeach; ?>

                                </tbody>

                            </table>

                        </div>

                    <?php endif; ?>

                </div>

                <?php if ($totalPages > 1): ?>

                    <div class="pg-pagination">

                        <div class="pg-pagination-info">
                            Page <strong><?= $page ?></strong>
                            of <strong><?= $totalPages ?></strong>
                            &nbsp;•&nbsp;
                            <?= number_format($startRow) ?>&ndash;<?= number_format($endRow) ?>
                            of <?= number_format($totalFiltered) ?>
                        </div>

                        <div class="pg-pagination-controls">

                            <a
                                href="<?= htmlspecialchars(buildScanPageUrl(max(1, $page - 1), $queryBase)) ?>"
                                class="pg-page-btn <?= $page <= 1 ? 'disabled' : '' ?>"
                                title="Previous page"
                            >
                                <i class="fa-solid fa-chevron-left"></i>
                            </a>

                            <?php
                            $range = 2;
                            $startPage = max(1, $page - $range);
                            $endPage = min($totalPages, $page + $range);

                            if ($startPage > 1) {
                                echo '<a href="' . htmlspecialchars(buildScanPageUrl(1, $queryBase)) . '" class="pg-page-btn">1</a>';
                                if ($startPage > 2) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                            }

                            for ($p = $startPage; $p <= $endPage; $p++) {
                                $active = $p === $page ? 'active' : '';
                                echo '<a href="' . htmlspecialchars(buildScanPageUrl($p, $queryBase)) . '" class="pg-page-btn ' . $active . '">' . $p . '</a>';
                            }

                            if ($endPage < $totalPages) {
                                if ($endPage < $totalPages - 1) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                                echo '<a href="' . htmlspecialchars(buildScanPageUrl($totalPages, $queryBase)) . '" class="pg-page-btn">' . $totalPages . '</a>';
                            }
                            ?>

                            <a
                                href="<?= htmlspecialchars(buildScanPageUrl(min($totalPages, $page + 1), $queryBase)) ?>"
                                class="pg-page-btn <?= $page >= $totalPages ? 'disabled' : '' ?>"
                                title="Next page"
                            >
                                <i class="fa-solid fa-chevron-right"></i>
                            </a>

                        </div>

                    </div>

                <?php endif; ?>

            </div>

        </section>

    </main>

</div>

<script src="../assets/js/app.js"></script>

</body>
</html>