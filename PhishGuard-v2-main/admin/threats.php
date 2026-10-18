<?php

session_start();

require_once '../db.php';

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: ../web/login.php');
    exit;
}

$pageTitle = 'Threat Monitor';
$pageSubtitle = 'Review and monitor reported security threats';

$userName = $_SESSION['full_name'] ?? 'Administrator';
$userInitial = strtoupper(substr($userName, 0, 1));

$search = trim($_GET['search'] ?? '');
$type = $_GET['type'] ?? '';
$result = $_GET['result'] ?? '';

$allowedTypes = ['url', 'phone', 'qr', 'image', 'sms'];
$allowedResults = ['SAFE', 'SUSPICIOUS', 'DANGEROUS'];

if (!in_array($type, $allowedTypes, true)) {
    $type = '';
}

if (!in_array($result, $allowedResults, true)) {
    $result = '';
}

$where = [];
$params = [];

if ($search !== '') {
    $where[] = "(threat_value LIKE ? OR source LIKE ?)";
    $params[] = '%' . $search . '%';
    $params[] = '%' . $search . '%';
}

if ($type !== '') {
    $where[] = "threat_type = ?";
    $params[] = $type;
}

if ($result !== '') {
    $where[] = "result = ?";
    $params[] = $result;
}

$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$totalThreats = (int)$pdo->query("
    SELECT COUNT(*) 
    FROM threat_reports
")->fetchColumn();

$dangerousThreats = (int)$pdo->query("
    SELECT COUNT(*) 
    FROM threat_reports
    WHERE result = 'DANGEROUS'
")->fetchColumn();

$suspiciousThreats = (int)$pdo->query("
    SELECT COUNT(*) 
    FROM threat_reports
    WHERE result = 'SUSPICIOUS'
")->fetchColumn();

$safeReports = (int)$pdo->query("
    SELECT COUNT(*) 
    FROM threat_reports
    WHERE result = 'SAFE'
")->fetchColumn();

$todayThreats = (int)$pdo->query("
    SELECT COUNT(*)
    FROM threat_reports
    WHERE DATE(created_at) = CURDATE()
")->fetchColumn();

$perPage = 10;
$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page - 1) * $perPage;

$countStmt = $pdo->prepare("
    SELECT COUNT(*)
    FROM threat_reports
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
    SELECT *
    FROM threat_reports
    $whereSql
    ORDER BY created_at DESC
    LIMIT $perPage OFFSET $offset
");

$stmt->execute($params);
$threats = $stmt->fetchAll();

$startRow = $totalFiltered > 0 ? $offset + 1 : 0;
$endRow = min($offset + $perPage, $totalFiltered);

$typeStats = $pdo->query("
    SELECT threat_type, COUNT(*) AS total
    FROM threat_reports
    GROUP BY threat_type
    ORDER BY total DESC
")->fetchAll();

function threatTypeLabel($type)
{
    return match ($type) {
        'url' => 'URL / Link',
        'phone' => 'Phone Number',
        'qr' => 'QR Code',
        'image' => 'Image',
        'sms' => 'SMS',
        default => ucfirst($type)
    };
}

function threatIcon($type)
{
    return match ($type) {
        'url' => 'fa-link',
        'phone' => 'fa-phone',
        'qr' => 'fa-qrcode',
        'image' => 'fa-image',
        'sms' => 'fa-comment-sms',
        default => 'fa-shield-halved'
    };
}

function truncateThreat($value, $length = 55)
{
    $value = trim($value);

    if (strlen($value) <= $length) {
        return $value;
    }

    return substr($value, 0, $length) . '...';
}

function formatThreatDate($date)
{
    return date('M d, Y • h:i A', strtotime($date));
}

function resultClass($result)
{
    return match ($result) {
        'SAFE' => 'pg-badge-safe',
        'SUSPICIOUS' => 'pg-badge-suspicious',
        'DANGEROUS' => 'pg-badge-dangerous',
        default => ''
    };
}

function sourceLabel($source)
{
    if (!$source) {
        return 'Unknown';
    }

    return $source;
}

function buildThreatPageUrl($pageNum, $queryBase)
{
    $queryBase['page'] = $pageNum;
    return 'threats.php?' . http_build_query($queryBase);
}

$queryBase = $_GET;
unset($queryBase['page']);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title><?= htmlspecialchars($pageTitle) ?> | PhishGuard</title>

    <link
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
        rel="stylesheet"
    >

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <style>
        .pg-threat-filter-grid {
            display: grid;
            grid-template-columns: 1.5fr 1fr 1fr auto;
            gap: 16px;
            align-items: end;
        }

        .pg-filter-label {
            display: block;
            margin-bottom: 7px;
            font-size: 11px;
            font-weight: 700;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: .5px;
        }

        .pg-filter-input {
            width: 100%;
            min-height: 44px;
            padding: 10px 13px;
            border: 1px solid #dbe3ec;
            border-radius: 10px;
            background: #ffffff;
            color: #172033;
            font-size: 13px;
            outline: none;
        }

        .pg-filter-input:focus {
            border-color: #38bdf8;
            box-shadow: 0 0 0 3px rgba(56, 189, 248, .12);
        }

        .pg-filter-actions {
            display: flex;
            gap: 8px;
        }

        .pg-primary-button,
        .pg-secondary-button {
            min-height: 44px;
            padding: 10px 15px;
            border-radius: 10px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            font-size: 12px;
            font-weight: 700;
            text-decoration: none;
            white-space: nowrap;
            cursor: pointer;
        }

        .pg-primary-button {
            border: 0;
            background: #0ea5e9;
            color: #ffffff;
        }

        .pg-primary-button:hover {
            background: #0284c7;
        }

        .pg-secondary-button {
            border: 1px solid #dbe3ec;
            background: #f8fafc;
            color: #475569;
        }

        .pg-secondary-button:hover {
            background: #eef2f7;
        }

        .pg-threat-type-icon {
            width: 34px;
            height: 34px;
            border-radius: 9px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #f1f5f9;
            color: #475569;
            margin-right: 9px;
            flex-shrink: 0;
        }

        .pg-threat-value {
            max-width: 420px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            display: inline-block;
            vertical-align: middle;
        }

        .pg-threat-stat-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }

        .pg-threat-stat {
            padding: 15px;
            border: 1px solid #e5eaf0;
            border-radius: 10px;
            background: #f8fafc;
        }

        .pg-threat-stat-label {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .5px;
            color: #64748b;
            margin-bottom: 5px;
        }

        .pg-threat-stat-value {
            font-size: 22px;
            font-weight: 800;
            color: #172033;
        }

        .pg-threat-type-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .pg-threat-type-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 15px;
        }

        .pg-threat-type-name {
            display: flex;
            align-items: center;
            gap: 9px;
            font-size: 12px;
            font-weight: 700;
            color: #334155;
        }

        .pg-threat-type-count {
            font-size: 12px;
            font-weight: 800;
            color: #0f172a;
        }

        /* ===== PAGINATION ===== */

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

        @media (max-width: 1100px) {
            .pg-threat-filter-grid {
                grid-template-columns: 1fr 1fr;
            }

            .pg-threat-stat-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 650px) {
            .pg-threat-filter-grid {
                grid-template-columns: 1fr;
            }

            .pg-filter-actions {
                width: 100%;
            }

            .pg-primary-button,
            .pg-secondary-button {
                flex: 1;
            }

            .pg-threat-value {
                max-width: 180px;
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
                        THREAT MONITOR
                    </div>

                    <h2>
                        Threat Reports
                    </h2>

                    <p>
                        Monitor reported phishing, scam, and suspicious activity detected by PhishGuard.
                    </p>
                </div>

                <div class="pg-admin-status">
                    <span class="pg-status-dot"></span>
                    Monitoring Active
                </div>

            </div>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat-card">
                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">TOTAL THREATS</span>
                        <strong><?= number_format($totalThreats) ?></strong>
                    </div>
                </div>

                <div class="pg-stat-card">
                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-calendar-day"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">TODAY</span>
                        <strong><?= number_format($todayThreats) ?></strong>
                    </div>
                </div>

                <div class="pg-stat-card">
                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-skull-crossbones"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">DANGEROUS</span>
                        <strong><?= number_format($dangerousThreats) ?></strong>
                    </div>
                </div>

                <div class="pg-stat-card">
                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-circle-exclamation"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">SUSPICIOUS</span>
                        <strong><?= number_format($suspiciousThreats) ?></strong>
                    </div>
                </div>

            </div>

            <div class="pg-admin-grid">

                <div class="pg-card">

                    <div class="pg-card-header">
                        <div>
                            <h3>Threat Distribution</h3>
                            <span>Current threat report statistics</span>
                        </div>
                    </div>

                    <div class="pg-card-body">

                        <div class="pg-threat-stat-grid">

                            <div class="pg-threat-stat">
                                <div class="pg-threat-stat-label">
                                    Dangerous
                                </div>

                                <div class="pg-threat-stat-value">
                                    <?= number_format($dangerousThreats) ?>
                                </div>
                            </div>

                            <div class="pg-threat-stat">
                                <div class="pg-threat-stat-label">
                                    Suspicious
                                </div>

                                <div class="pg-threat-stat-value">
                                    <?= number_format($suspiciousThreats) ?>
                                </div>
                            </div>

                            <div class="pg-threat-stat">
                                <div class="pg-threat-stat-label">
                                    Safe Reports
                                </div>

                                <div class="pg-threat-stat-value">
                                    <?= number_format($safeReports) ?>
                                </div>
                            </div>

                        </div>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">
                        <div>
                            <h3>Threat Types</h3>
                            <span>Reports grouped by category</span>
                        </div>
                    </div>

                    <div class="pg-card-body">

                        <div class="pg-threat-type-list">

                            <?php if ($typeStats): ?>

                                <?php foreach ($typeStats as $stat): ?>

                                    <div class="pg-threat-type-row">

                                        <div class="pg-threat-type-name">

                                            <span class="pg-threat-type-icon">
                                                <i class="fa-solid <?= htmlspecialchars(threatIcon($stat['threat_type'])) ?>"></i>
                                            </span>

                                            <?= htmlspecialchars(threatTypeLabel($stat['threat_type'])) ?>

                                        </div>

                                        <span class="pg-threat-type-count">
                                            <?= number_format($stat['total']) ?>
                                        </span>

                                    </div>

                                <?php endforeach; ?>

                            <?php else: ?>

                                <div class="pg-empty-state">
                                    No threat reports available.
                                </div>

                            <?php endif; ?>

                        </div>

                    </div>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>
                        <h3>Threat Report Filters</h3>
                        <span>Search and filter reported threats</span>
                    </div>

                    <div class="pg-time">
                        <?= number_format($totalFiltered) ?> result(s)
                    </div>

                </div>

                <div class="pg-card-body">

                    <form method="GET">

                        <div class="pg-threat-filter-grid">

                            <div>

                                <label class="pg-filter-label">
                                    Search
                                </label>

                                <input
                                    type="text"
                                    name="search"
                                    class="pg-filter-input"
                                    placeholder="Search threat value or source..."
                                    value="<?= htmlspecialchars($search) ?>"
                                >

                            </div>

                            <div>

                                <label class="pg-filter-label">
                                    Threat Type
                                </label>

                                <select
                                    name="type"
                                    class="pg-filter-input"
                                >
                                    <option value="">All Types</option>
                                    <option value="url" <?= $type === 'url' ? 'selected' : '' ?>>URL / Link</option>
                                    <option value="phone" <?= $type === 'phone' ? 'selected' : '' ?>>Phone Number</option>
                                    <option value="qr" <?= $type === 'qr' ? 'selected' : '' ?>>QR Code</option>
                                    <option value="image" <?= $type === 'image' ? 'selected' : '' ?>>Image</option>
                                    <option value="sms" <?= $type === 'sms' ? 'selected' : '' ?>>SMS</option>
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
                                    <option value="">All Results</option>
                                    <option value="SAFE" <?= $result === 'SAFE' ? 'selected' : '' ?>>SAFE</option>
                                    <option value="SUSPICIOUS" <?= $result === 'SUSPICIOUS' ? 'selected' : '' ?>>SUSPICIOUS</option>
                                    <option value="DANGEROUS" <?= $result === 'DANGEROUS' ? 'selected' : '' ?>>DANGEROUS</option>
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
                                    href="threats.php"
                                    class="pg-secondary-button"
                                >
                                    <i class="fa-solid fa-rotate-left"></i>
                                    Reset
                                </a>

                            </div>

                        </div>

                    </form>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>
                        <h3>Threat Reports</h3>
                        <span>
                            Showing <?= number_format($startRow) ?>&ndash;<?= number_format($endRow) ?>
                            of <?= number_format($totalFiltered) ?> report(s)
                        </span>
                    </div>

                    <div class="pg-time">
                        Page <?= $page ?> of <?= $totalPages ?>
                    </div>

                </div>

                <div class="pg-table-wrap">

                    <table class="pg-table">

                        <thead>

                            <tr>
                                <th>THREAT</th>
                                <th>TYPE</th>
                                <th>RESULT</th>
                                <th>RISK</th>
                                <th>SOURCE</th>
                                <th>DATE</th>
                            </tr>

                        </thead>

                        <tbody>

                        <?php if ($threats): ?>

                            <?php foreach ($threats as $threat): ?>

                                <tr>

                                    <td>

                                        <div style="display:flex;align-items:center;">

                                            <span class="pg-threat-type-icon">
                                                <i class="fa-solid <?= htmlspecialchars(threatIcon($threat['threat_type'])) ?>"></i>
                                            </span>

                                            <span
                                                class="pg-threat-value"
                                                title="<?= htmlspecialchars($threat['threat_value']) ?>"
                                            >
                                                <?= htmlspecialchars(truncateThreat($threat['threat_value'])) ?>
                                            </span>

                                        </div>

                                    </td>

                                    <td>
                                        <?= htmlspecialchars(threatTypeLabel($threat['threat_type'])) ?>
                                    </td>

                                    <td>
                                        <span class="pg-badge <?= htmlspecialchars(resultClass($threat['result'])) ?>">
                                            <?= htmlspecialchars($threat['result']) ?>
                                        </span>
                                    </td>

                                    <td>
                                        <strong>
                                            <?= number_format((int)$threat['risk_score']) ?>%
                                        </strong>
                                    </td>

                                    <td>
                                        <span class="pg-source-badge">
                                            <?= htmlspecialchars(sourceLabel($threat['source'])) ?>
                                        </span>
                                    </td>

                                    <td>
                                        <span class="pg-time">
                                            <?= htmlspecialchars(formatThreatDate($threat['created_at'])) ?>
                                        </span>
                                    </td>

                                </tr>

                            <?php endforeach; ?>

                        <?php else: ?>

                            <tr>

                                <td colspan="6">

                                    <div class="pg-empty-state">
                                        <i class="fa-solid fa-shield-halved"></i>
                                        <strong>No threat reports found.</strong>
                                        <span>
                                            Try changing your filters or wait for new threat activity.
                                        </span>
                                    </div>

                                </td>

                            </tr>

                        <?php endif; ?>

                        </tbody>

                    </table>

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
                                href="<?= htmlspecialchars(buildThreatPageUrl(max(1, $page - 1), $queryBase)) ?>"
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
                                echo '<a href="' . htmlspecialchars(buildThreatPageUrl(1, $queryBase)) . '" class="pg-page-btn">1</a>';
                                if ($startPage > 2) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                            }

                            for ($p = $startPage; $p <= $endPage; $p++) {
                                $active = $p === $page ? 'active' : '';
                                echo '<a href="' . htmlspecialchars(buildThreatPageUrl($p, $queryBase)) . '" class="pg-page-btn ' . $active . '">' . $p . '</a>';
                            }

                            if ($endPage < $totalPages) {
                                if ($endPage < $totalPages - 1) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                                echo '<a href="' . htmlspecialchars(buildThreatPageUrl($totalPages, $queryBase)) . '" class="pg-page-btn">' . $totalPages . '</a>';
                            }
                            ?>

                            <a
                                href="<?= htmlspecialchars(buildThreatPageUrl(min($totalPages, $page + 1), $queryBase)) ?>"
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