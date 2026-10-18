<?php

session_start();

require_once "../db.php";

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header("Location: ../web/login.php");
    exit;
}

$pageTitle = 'Activity Log';
$pageSubtitle = 'Review system activity and security events';

$adminName = $_SESSION['full_name'] ?? 'Administrator';
$adminInitial = strtoupper(substr($adminName, 0, 1));

$search = trim($_GET['search'] ?? '');
$source = $_GET['source'] ?? '';
$date = $_GET['date'] ?? '';

$where = [];
$params = [];

if ($search !== '') {
    $where[] = "(
        a.action LIKE :search
        OR a.description LIKE :search
        OR a.ip_address LIKE :search
    )";
    $params[':search'] = '%' . $search . '%';
}

if (in_array($source, ['web', 'mobile'], true)) {
    $where[] = "a.source = :source";
    $params[':source'] = $source;
}

if ($date !== '') {
    $where[] = "DATE(a.created_at) = :activity_date";
    $params[':activity_date'] = $date;
}

$whereSql = $where
    ? 'WHERE ' . implode(' AND ', $where)
    : '';

$perPage = 20;
$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page - 1) * $perPage;

$countStmt = $pdo->prepare("
    SELECT COUNT(*)
    FROM activity_logs a
    LEFT JOIN users u ON u.id = a.user_id
    $whereSql
");
$countStmt->execute($params);
$totalFiltered = (int) $countStmt->fetchColumn();

$totalPages = max(1, (int) ceil($totalFiltered / $perPage));

if ($page > $totalPages) {
    $page = $totalPages;
    $offset = ($page - 1) * $perPage;
}

$stmt = $pdo->prepare("
    SELECT
        a.id,
        a.user_id,
        a.action,
        a.description,
        a.ip_address,
        a.source,
        a.created_at,
        u.full_name,
        u.email
    FROM activity_logs a
    LEFT JOIN users u ON u.id = a.user_id
    $whereSql
    ORDER BY a.created_at DESC
    LIMIT $perPage OFFSET $offset
");

$stmt->execute($params);

$activities = $stmt->fetchAll();

$startRow = $totalFiltered > 0 ? $offset + 1 : 0;
$endRow = min($offset + $perPage, $totalFiltered);

$totalActivities = (int) $pdo->query("
    SELECT COUNT(*)
    FROM activity_logs
")->fetchColumn();

$todayActivities = (int) $pdo->query("
    SELECT COUNT(*)
    FROM activity_logs
    WHERE DATE(created_at) = CURDATE()
")->fetchColumn();

$webActivities = (int) $pdo->query("
    SELECT COUNT(*)
    FROM activity_logs
    WHERE source = 'web'
")->fetchColumn();

$mobileActivities = (int) $pdo->query("
    SELECT COUNT(*)
    FROM activity_logs
    WHERE source = 'mobile'
")->fetchColumn();

function activityIcon($action)
{
    $action = strtolower($action);

    if (strpos($action, 'login') !== false) {
        return 'fa-right-to-bracket';
    }

    if (strpos($action, 'logout') !== false) {
        return 'fa-right-from-bracket';
    }

    if (strpos($action, 'scan') !== false) {
        return 'fa-magnifying-glass';
    }

    if (
        strpos($action, 'threat') !== false ||
        strpos($action, 'danger') !== false
    ) {
        return 'fa-triangle-exclamation';
    }

    if (
        strpos($action, 'user') !== false ||
        strpos($action, 'account') !== false
    ) {
        return 'fa-user';
    }

    if (
        strpos($action, 'alert') !== false ||
        strpos($action, 'safety') !== false
    ) {
        return 'fa-bell';
    }

    return 'fa-clock-rotate-left';
}

function activityClass($action)
{
    $action = strtolower($action);

    if (
        strpos($action, 'threat') !== false ||
        strpos($action, 'danger') !== false
    ) {
        return 'dangerous';
    }

    if (
        strpos($action, 'scan') !== false ||
        strpos($action, 'login') !== false ||
        strpos($action, 'user') !== false
    ) {
        return 'info';
    }

    if (strpos($action, 'logout') !== false) {
        return 'warning';
    }

    return 'default';
}

function formatActivityAction($action)
{
    return ucwords(str_replace(['_', '-'], ' ', $action));
}

function formatActivityTime($datetime)
{
    $time = strtotime($datetime);

    if (!$time) {
        return $datetime;
    }

    return date('M d, Y h:i A', $time);
}

function buildActivityPageUrl($pageNum, $queryBase)
{
    $queryBase['page'] = $pageNum;
    return 'activity.php?' . http_build_query($queryBase);
}

$queryBase = $_GET;
unset($queryBase['page']);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title><?= htmlspecialchars($pageTitle) ?> - PhishGuard</title>

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <style>
        .pg-activity-filter-grid {
            display: grid;
            grid-template-columns: 1.6fr 1fr 1fr auto;
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

        .pg-activity-icon {
            width: 34px;
            height: 34px;
            border-radius: 9px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            margin-right: 10px;
        }

        .pg-activity-icon.info {
            background: #e0f2fe;
            color: #0284c7;
        }

        .pg-activity-icon.dangerous {
            background: #fee2e2;
            color: #dc2626;
        }

        .pg-activity-icon.warning {
            background: #fef3c7;
            color: #d97706;
        }

        .pg-activity-icon.default {
            background: #f1f5f9;
            color: #64748b;
        }

        .pg-activity-action {
            display: flex;
            align-items: center;
            font-weight: 700;
            color: #5081eb81;
            font-size: 12px;
        }

        .pg-activity-description {
            margin-top: 3px;
            color: #5a9df3;
            font-size: 11px;
            line-height: 1.5;
            max-width: 420px;
        }

        .pg-activity-user strong {
            display: block;
            color: #3259ad;
            font-size: 12px;
        }

        .pg-activity-user span {
            display: block;
            color: #94a3b8;
            font-size: 11px;
            margin-top: 2px;
        }

        .pg-ip-address {
            font-family: monospace;
            font-size: 11px;
            color: #6f92c2;
        }

        .pg-source-badge.web {
            background: #e0f2fe;
            color: #0369a1;
        }

        .pg-source-badge.mobile {
            background: #ede9fe;
            color: #6d28d9;
        }

        .pg-empty-state {
            padding: 50px 20px;
            text-align: center;
            color: #64748b;
        }

        .pg-empty-state i {
            font-size: 32px;
            margin-bottom: 12px;
            color: #94a3b8;
        }

        .pg-empty-state strong {
            display: block;
            color: #334155;
            margin-bottom: 5px;
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
            .pg-activity-filter-grid {
                grid-template-columns: 1fr 1fr;
            }
        }

        @media (max-width: 650px) {
            .pg-activity-filter-grid {
                grid-template-columns: 1fr;
            }

            .pg-filter-actions {
                width: 100%;
            }

            .pg-primary-button,
            .pg-secondary-button {
                flex: 1;
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
                        <i class="fa-solid fa-clock-rotate-left"></i>
                        SYSTEM ACTIVITY
                    </div>

                    <h2>
                        Activity Log
                    </h2>

                    <p>
                        Monitor user activity, scanner events, and administrative actions across PhishGuard.
                    </p>
                </div>

                <div class="pg-hero-status">
                    <span class="pg-status-dot"></span>
                    Live Monitoring
                </div>

            </div>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-list-check"></i>
                    </div>

                    <div>
                        <span>Total Activities</span>
                        <strong><?= number_format($totalActivities) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-calendar-day"></i>
                    </div>

                    <div>
                        <span>Today</span>
                        <strong><?= number_format($todayActivities) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-globe"></i>
                    </div>

                    <div>
                        <span>Web Activity</span>
                        <strong><?= number_format($webActivities) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-mobile-screen-button"></i>
                    </div>

                    <div>
                        <span>Mobile Activity</span>
                        <strong><?= number_format($mobileActivities) ?></strong>
                    </div>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>
                        <h3>
                            <i class="fa-solid fa-filter"></i>
                            Activity Filters
                        </h3>

                        <span>
                            Search and filter recorded system events
                        </span>
                    </div>

                </div>

                <div class="pg-card-body">

                    <form method="GET">

                        <div class="pg-activity-filter-grid">

                            <div>
                                <label class="pg-filter-label">
                                    Search
                                </label>

                                <input
                                    type="text"
                                    name="search"
                                    class="pg-filter-input"
                                    placeholder="Action, description, or IP address"
                                    value="<?= htmlspecialchars($search) ?>"
                                >
                            </div>

                            <div>
                                <label class="pg-filter-label">
                                    Source
                                </label>

                                <select
                                    name="source"
                                    class="pg-filter-input"
                                >
                                    <option value="">All Sources</option>

                                    <option
                                        value="web"
                                        <?= $source === 'web' ? 'selected' : '' ?>
                                    >
                                        Web
                                    </option>

                                    <option
                                        value="mobile"
                                        <?= $source === 'mobile' ? 'selected' : '' ?>
                                    >
                                        Mobile
                                    </option>
                                </select>
                            </div>

                            <div>
                                <label class="pg-filter-label">
                                    Date
                                </label>

                                <input
                                    type="date"
                                    name="date"
                                    class="pg-filter-input"
                                    value="<?= htmlspecialchars($date) ?>"
                                >
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
                                    href="activity.php"
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
                        <h3>
                            <i class="fa-solid fa-list"></i>
                            Recent System Activity
                        </h3>

                        <span>
                            Showing <?= number_format($startRow) ?>&ndash;<?= number_format($endRow) ?>
                            of <?= number_format($totalFiltered) ?> recorded event(s)
                        </span>
                    </div>

                    <div class="pg-card-header-status">
                        <span class="pg-status-dot"></span>
                        Activity Tracking
                    </div>

                </div>

                <div class="pg-table-wrap">

                    <?php if (!$activities): ?>

                        <div class="pg-empty-state">

                            <i class="fa-solid fa-clock-rotate-left"></i>

                            <strong>
                                No activity records found
                            </strong>

                            <span>
                                No system activity matches your current filters.
                            </span>

                        </div>

                    <?php else: ?>

                        <table class="pg-table">

                            <thead>
                                <tr>
                                    <th>Activity</th>
                                    <th>User</th>
                                    <th>Source</th>
                                    <th>IP Address</th>
                                    <th>Date & Time</th>
                                </tr>
                            </thead>

                            <tbody>

                            <?php foreach ($activities as $activity): ?>

                                <?php
                                $activityType = activityClass($activity['action']);
                                $icon = activityIcon($activity['action']);
                                ?>

                                <tr>

                                    <td>

                                        <div class="pg-activity-action">

                                            <span class="pg-activity-icon <?= htmlspecialchars($activityType) ?>">
                                                <i class="fa-solid <?= htmlspecialchars($icon) ?>"></i>
                                            </span>

                                            <div>

                                                <div>
                                                    <?= htmlspecialchars(
                                                        formatActivityAction($activity['action'])
                                                    ) ?>
                                                </div>

                                                <?php if (!empty($activity['description'])): ?>

                                                    <div class="pg-activity-description">
                                                        <?= htmlspecialchars($activity['description']) ?>
                                                    </div>

                                                <?php endif; ?>

                                            </div>

                                        </div>

                                    </td>

                                    <td>

                                        <div class="pg-activity-user">

                                            <strong>
                                                <?= htmlspecialchars(
                                                    $activity['full_name'] ?? 'Unknown User'
                                                ) ?>
                                            </strong>

                                            <?php if (!empty($activity['email'])): ?>

                                                <span>
                                                    <?= htmlspecialchars($activity['email']) ?>
                                                </span>

                                            <?php endif; ?>

                                        </div>

                                    </td>

                                    <td>

                                        <span class="pg-source-badge <?= htmlspecialchars($activity['source']) ?>">
                                            <?php if ($activity['source'] === 'mobile'): ?>
                                                <i class="fa-solid fa-mobile-screen-button"></i>
                                            <?php else: ?>
                                                <i class="fa-solid fa-globe"></i>
                                            <?php endif; ?>

                                            <?= htmlspecialchars(ucfirst($activity['source'])) ?>
                                        </span>

                                    </td>

                                    <td>

                                        <span class="pg-ip-address">
                                            <?= htmlspecialchars(
                                                $activity['ip_address'] ?: 'N/A'
                                            ) ?>
                                        </span>

                                    </td>

                                    <td>

                                        <span class="pg-time">
                                            <?= htmlspecialchars(
                                                formatActivityTime($activity['created_at'])
                                            ) ?>
                                        </span>

                                    </td>

                                </tr>

                            <?php endforeach; ?>

                            </tbody>

                        </table>

                    <?php endif; ?>

                </div>

                <?php if ($totalPages > 1): ?>

                    <div class="pg-pagination">

                        <div class="pg-pagination-info">
                            Page <strong><?= $page ?></strong>
                            of <strong><?= $totalPages ?></strong>
                        </div>

                        <div class="pg-pagination-controls">

                            <a
                                href="<?= htmlspecialchars(buildActivityPageUrl(max(1, $page - 1), $queryBase)) ?>"
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
                                echo '<a href="' . htmlspecialchars(buildActivityPageUrl(1, $queryBase)) . '" class="pg-page-btn">1</a>';
                                if ($startPage > 2) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                            }

                            for ($p = $startPage; $p <= $endPage; $p++) {
                                $active = $p === $page ? 'active' : '';
                                echo '<a href="' . htmlspecialchars(buildActivityPageUrl($p, $queryBase)) . '" class="pg-page-btn ' . $active . '">' . $p . '</a>';
                            }

                            if ($endPage < $totalPages) {
                                if ($endPage < $totalPages - 1) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                                echo '<a href="' . htmlspecialchars(buildActivityPageUrl($totalPages, $queryBase)) . '" class="pg-page-btn">' . $totalPages . '</a>';
                            }
                            ?>

                            <a
                                href="<?= htmlspecialchars(buildActivityPageUrl(min($totalPages, $page + 1), $queryBase)) ?>"
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