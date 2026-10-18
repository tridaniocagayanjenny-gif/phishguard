<?php

session_start();

require_once "../config.php";
require_once "../db.php";

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header("Location: ../web/login.php");
    exit;
}

$pageTitle = 'Feedback Review';
$pageSubtitle = 'Review user feedback to improve PhishGuard detection';

$userName = $_SESSION['full_name'] ?? 'Administrator';
$userInitial = strtoupper(substr($userName, 0, 1));

$message = '';
$messageType = '';

$adminId = (int) $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'], $_POST['feedback_id'])) {

    $feedbackId = (int) $_POST['feedback_id'];
    $action     = $_POST['action'];

    if ($feedbackId > 0 && in_array($action, ['approve', 'reject'], true)) {

        $stmt = $pdo->prepare("SELECT * FROM scan_feedback WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $feedbackId]);
        $fb = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($fb) {

            $status = $action === 'approve' ? 'approved' : 'rejected';

            $pdo->prepare("
                UPDATE scan_feedback
                SET status = :status, reviewed_by = :admin, reviewed_at = NOW()
                WHERE id = :id
            ")->execute([
                ':status' => $status,
                ':admin'  => $adminId,
                ':id'     => $feedbackId,
            ]);

            if ($action === 'approve' && $fb['user_verdict'] === 'SAFE') {

                $urlHash = hash('sha256', strtolower(trim($fb['url'])));

                $pdo->prepare("
                    INSERT INTO detection_overrides
                    (url, url_hash, verdict, reason, created_by, created_at)
                    VALUES (:url, :hash, 'SAFE', :reason, :admin, NOW())
                    ON DUPLICATE KEY UPDATE
                        verdict = 'SAFE',
                        reason = VALUES(reason),
                        created_by = VALUES(created_by),
                        created_at = NOW()
                ")->execute([
                    ':url'    => $fb['url'],
                    ':hash'   => $urlHash,
                    ':reason' => 'Approved safe by admin (feedback #' . $feedbackId . ')',
                    ':admin'  => $adminId,
                ]);
            }

            $message = 'Feedback #' . $feedbackId . ' ' . $status . '.';
            $messageType = 'success';
        }
    }
}

$perPage = 20;
$page = max(1, (int)($_GET['page'] ?? 1));
$offset = ($page - 1) * $perPage;

$filter = $_GET['filter'] ?? 'pending';
if (!in_array($filter, ['pending', 'approved', 'rejected', 'all'], true)) {
    $filter = 'pending';
}

$search = trim($_GET['search'] ?? '');

$where = [];
$params = [];

if ($filter !== 'all') {
    $where[] = "f.status = :status";
    $params[':status'] = $filter;
}

if ($search !== '') {
    $where[] = "(f.url LIKE :search OR f.user_note LIKE :search OR u.full_name LIKE :search)";
    $params[':search'] = '%' . $search . '%';
}

$whereSql = $where ? " WHERE " . implode(" AND ", $where) : "";

$countStmt = $pdo->prepare("
    SELECT COUNT(*)
    FROM scan_feedback f
    LEFT JOIN users u ON u.id = f.user_id
    $whereSql
");
$countStmt->execute($params);
$totalRows = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($totalRows / $perPage));

if ($page > $totalPages) {
    $page = $totalPages;
    $offset = ($page - 1) * $perPage;
}

$listStmt = $pdo->prepare("
    SELECT
        f.*,
        u.full_name AS user_name,
        u.email AS user_email
    FROM scan_feedback f
    LEFT JOIN users u ON u.id = f.user_id
    $whereSql
    ORDER BY f.created_at DESC
    LIMIT $perPage OFFSET $offset
");
$listStmt->execute($params);
$rows = $listStmt->fetchAll(PDO::FETCH_ASSOC);

$totalPending  = (int)$pdo->query("SELECT COUNT(*) FROM scan_feedback WHERE status = 'pending'")->fetchColumn();
$totalApproved = (int)$pdo->query("SELECT COUNT(*) FROM scan_feedback WHERE status = 'approved'")->fetchColumn();
$totalRejected = (int)$pdo->query("SELECT COUNT(*) FROM scan_feedback WHERE status = 'rejected'")->fetchColumn();

$startRow = $totalRows > 0 ? $offset + 1 : 0;
$endRow = min($offset + $perPage, $totalRows);

function feedbackVerdictClass($verdict)
{
    $verdict = strtolower($verdict);
    if ($verdict === 'safe')        return 'pg-badge-safe';
    if ($verdict === 'suspicious')  return 'pg-badge-suspicious';
    if ($verdict === 'dangerous')   return 'pg-badge-dangerous';
    if ($verdict === 'pending')     return 'pg-badge-info';
    if ($verdict === 'approved')    return 'pg-badge-safe';
    if ($verdict === 'rejected')    return 'pg-badge-dangerous';
    return 'pg-badge-info';
}

function formatFeedbackDate($date)
{
    if (!$date) return '—';
    return date('M d, Y h:i A', strtotime($date));
}

$queryBase = $_GET;
unset($queryBase['page']);

function buildFeedbackPageUrl($pageNum, $queryBase)
{
    $queryBase['page'] = $pageNum;
    return 'feedback_review.php?' . http_build_query($queryBase);
}

?>
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title><?= htmlspecialchars($pageTitle) ?> | PhishGuard</title>

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <style>
        .pg-feedback-card {
            background: #101c33;
            border: 1px solid rgba(148, 163, 184, 0.15);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
            transition: all 0.15s ease;
        }

        .pg-feedback-card:hover {
            border-color: rgba(56, 189, 248, 0.35);
        }

        .pg-feedback-badges {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            margin-bottom: 10px;
        }

        .pg-feedback-arrow {
            color: #64748b;
            font-weight: 700;
        }

        .pg-feedback-url {
            font-family: 'Consolas', monospace;
            font-size: 12px;
            word-break: break-all;
            color: #93c5fd;
            padding: 8px 10px;
            background: rgba(2, 6, 23, 0.5);
            border-radius: 6px;
            margin: 8px 0;
        }

        .pg-feedback-note {
            font-size: 12px;
            color: #cbd5e1;
            background: rgba(56, 189, 248, 0.06);
            border-left: 3px solid #38bdf8;
            padding: 10px 12px;
            border-radius: 6px;
            margin: 10px 0;
            line-height: 1.55;
        }

        .pg-feedback-meta {
            font-size: 11px;
            color: #64748b;
            margin-top: 8px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .pg-feedback-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid rgba(148, 163, 184, 0.10);
        }

        .pg-feedback-actions button {
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid transparent;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
        }

        .pg-feedback-actions .approve {
            background: rgba(34, 197, 94, 0.15);
            color: #86efac;
            border-color: rgba(34, 197, 94, 0.35);
        }

        .pg-feedback-actions .approve:hover {
            background: rgba(34, 197, 94, 0.28);
            color: #bbf7d0;
        }

        .pg-feedback-actions .reject {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border-color: rgba(239, 68, 68, 0.35);
        }

        .pg-feedback-actions .reject:hover {
            background: rgba(239, 68, 68, 0.28);
            color: #fecaca;
        }

        .pg-feedback-status {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 6px;
            margin-top: 8px;
        }

        .pg-feedback-status.approved {
            background: rgba(34, 197, 94, 0.15);
            color: #86efac;
        }

        .pg-feedback-status.rejected {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
        }

        .pg-user-message {
            padding: 12px 16px;
            border-radius: 10px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 16px;
        }

        .pg-user-message.success {
            background: rgba(34, 197, 94, 0.08);
            border: 1px solid rgba(34, 197, 94, 0.25);
            color: #86efac;
        }

        .pg-user-message.error {
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #fca5a5;
        }

        .pg-filter-tabs {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            padding: 12px 18px 0;
        }

        .pg-filter-tab {
            padding: 8px 14px;
            border-radius: 8px 8px 0 0;
            background: rgba(148, 163, 184, 0.08);
            color: #94a3b8;
            font-size: 12px;
            font-weight: 700;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
            border-bottom: 2px solid transparent;
        }

        .pg-filter-tab:hover {
            background: rgba(148, 163, 184, 0.15);
            color: #e2e8f0;
        }

        .pg-filter-tab.active {
            background: rgba(56, 189, 248, 0.10);
            color: #38bdf8;
            border-bottom-color: #38bdf8;
        }

        .pg-filter-tab .count {
            background: rgba(148, 163, 184, 0.2);
            color: inherit;
            padding: 2px 7px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: 800;
        }

        .pg-filter-tab.active .count {
            background: rgba(56, 189, 248, 0.25);
        }

        .pg-pagination {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            padding: 14px 18px;
            border-top: 1px solid rgba(148, 163, 184, 0.12);
        }

        .pg-pagination-info {
            font-size: 12px;
            color: #94a3b8;
        }

        .pg-pagination-info strong {
            color: #e2e8f0;
        }

        .pg-pagination-controls {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }

        .pg-page-btn {
            min-width: 34px;
            height: 34px;
            padding: 0 10px;
            border-radius: 8px;
            border: 1px solid rgba(148, 163, 184, 0.18);
            background: rgba(15, 27, 48, 0.6);
            color: #cbd5e1;
            font-size: 12px;
            font-weight: 700;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s ease;
        }

        .pg-page-btn:hover {
            background: rgba(56, 189, 248, 0.10);
            color: #38bdf8;
            border-color: rgba(56, 189, 248, 0.35);
        }

        .pg-page-btn.active {
            background: linear-gradient(135deg, #2563eb, #38bdf8);
            color: #fff;
            border-color: transparent;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.28);
        }

        .pg-page-btn.disabled {
            opacity: 0.35;
            pointer-events: none;
        }

        .pg-page-dots {
            color: #64748b;
            padding: 0 4px;
            font-weight: 700;
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
                        <i class="fa-solid fa-clipboard-check"></i>
                        FEEDBACK REVIEW
                    </div>

                    <h2>User Feedback</h2>

                    <p>
                        Review user feedback to improve PhishGuard detection accuracy.
                    </p>

                </div>

            </div>

            <?php if ($message !== ''): ?>
                <div class="pg-user-message <?= $messageType === 'success' ? 'success' : 'error' ?>">
                    <i class="fa-solid <?= $messageType === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation' ?>"></i>
                    <span><?= htmlspecialchars($message) ?></span>
                </div>
            <?php endif; ?>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat-card">
                    <div class="pg-stat-icon" style="background:rgba(245,158,11,0.12);color:#f59e0b;">
                        <i class="fa-solid fa-clock"></i>
                    </div>
                    <div>
                        <span class="pg-stat-label">Pending</span>
                        <strong><?= number_format($totalPending) ?></strong>
                    </div>
                </div>

                <div class="pg-stat-card">
                    <div class="pg-stat-icon" style="background:rgba(34,197,94,0.12);color:#22c55e;">
                        <i class="fa-solid fa-circle-check"></i>
                    </div>
                    <div>
                        <span class="pg-stat-label">Approved</span>
                        <strong><?= number_format($totalApproved) ?></strong>
                    </div>
                </div>

                <div class="pg-stat-card">
                    <div class="pg-stat-icon" style="background:rgba(239,68,68,0.12);color:#ef4444;">
                        <i class="fa-solid fa-circle-xmark"></i>
                    </div>
                    <div>
                        <span class="pg-stat-label">Rejected</span>
                        <strong><?= number_format($totalRejected) ?></strong>
                    </div>
                </div>

            </div>

            <div class="pg-card">

                <div class="pg-filter-tabs">

                    <a
                        href="feedback_review.php?filter=pending"
                        class="pg-filter-tab <?= $filter === 'pending' ? 'active' : '' ?>"
                    >
                        <i class="fa-solid fa-clock"></i>
                        Pending
                        <span class="count"><?= $totalPending ?></span>
                    </a>

                    <a
                        href="feedback_review.php?filter=approved"
                        class="pg-filter-tab <?= $filter === 'approved' ? 'active' : '' ?>"
                    >
                        <i class="fa-solid fa-check"></i>
                        Approved
                        <span class="count"><?= $totalApproved ?></span>
                    </a>

                    <a
                        href="feedback_review.php?filter=rejected"
                        class="pg-filter-tab <?= $filter === 'rejected' ? 'active' : '' ?>"
                    >
                        <i class="fa-solid fa-xmark"></i>
                        Rejected
                        <span class="count"><?= $totalRejected ?></span>
                    </a>

                    <a
                        href="feedback_review.php?filter=all"
                        class="pg-filter-tab <?= $filter === 'all' ? 'active' : '' ?>"
                    >
                        <i class="fa-solid fa-list"></i>
                        All
                        <span class="count"><?= $totalPending + $totalApproved + $totalRejected ?></span>
                    </a>

                </div>

                <div class="pg-card-body">

                    <form method="GET" class="pg-user-filter-grid">

                        <input type="hidden" name="filter" value="<?= htmlspecialchars($filter) ?>">

                        <div>
                            <label class="pg-filter-label">Search</label>
                            <input
                                type="text"
                                name="search"
                                class="pg-filter-input"
                                placeholder="URL, note, or user"
                                value="<?= htmlspecialchars($search) ?>"
                            >
                        </div>

                        <div class="pg-filter-actions">

                            <button type="submit" class="pg-primary-button">
                                <i class="fa-solid fa-magnifying-glass"></i>
                                Search
                            </button>

                            <a href="feedback_review.php?filter=<?= htmlspecialchars($filter) ?>" class="pg-secondary-button">
                                <i class="fa-solid fa-rotate-left"></i>
                                Reset
                            </a>

                        </div>

                    </form>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>
                        <h3>
                            <i class="fa-solid fa-comments"></i>
                            Feedback Entries
                        </h3>
                        <p>
                            Showing <?= number_format($startRow) ?>–<?= number_format($endRow) ?>
                            of <?= number_format($totalRows) ?> entr<?= $totalRows === 1 ? 'y' : 'ies' ?>
                        </p>
                    </div>

                </div>

                <div class="pg-card-body">

                    <?php if (!$rows): ?>

                        <div class="pg-empty-state">
                            <i class="fa-solid fa-inbox"></i>
                            <strong>No feedback found</strong>
                            <span>There is no feedback for this filter.</span>
                        </div>

                    <?php else: ?>

                        <?php foreach ($rows as $row): ?>

                            <div class="pg-feedback-card">

                                <div class="pg-feedback-badges">

                                    <span class="pg-badge <?= feedbackVerdictClass($row['detected_result']) ?>">
                                        <i class="fa-solid fa-robot"></i>
                                        Detected: <?= htmlspecialchars($row['detected_result']) ?>
                                    </span>

                                    <span class="pg-feedback-arrow">→</span>

                                    <span class="pg-badge <?= feedbackVerdictClass($row['user_verdict']) ?>">
                                        <i class="fa-solid fa-user"></i>
                                        User: <?= htmlspecialchars($row['user_verdict']) ?>
                                    </span>

                                    <span class="pg-badge <?= feedbackVerdictClass($row['status']) ?>">
                                        <?= strtoupper(htmlspecialchars($row['status'])) ?>
                                    </span>

                                </div>

                                <div class="pg-feedback-url">
                                    <?= htmlspecialchars($row['url']) ?>
                                </div>

                                <?php if (!empty($row['user_note'])): ?>
                                    <div class="pg-feedback-note">
                                        <strong>User note:</strong> <?= htmlspecialchars($row['user_note']) ?>
                                    </div>
                                <?php endif; ?>

                                <div class="pg-feedback-meta">
                                    <span><i class="fa-solid fa-hashtag"></i> #<?= (int)$row['id'] ?></span>
                                    <span><i class="fa-solid fa-user"></i> <?= htmlspecialchars($row['user_name'] ?? 'Unknown') ?></span>
                                    <span><i class="fa-solid fa-calendar"></i> <?= htmlspecialchars(formatFeedbackDate($row['created_at'])) ?></span>
                                    <?php if ($row['detected_score'] > 0): ?>
                                        <span><i class="fa-solid fa-gauge"></i> Score: <?= (int)$row['detected_score'] ?>%</span>
                                    <?php endif; ?>
                                </div>

                                <?php if ($row['status'] === 'pending'): ?>

                                    <div class="pg-feedback-actions">

                                        <form method="POST" style="display:inline;">
                                            <input type="hidden" name="feedback_id" value="<?= (int)$row['id'] ?>">
                                            <button type="submit" name="action" value="approve" class="approve">
                                                <i class="fa-solid fa-check"></i>
                                                Approve — Mark as Safe
                                            </button>
                                        </form>

                                        <form method="POST" style="display:inline;">
                                            <input type="hidden" name="feedback_id" value="<?= (int)$row['id'] ?>">
                                            <button type="submit" name="action" value="reject" class="reject">
                                                <i class="fa-solid fa-xmark"></i>
                                                Reject — Keep Detection
                                            </button>
                                        </form>

                                    </div>

                                <?php elseif ($row['status'] === 'approved'): ?>

                                    <div class="pg-feedback-status approved">
                                        <i class="fa-solid fa-circle-check"></i>
                                        Approved
                                        <?php if (!empty($row['reviewed_at'])): ?>
                                            on <?= htmlspecialchars(formatFeedbackDate($row['reviewed_at'])) ?>
                                        <?php endif; ?>
                                    </div>

                                <?php elseif ($row['status'] === 'rejected'): ?>

                                    <div class="pg-feedback-status rejected">
                                        <i class="fa-solid fa-circle-xmark"></i>
                                        Rejected
                                        <?php if (!empty($row['reviewed_at'])): ?>
                                            on <?= htmlspecialchars(formatFeedbackDate($row['reviewed_at'])) ?>
                                        <?php endif; ?>
                                    </div>

                                <?php endif; ?>

                            </div>

                        <?php endforeach; ?>

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
                                href="<?= htmlspecialchars(buildFeedbackPageUrl(max(1, $page - 1), $queryBase)) ?>"
                                class="pg-page-btn <?= $page <= 1 ? 'disabled' : '' ?>"
                            >
                                <i class="fa-solid fa-chevron-left"></i>
                            </a>

                            <?php
                            $range = 2;
                            $startPage = max(1, $page - $range);
                            $endPage = min($totalPages, $page + $range);

                            if ($startPage > 1) {
                                echo '<a href="' . htmlspecialchars(buildFeedbackPageUrl(1, $queryBase)) . '" class="pg-page-btn">1</a>';
                                if ($startPage > 2) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                            }

                            for ($p = $startPage; $p <= $endPage; $p++) {
                                $active = $p === $page ? 'active' : '';
                                echo '<a href="' . htmlspecialchars(buildFeedbackPageUrl($p, $queryBase)) . '" class="pg-page-btn ' . $active . '">' . $p . '</a>';
                            }

                            if ($endPage < $totalPages) {
                                if ($endPage < $totalPages - 1) {
                                    echo '<span class="pg-page-dots">…</span>';
                                }
                                echo '<a href="' . htmlspecialchars(buildFeedbackPageUrl($totalPages, $queryBase)) . '" class="pg-page-btn">' . $totalPages . '</a>';
                            }
                            ?>

                            <a
                                href="<?= htmlspecialchars(buildFeedbackPageUrl(min($totalPages, $page + 1), $queryBase)) ?>"
                                class="pg-page-btn <?= $page >= $totalPages ? 'disabled' : '' ?>"
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