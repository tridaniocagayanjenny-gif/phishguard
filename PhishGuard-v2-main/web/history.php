<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require_once '../config.php';
require_once '../db.php';

$userName = $_SESSION['full_name'] ?? 'User';
$userInitial = strtoupper(substr($userName, 0, 1));

$pageTitle = 'Scan History';
$pageSubtitle = 'Review and manage your complete scan history';

$typeFilter = isset($_GET['type']) ? trim($_GET['type']) : '';
$resultFilter = isset($_GET['result']) ? trim($_GET['result']) : '';
$search = isset($_GET['search']) ? trim($_GET['search']) : '';

/* View mode: 'all' shows every matching record, otherwise 10 latest */
$viewAll = isset($_GET['view']) && $_GET['view'] === 'all';

$allowedTypes = [
    'url',
    'image',
    'qr',
    'sms'
];

$allowedResults = [
    'SAFE',
    'SUSPICIOUS',
    'DANGEROUS'
];

$conditions = [
    'user_id = :user_id'
];

$params = [
    ':user_id' => (int) $_SESSION['user_id']
];

if ($typeFilter !== '' && in_array($typeFilter, $allowedTypes, true)) {

    $conditions[] = 'scan_type = :scan_type';

    $params[':scan_type'] = $typeFilter;
}

if ($resultFilter !== '' && in_array($resultFilter, $allowedResults, true)) {

    $conditions[] = 'result = :result';

    $params[':result'] = $resultFilter;
}

if ($search !== '') {

    $conditions[] = '(
        input_value LIKE :search
        OR explanation LIKE :search
        OR result LIKE :search
        OR scan_type LIKE :search
    )';

    $params[':search'] = '%' . $search . '%';
}

$where = implode(' AND ', $conditions);

try {

    $statsStmt = $pdo->prepare("
        SELECT
            COUNT(*) AS total_scans,
            SUM(CASE WHEN scan_type = 'url' THEN 1 ELSE 0 END) AS total_urls,
            SUM(CASE WHEN scan_type = 'qr' THEN 1 ELSE 0 END) AS total_qr,
            SUM(CASE WHEN scan_type = 'image' THEN 1 ELSE 0 END) AS total_images,
            SUM(CASE WHEN scan_type = 'sms' THEN 1 ELSE 0 END) AS total_sms
        FROM scans
        WHERE user_id = :user_id
    ");

    $statsStmt->execute([
        ':user_id' => (int) $_SESSION['user_id']
    ]);

    $stats = $statsStmt->fetch();

    $totalScans = (int) ($stats['total_scans'] ?? 0);
    $totalUrls = (int) ($stats['total_urls'] ?? 0);
    $totalQr = (int) ($stats['total_qr'] ?? 0);
    $totalImages = (int) ($stats['total_images'] ?? 0);
    $totalSms = (int) ($stats['total_sms'] ?? 0);

    /* Count total matching the current filters (for View All hint) */
    $countStmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM scans
        WHERE {$where}
    ");
    $countStmt->execute($params);
    $filteredCount = (int) $countStmt->fetchColumn();

    /* Limit to 10 unless View All */
    $limitSql = $viewAll ? '' : ' LIMIT 10';

    $stmt = $pdo->prepare("
        SELECT
            id,
            scan_type,
            input_value,
            result,
            risk_score,
            explanation,
            source,
            created_at
        FROM scans
        WHERE {$where}
        ORDER BY created_at DESC
        {$limitSql}
    ");

    $stmt->execute($params);

    $scans = $stmt->fetchAll();

} catch (PDOException $e) {

    $totalScans = 0;
    $totalUrls = 0;
    $totalQr = 0;
    $totalImages = 0;
    $totalSms = 0;
    $filteredCount = 0;
    $scans = [];
}

function formatScanType($type)
{
    switch ($type) {
        case 'url':
            return 'URL';

        case 'image':
            return 'Image';

        case 'qr':
            return 'QR Code';

        case 'sms':
            return 'SMS';

        default:
            return ucfirst($type);
    }
}

function getScanIcon($type)
{
    switch ($type) {
        case 'url':
            return 'fa-link';

        case 'image':
            return 'fa-image';

        case 'qr':
            return 'fa-qrcode';

        case 'sms':
            return 'fa-comment-sms';

        default:
            return 'fa-shield-halved';
    }
}

function formatInputValue($value, $type)
{
    $value = trim((string) $value);

    if ($value === '') {
        return 'No input recorded';
    }

    if ($type === 'image') {
        return basename($value);
    }

    if (strlen($value) > 80) {
        return substr($value, 0, 80) . '...';
    }

    return $value;
}

function formatDateTime($date)
{
    if (!$date) {
        return '—';
    }

    $timestamp = strtotime($date);

    if (!$timestamp) {
        return htmlspecialchars($date);
    }

    return date('M d, Y', $timestamp) . '<br><span>' . date('h:i A', $timestamp) . '</span>';
}

function resultClass($result)
{
    switch ($result) {
        case 'SAFE':
            return 'safe';

        case 'SUSPICIOUS':
            return 'suspicious';

        case 'DANGEROUS':
            return 'dangerous';

        default:
            return 'unknown';
    }
}

function riskClass($score)
{
    $score = (int) $score;

    if ($score >= 70) {
        return 'high';
    }

    if ($score >= 40) {
        return 'medium';
    }

    return 'low';
}

?>
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Scan History - PhishGuard</title>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
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

        <section class="pg-content">

            <div class="pg-page-header">

                <div>

                    <h2 class="pg-section-title">
                        Scan History
                    </h2>

                    <p class="pg-section-description">
                        Review and manage all scans associated with your account.
                    </p>

                </div>

            </div>

            <div class="pg-history-stats pg-history-stats-5">

                <div class="pg-history-stat-card">

                    <div class="pg-history-stat-icon blue">
                        <i class="fa-solid fa-chart-column"></i>
                    </div>

                    <div>

                        <span class="pg-history-stat-label">
                            Total Scans
                        </span>

                        <strong>
                            <?= number_format($totalScans) ?>
                        </strong>

                    </div>

                </div>

                <div class="pg-history-stat-card">

                    <div class="pg-history-stat-icon cyan">
                        <i class="fa-solid fa-link"></i>
                    </div>

                    <div>

                        <span class="pg-history-stat-label">
                            URL Scans
                        </span>

                        <strong>
                            <?= number_format($totalUrls) ?>
                        </strong>

                    </div>

                </div>

                <div class="pg-history-stat-card">

                    <div class="pg-history-stat-icon purple">
                        <i class="fa-solid fa-qrcode"></i>
                    </div>

                    <div>

                        <span class="pg-history-stat-label">
                            QR Scans
                        </span>

                        <strong>
                            <?= number_format($totalQr) ?>
                        </strong>

                    </div>

                </div>

                <div class="pg-history-stat-card">

                    <div class="pg-history-stat-icon orange">
                        <i class="fa-solid fa-image"></i>
                    </div>

                    <div>

                        <span class="pg-history-stat-label">
                            Image Scans
                        </span>

                        <strong>
                            <?= number_format($totalImages) ?>
                        </strong>

                    </div>

                </div>

                <div class="pg-history-stat-card">

                    <div class="pg-history-stat-icon green">
                        <i class="fa-solid fa-comment-sms"></i>
                    </div>

                    <div>

                        <span class="pg-history-stat-label">
                            SMS Scans
                        </span>

                        <strong>
                            <?= number_format($totalSms) ?>
                        </strong>

                    </div>

                </div>

            </div>

            <div class="pg-history-filter-card">

                <form
                    method="GET"
                    action="history.php"
                    class="pg-history-filter"
                >

                    <div class="pg-history-search">

                        <label for="historySearch">
                            Search
                        </label>

                        <div class="pg-input-icon">

                            <i class="fa-solid fa-magnifying-glass"></i>

                            <input
                                type="text"
                                id="historySearch"
                                name="search"
                                value="<?= htmlspecialchars($search) ?>"
                                placeholder="Search URL, result, explanation..."
                            >

                        </div>

                    </div>

                    <div class="pg-history-filter-field">

                        <label for="historyType">
                            Scan Type
                        </label>

                        <select
                            id="historyType"
                            name="type"
                        >

                            <option value="">
                                All Types
                            </option>

                            <option
                                value="url"
                                <?= $typeFilter === 'url' ? 'selected' : '' ?>
                            >
                                URL
                            </option>

                            <option
                                value="qr"
                                <?= $typeFilter === 'qr' ? 'selected' : '' ?>
                            >
                                QR Code
                            </option>

                            <option
                                value="image"
                                <?= $typeFilter === 'image' ? 'selected' : '' ?>
                            >
                                Image
                            </option>

                            <option
                                value="sms"
                                <?= $typeFilter === 'sms' ? 'selected' : '' ?>
                            >
                                SMS
                            </option>

                        </select>

                    </div>

                    <div class="pg-history-filter-field">

                        <label for="historyResult">
                            Result
                        </label>

                        <select
                            id="historyResult"
                            name="result"
                        >

                            <option value="">
                                All Results
                            </option>

                            <option
                                value="SAFE"
                                <?= $resultFilter === 'SAFE' ? 'selected' : '' ?>
                            >
                                Safe
                            </option>

                            <option
                                value="SUSPICIOUS"
                                <?= $resultFilter === 'SUSPICIOUS' ? 'selected' : '' ?>
                            >
                                Suspicious
                            </option>

                            <option
                                value="DANGEROUS"
                                <?= $resultFilter === 'DANGEROUS' ? 'selected' : '' ?>
                            >
                                Dangerous
                            </option>

                        </select>

                    </div>

                    <div class="pg-history-filter-actions">

                        <button
                            type="submit"
                            class="pg-primary-btn"
                        >
                            <i class="fa-solid fa-filter"></i>
                            Filter
                        </button>

                        <?php if ($search !== '' || $typeFilter !== '' || $resultFilter !== ''): ?>

                            <a
                                href="history.php"
                                class="pg-secondary-btn"
                            >
                                <i class="fa-solid fa-rotate-left"></i>
                                Reset
                            </a>

                        <?php endif; ?>

                    </div>

                </form>

            </div>

            <div class="pg-history-card">

                <div class="pg-history-card-header">

                    <div>

                        <h3>
                            Scan Records
                        </h3>

                        <p>
                            <?php if (!$viewAll && $filteredCount > count($scans)): ?>
                                Showing <?= number_format(count($scans)) ?> of <?= number_format($filteredCount) ?> records
                            <?php else: ?>
                                <?= number_format(count($scans)) ?> record<?= count($scans) === 1 ? '' : 's' ?> displayed
                            <?php endif; ?>
                        </p>

                    </div>

                    <div class="pg-history-card-actions">

                        <?php if (!$viewAll && $filteredCount > 10): ?>

                            <a
                                href="?<?= htmlspecialchars(http_build_query(array_filter([
                                    'search' => $search,
                                    'type'   => $typeFilter,
                                    'result' => $resultFilter,
                                    'view'   => 'all',
                                ]))) ?>"
                                class="pg-view-all-btn"
                            >
                                <i class="fa-solid fa-list"></i>
                                View All
                            </a>

                        <?php elseif ($viewAll): ?>

                            <a
                                href="?<?= htmlspecialchars(http_build_query(array_filter([
                                    'search' => $search,
                                    'type'   => $typeFilter,
                                    'result' => $resultFilter,
                                ]))) ?>"
                                class="pg-view-all-btn pg-show-less-btn"
                            >
                                <i class="fa-solid fa-chevron-up"></i>
                                Show Less
                            </a>

                        <?php endif; ?>

                        <?php if ($scans): ?>

                            <button
                                type="button"
                                class="pg-danger-btn"
                                id="deleteAllHistory"
                            >
                                <i class="fa-solid fa-trash"></i>
                                Delete All
                            </button>

                        <?php endif; ?>

                    </div>

                </div>

                <?php if ($scans): ?>

                    <div class="pg-history-table-wrapper">

                        <table class="pg-history-table">

                            <thead>

                                <tr>

                                    <th>TYPE</th>

                                    <th>INPUT / SUBJECT</th>

                                    <th>RESULT</th>

                                    <th>RISK</th>

                                    <th>SOURCE</th>

                                    <th>DATE</th>

                                    <th>ACTION</th>

                                </tr>

                            </thead>

                            <tbody>

                                <?php foreach ($scans as $scan): ?>

                                    <?php
                                    $type   = $scan['scan_type'];
                                    $result = $scan['result'];
                                    $risk   = (int) $scan['risk_score'];
                                    ?>

                                    <tr>

                                        <td>
                                            <div class="pg-history-type">
                                                <div class="pg-history-type-icon <?= htmlspecialchars($type) ?>">
                                                    <i class="fa-solid <?= getScanIcon($type) ?>"></i>
                                                </div>
                                                <span>
                                                    <?= htmlspecialchars(formatScanType($type)) ?>
                                                </span>
                                            </div>
                                        </td>

                                        <td>
                                            <div class="pg-history-input">
                                                <strong>
                                                    <?= htmlspecialchars(formatInputValue($scan['input_value'], $type)) ?>
                                                </strong>
                                                <?php if (!empty($scan['explanation'])): ?>
                                                    <span>
                                                        <?= htmlspecialchars($scan['explanation']) ?>
                                                    </span>
                                                <?php endif; ?>
                                            </div>
                                        </td>

                                        <td>
                                            <span class="pg-result-badge <?= resultClass($result) ?>">
                                                <?php if ($result === 'SAFE'): ?>
                                                    <i class="fa-solid fa-circle-check"></i>
                                                <?php elseif ($result === 'SUSPICIOUS'): ?>
                                                    <i class="fa-solid fa-triangle-exclamation"></i>
                                                <?php elseif ($result === 'DANGEROUS'): ?>
                                                    <i class="fa-solid fa-circle-exclamation"></i>
                                                <?php else: ?>
                                                    <i class="fa-solid fa-circle-question"></i>
                                                <?php endif; ?>
                                                <?= htmlspecialchars($result) ?>
                                            </span>
                                        </td>

                                        <td>
                                            <div class="pg-risk">
                                                <div class="pg-risk-score <?= riskClass($risk) ?>">
                                                    <?= $risk ?>%
                                                </div>
                                                <div class="pg-risk-bar">
                                                    <span
                                                        class="<?= riskClass($risk) ?>"
                                                        style="width: <?= min(100, max(0, $risk)) ?>%;"
                                                    ></span>
                                                </div>
                                            </div>
                                        </td>

                                        <td>
                                            <span class="pg-source-badge">
                                                <?php if ($scan['source'] === 'mobile'): ?>
                                                    <i class="fa-solid fa-mobile-screen-button"></i>
                                                    Mobile
                                                <?php else: ?>
                                                    <i class="fa-solid fa-globe"></i>
                                                    Web
                                                <?php endif; ?>
                                            </span>
                                        </td>

                                        <td>
                                            <div class="pg-history-date">
                                                <?= formatDateTime($scan['created_at']) ?>
                                            </div>
                                        </td>

                                        <td>
                                            <button
                                                type="button"
                                                class="pg-history-delete"
                                                data-id="<?= (int) $scan['id'] ?>"
                                                title="Delete this scan"
                                            >
                                                <i class="fa-solid fa-trash"></i>
                                                Delete
                                            </button>
                                        </td>

                                    </tr>

                                <?php endforeach; ?>

                            </tbody>

                        </table>

                    </div>

                <?php else: ?>

                    <div class="pg-history-empty">

                        <div class="pg-history-empty-icon">

                            <i class="fa-solid fa-clock-rotate-left"></i>

                        </div>

                        <h3>
                            No Scan Records Found
                        </h3>

                        <?php if ($search !== '' || $typeFilter !== '' || $resultFilter !== ''): ?>

                            <p>
                                No scan records match your current filters.
                            </p>

                            <a
                                href="history.php"
                                class="pg-primary-btn"
                            >
                                <i class="fa-solid fa-rotate-left"></i>
                                Clear Filters
                            </a>

                        <?php else: ?>

                            <p>
                                Your completed scans will appear here.
                            </p>

                            <a
                                href="scanner.php"
                                class="pg-primary-btn"
                            >
                                <i class="fa-solid fa-magnifying-glass"></i>
                                Start a Scan
                            </a>

                        <?php endif; ?>

                    </div>

                <?php endif; ?>

            </div>

        </section>

    </main>

</div>

<div
    class="pg-confirm-overlay"
    id="pgConfirmModal"
>

    <div class="pg-confirm-modal">

        <div class="pg-confirm-icon">

            <i class="fa-solid fa-trash"></i>

        </div>

        <div class="pg-confirm-content">

            <h3 id="pgConfirmTitle">
                Delete Scan?
            </h3>

            <p id="pgConfirmMessage">
                Are you sure you want to delete this scan?
            </p>

        </div>

        <div class="pg-confirm-actions">

            <button
                type="button"
                class="pg-confirm-cancel"
                id="pgConfirmCancel"
            >
                Cancel
            </button>

            <button
                type="button"
                class="pg-confirm-delete"
                id="pgConfirmDelete"
            >
                <i class="fa-solid fa-trash"></i>
                Delete
            </button>

        </div>

    </div>

</div>

<script src="../assets/js/app.js"></script>

<script>

const pgConfirmModal =
    document.getElementById('pgConfirmModal');

const pgConfirmTitle =
    document.getElementById('pgConfirmTitle');

const pgConfirmMessage =
    document.getElementById('pgConfirmMessage');

const pgConfirmCancel =
    document.getElementById('pgConfirmCancel');

const pgConfirmDelete =
    document.getElementById('pgConfirmDelete');

let pgConfirmAction = null;

function showConfirmModal(title, message, action) {

    pgConfirmTitle.textContent = title;

    pgConfirmMessage.textContent = message;

    pgConfirmAction = action;

    pgConfirmModal.classList.add('show');

    document.body.style.overflow = 'hidden';
}

function closeConfirmModal() {

    pgConfirmModal.classList.remove('show');

    document.body.style.overflow = '';

    pgConfirmAction = null;
}

pgConfirmCancel.addEventListener(
    'click',
    closeConfirmModal
);

pgConfirmModal.addEventListener(
    'click',
    function (event) {

        if (event.target === pgConfirmModal) {
            closeConfirmModal();
        }

    }
);

document.addEventListener(
    'keydown',
    function (event) {

        if (
            event.key === 'Escape' &&
            pgConfirmModal.classList.contains('show')
        ) {
            closeConfirmModal();
        }

    }
);

pgConfirmDelete.addEventListener(
    'click',
    async function () {

        if (typeof pgConfirmAction !== 'function') {
            return;
        }

        const action = pgConfirmAction;

        pgConfirmDelete.disabled = true;

        pgConfirmDelete.innerHTML =
            '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

        try {

            await action();

        } finally {

            pgConfirmDelete.disabled = false;

            pgConfirmDelete.innerHTML =
                '<i class="fa-solid fa-trash"></i> Delete';

        }

    }
);

document.addEventListener(
    'click',
    function (event) {

        const deleteButton =
            event.target.closest('.pg-history-delete');

        if (!deleteButton) {
            return;
        }

        const scanId =
            deleteButton.dataset.id;

        if (!scanId) {
            return;
        }

        showConfirmModal(
            'Delete Scan?',
            'Are you sure you want to delete this scan from your history?',
            async function () {

                try {

                    const formData =
                        new FormData();

                    formData.append(
                        'action',
                        'delete'
                    );

                    formData.append(
                        'id',
                        scanId
                    );

                    const response =
                        await fetch(
                            '../api/delete_history.php',
                            {
                                method: 'POST',
                                body: formData
                            }
                        );

                    const data =
                        await response.json();

                    if (!data.success) {

                        closeConfirmModal();

                        alert(
                            data.message ||
                            'Unable to delete scan.'
                        );

                        return;
                    }

                    closeConfirmModal();

                    window.location.reload();

                } catch (error) {

                    closeConfirmModal();

                    alert(
                        'Unable to delete scan.'
                    );

                }

            }
        );

    }
);

const deleteAllHistory =
    document.getElementById('deleteAllHistory');

if (deleteAllHistory) {

    deleteAllHistory.addEventListener(
        'click',
        function () {

            showConfirmModal(
                'Delete All History?',
                'Are you sure you want to delete all of your scan history? This action cannot be undone.',
                async function () {

                    try {

                        const formData =
                            new FormData();

                        formData.append(
                            'action',
                            'delete_all'
                        );

                        const response =
                            await fetch(
                                '../api/delete_history.php',
                                {
                                    method: 'POST',
                                    body: formData
                                }
                            );

                        const data =
                            await response.json();

                        if (!data.success) {

                            closeConfirmModal();

                            alert(
                                data.message ||
                                'Unable to delete history.'
                            );

                            return;
                        }

                        closeConfirmModal();

                        window.location.reload();

                    } catch (error) {

                        closeConfirmModal();

                        alert(
                            'Unable to delete history.'
                        );

                    }

                }
            );

        }
    );

}

</script>

</body>
</html>