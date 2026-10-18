<?php

session_start();

require_once "../config.php";
require_once "../db.php";

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header("Location: ../web/login.php");
    exit;
}

$userName = $_SESSION['full_name'] ?? 'Administrator';
$userInitial = strtoupper(substr($userName, 0, 1));

$message = '';
$messageType = '';

if (isset($_POST['add_alert'])) {

    $title = trim($_POST['title'] ?? '');
    $alertMessage = trim($_POST['message'] ?? '');
    $isActive = isset($_POST['is_active']) ? 1 : 0;

    if ($title === '' || $alertMessage === '') {

        $message = 'Please complete all required fields.';
        $messageType = 'error';

    } else {

        $stmt = $pdo->prepare("
            INSERT INTO safety_alerts
            (
                title,
                message,
                is_active
            )
            VALUES
            (
                :title,
                :message,
                :is_active
            )
        ");

        $stmt->execute([
            ':title' => $title,
            ':message' => $alertMessage,
            ':is_active' => $isActive
        ]);

        $message = 'Safety alert created successfully.';
        $messageType = 'success';
    }
}

if (isset($_POST['edit_alert'])) {

    $id = (int)($_POST['id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $alertMessage = trim($_POST['message'] ?? '');
    $isActive = isset($_POST['is_active']) ? 1 : 0;

    if ($id <= 0 || $title === '' || $alertMessage === '') {

        $message = 'Please complete all required fields.';
        $messageType = 'error';

    } else {

        $stmt = $pdo->prepare("
            UPDATE safety_alerts
            SET
                title = :title,
                message = :message,
                is_active = :is_active
            WHERE id = :id
        ");

        $stmt->execute([
            ':title' => $title,
            ':message' => $alertMessage,
            ':is_active' => $isActive,
            ':id' => $id
        ]);

        $message = 'Safety alert updated successfully.';
        $messageType = 'success';
    }
}

if (isset($_POST['toggle_alert'])) {

    $id = (int)($_POST['id'] ?? 0);

    if ($id > 0) {

        $stmt = $pdo->prepare("
            UPDATE safety_alerts
            SET is_active = IF(is_active = 1, 0, 1)
            WHERE id = :id
        ");

        $stmt->execute([
            ':id' => $id
        ]);

        $message = 'Alert status updated successfully.';
        $messageType = 'success';
    }
}

if (isset($_POST['delete_alert'])) {

    $id = (int)($_POST['id'] ?? 0);

    if ($id > 0) {

        $stmt = $pdo->prepare("
            DELETE FROM safety_alerts
            WHERE id = :id
        ");

        $stmt->execute([
            ':id' => $id
        ]);

        $message = 'Safety alert deleted successfully.';
        $messageType = 'success';
    }
}

$totalAlerts = (int)$pdo->query("
    SELECT COUNT(*)
    FROM safety_alerts
")->fetchColumn();

$activeAlerts = (int)$pdo->query("
    SELECT COUNT(*)
    FROM safety_alerts
    WHERE is_active = 1
")->fetchColumn();

$inactiveAlerts = (int)$pdo->query("
    SELECT COUNT(*)
    FROM safety_alerts
    WHERE is_active = 0
")->fetchColumn();

$todayAlerts = (int)$pdo->query("
    SELECT COUNT(*)
    FROM safety_alerts
    WHERE DATE(created_at) = CURDATE()
")->fetchColumn();

$search = trim($_GET['search'] ?? '');
$statusFilter = $_GET['status'] ?? '';

$where = [];
$params = [];

if ($search !== '') {

    $where[] = "(title LIKE :search OR message LIKE :search)";
    $params[':search'] = '%' . $search . '%';
}

if ($statusFilter === 'active') {

    $where[] = "is_active = 1";

} elseif ($statusFilter === 'inactive') {

    $where[] = "is_active = 0";
}

$sql = "
    SELECT
        id,
        title,
        message,
        is_active,
        created_at
    FROM safety_alerts
";

if ($where) {
    $sql .= " WHERE " . implode(" AND ", $where);
}

$sql .= " ORDER BY created_at DESC LIMIT 200";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);

$alerts = $stmt->fetchAll();

$pageTitle = 'Safety Alerts';
$pageSubtitle = 'Manage security warnings and user safety notifications';

function alertStatusClass($status)
{
    return (int)$status === 1
        ? 'pg-badge-safe'
        : 'pg-badge-suspicious';
}

function alertStatusLabel($status)
{
    return (int)$status === 1
        ? 'Active'
        : 'Inactive';
}

function formatAlertDate($date)
{
    if (!$date) {
        return '—';
    }

    return date('M d, Y h:i A', strtotime($date));
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
                        <i class="fa-solid fa-bell"></i>
                        SECURITY NOTIFICATIONS
                    </div>

                    <h2>Safety Alerts</h2>

                    <p>
                        Create and manage security alerts shown to PhishGuard users.
                    </p>

                </div>

                <button
                    type="button"
                    class="pg-primary-button"
                    id="openAddAlert"
                >
                    <i class="fa-solid fa-plus"></i>
                    Create Alert
                </button>

            </div>

            <?php if ($message !== ''): ?>

                <div class="pg-alert-message <?= $messageType === 'success' ? 'success' : 'error' ?>">

                    <i class="fa-solid <?= $messageType === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation' ?>"></i>

                    <span><?= htmlspecialchars($message) ?></span>

                </div>

            <?php endif; ?>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-bell"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Total Alerts</span>
                        <strong><?= number_format($totalAlerts) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-circle-check"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Active Alerts</span>
                        <strong><?= number_format($activeAlerts) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-circle-pause"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Inactive Alerts</span>
                        <strong><?= number_format($inactiveAlerts) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-calendar-day"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Created Today</span>
                        <strong><?= number_format($todayAlerts) ?></strong>
                    </div>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>

                        <h3>
                            <i class="fa-solid fa-filter"></i>
                            Alert Search
                        </h3>

                        <p>
                            Search alerts and filter them by status.
                        </p>

                    </div>

                </div>

                <div class="pg-card-body">

                    <form method="GET" class="pg-alert-filter-grid">

                        <div>

                            <label class="pg-filter-label">
                                Search
                            </label>

                            <input
                                type="text"
                                name="search"
                                class="pg-filter-input"
                                placeholder="Alert title or message"
                                value="<?= htmlspecialchars($search) ?>"
                            >

                        </div>

                        <div>

                            <label class="pg-filter-label">
                                Status
                            </label>

                            <select
                                name="status"
                                class="pg-filter-input"
                            >

                                <option value="">
                                    All Statuses
                                </option>

                                <option
                                    value="active"
                                    <?= $statusFilter === 'active' ? 'selected' : '' ?>
                                >
                                    Active
                                </option>

                                <option
                                    value="inactive"
                                    <?= $statusFilter === 'inactive' ? 'selected' : '' ?>
                                >
                                    Inactive
                                </option>

                            </select>

                        </div>

                        <div class="pg-filter-actions">

                            <button
                                type="submit"
                                class="pg-primary-button"
                            >
                                <i class="fa-solid fa-magnifying-glass"></i>
                                Search
                            </button>

                            <a
                                href="alerts.php"
                                class="pg-secondary-button"
                            >
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
                            <i class="fa-solid fa-list-check"></i>
                            Security Alerts
                        </h3>

                        <p>
                            <?= number_format(count($alerts)) ?> alert(s) displayed
                        </p>

                    </div>

                </div>

                <div class="pg-table-wrap">

                    <table class="pg-table">

                        <thead>

                            <tr>
                                <th>ID</th>
                                <th>Alert</th>
                                <th>Message</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>

                        </thead>

                        <tbody>

                        <?php if (!$alerts): ?>

                            <tr>

                                <td colspan="6">

                                    <div class="pg-empty-state">

                                        <i class="fa-solid fa-bell-slash"></i>

                                        <strong>No safety alerts found</strong>

                                        <span>
                                            Create a security alert to notify users.
                                        </span>

                                    </div>

                                </td>

                            </tr>

                        <?php else: ?>

                            <?php foreach ($alerts as $alert): ?>

                                <tr>

                                    <td>
                                        #<?= (int)$alert['id'] ?>
                                    </td>

                                    <td>

                                        <div class="pg-alert-title-cell">

                                            <div class="pg-alert-icon">
                                                <i class="fa-solid fa-shield-exclamation"></i>
                                            </div>

                                            <strong>
                                                <?= htmlspecialchars($alert['title']) ?>
                                            </strong>

                                        </div>

                                    </td>

                                    <td>

                                        <div class="pg-alert-message-cell">
                                            <?= nl2br(htmlspecialchars($alert['message'])) ?>
                                        </div>

                                    </td>

                                    <td>

                                        <span class="pg-badge <?= alertStatusClass($alert['is_active']) ?>">

                                            <i class="fa-solid <?= (int)$alert['is_active'] === 1 ? 'fa-circle-check' : 'fa-circle-pause' ?>"></i>

                                            <?= htmlspecialchars(alertStatusLabel($alert['is_active'])) ?>

                                        </span>

                                    </td>

                                    <td>

                                        <span class="pg-time">
                                            <?= htmlspecialchars(formatAlertDate($alert['created_at'])) ?>
                                        </span>

                                    </td>

                                    <td>

                                        <div class="pg-alert-actions">

                                            <button
                                                type="button"
                                                class="pg-icon-button pg-edit-alert"
                                                title="Edit alert"
                                                data-id="<?= (int)$alert['id'] ?>"
                                                data-title="<?= htmlspecialchars($alert['title'], ENT_QUOTES) ?>"
                                                data-message="<?= htmlspecialchars($alert['message'], ENT_QUOTES) ?>"
                                                data-active="<?= (int)$alert['is_active'] ?>"
                                            >
                                                <i class="fa-solid fa-pen"></i>
                                            </button>

                                            <form
                                                method="POST"
                                                class="pg-inline-form"
                                            >

                                                <input
                                                    type="hidden"
                                                    name="id"
                                                    value="<?= (int)$alert['id'] ?>"
                                                >

                                                <button
                                                    type="submit"
                                                    name="toggle_alert"
                                                    value="1"
                                                    class="pg-icon-button"
                                                    title="<?= (int)$alert['is_active'] === 1 ? 'Deactivate alert' : 'Activate alert' ?>"
                                                >
                                                    <i class="fa-solid <?= (int)$alert['is_active'] === 1 ? 'fa-pause' : 'fa-play' ?>"></i>
                                                </button>

                                            </form>

                                            <form
                                                method="POST"
                                                class="pg-inline-form"
                                                onsubmit="return confirm('Are you sure you want to delete this safety alert?');"
                                            >

                                                <input
                                                    type="hidden"
                                                    name="id"
                                                    value="<?= (int)$alert['id'] ?>"
                                                >

                                                <button
                                                    type="submit"
                                                    name="delete_alert"
                                                    value="1"
                                                    class="pg-icon-button pg-delete-alert"
                                                    title="Delete alert"
                                                >
                                                    <i class="fa-solid fa-trash"></i>
                                                </button>

                                            </form>

                                        </div>

                                    </td>

                                </tr>

                            <?php endforeach; ?>

                        <?php endif; ?>

                        </tbody>

                    </table>

                </div>

            </div>

        </section>

    </main>

</div>

<div class="pg-modal" id="alertModal">

    <div class="pg-modal-box">

        <div class="pg-modal-header">

            <div>

                <h3 id="alertModalTitle">
                    Create Safety Alert
                </h3>

                <p id="alertModalSubtitle">
                    Create a notification for PhishGuard users.
                </p>

            </div>

            <button
                type="button"
                class="pg-modal-close"
                id="closeAlertModal"
            >
                <i class="fa-solid fa-xmark"></i>
            </button>

        </div>

        <form method="POST" id="alertForm">

            <input
                type="hidden"
                name="id"
                id="alertId"
                value=""
            >

            <div class="pg-modal-body">

                <div class="pg-form-group">

                    <label for="alertTitle">
                        Alert Title
                    </label>

                    <input
                        type="text"
                        name="title"
                        id="alertTitle"
                        class="pg-filter-input"
                        maxlength="200"
                        placeholder="Example: New GCash phishing warning"
                        required
                    >

                </div>

                <div class="pg-form-group">

                    <label for="alertMessage">
                        Alert Message
                    </label>

                    <textarea
                        name="message"
                        id="alertMessage"
                        class="pg-filter-input pg-alert-textarea"
                        rows="6"
                        placeholder="Enter the safety message that users should see."
                        required
                    ></textarea>

                </div>

                <div class="pg-alert-switch-row">

                    <div>

                        <strong>
                            Alert Status
                        </strong>

                        <span>
                            Make this alert visible to users.
                        </span>

                    </div>

                    <label class="pg-switch">

                        <input
                            type="checkbox"
                            name="is_active"
                            id="alertActive"
                            checked
                        >

                        <span class="pg-switch-slider"></span>

                    </label>

                </div>

            </div>

            <div class="pg-modal-footer">

                <button
                    type="button"
                    class="pg-secondary-button"
                    id="cancelAlertModal"
                >
                    Cancel
                </button>

                <button
                    type="submit"
                    name="add_alert"
                    value="1"
                    class="pg-primary-button"
                    id="saveAlertButton"
                >
                    <i class="fa-solid fa-plus"></i>
                    Create Alert
                </button>

            </div>

        </form>

    </div>

</div>

<script src="../assets/js/app.js"></script>

<script>

document.addEventListener('DOMContentLoaded', function () {

    const modal = document.getElementById('alertModal');

    const openButton = document.getElementById('openAddAlert');
    const closeButton = document.getElementById('closeAlertModal');
    const cancelButton = document.getElementById('cancelAlertModal');

    const form = document.getElementById('alertForm');

    const modalTitle = document.getElementById('alertModalTitle');
    const modalSubtitle = document.getElementById('alertModalSubtitle');

    const alertId = document.getElementById('alertId');
    const alertTitle = document.getElementById('alertTitle');
    const alertMessage = document.getElementById('alertMessage');
    const alertActive = document.getElementById('alertActive');

    const saveButton = document.getElementById('saveAlertButton');

    function openModal() {

        modal.classList.add('show');
        document.body.classList.add('pg-modal-open');

    }

    function closeModal() {

        modal.classList.remove('show');
        document.body.classList.remove('pg-modal-open');

    }

    function resetAddForm() {

        form.reset();

        alertId.value = '';
        alertActive.checked = true;

        modalTitle.textContent = 'Create Safety Alert';

        modalSubtitle.textContent =
            'Create a notification for PhishGuard users.';

        saveButton.name = 'add_alert';
        saveButton.value = '1';

        saveButton.innerHTML =
            '<i class="fa-solid fa-plus"></i> Create Alert';

    }

    openButton.addEventListener('click', function () {

        resetAddForm();

        openModal();

        setTimeout(function () {
            alertTitle.focus();
        }, 100);

    });

    closeButton.addEventListener('click', closeModal);

    cancelButton.addEventListener('click', closeModal);

    modal.addEventListener('click', function (event) {

        if (event.target === modal) {
            closeModal();
        }

    });

    document.querySelectorAll('.pg-edit-alert').forEach(function (button) {

        button.addEventListener('click', function () {

            alertId.value = button.dataset.id || '';

            alertTitle.value = button.dataset.title || '';

            alertMessage.value = button.dataset.message || '';

            alertActive.checked =
                button.dataset.active === '1';

            modalTitle.textContent = 'Edit Safety Alert';

            modalSubtitle.textContent =
                'Update this security notification.';

            saveButton.name = 'edit_alert';
            saveButton.value = '1';

            saveButton.innerHTML =
                '<i class="fa-solid fa-floppy-disk"></i> Save Changes';

            openModal();

            setTimeout(function () {
                alertTitle.focus();
            }, 100);

        });

    });

    document.addEventListener('keydown', function (event) {

        if (event.key === 'Escape') {
            closeModal();
        }

    });

});

</script>

</body>
</html>