<?php

session_start();

require_once "../config.php";
require_once "../db.php";

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header("Location: ../web/login.php");
    exit;
}

$pageTitle = 'User Accounts';
$pageSubtitle = 'Manage PhishGuard user and administrator accounts';

$userName = $_SESSION['full_name'] ?? 'Administrator';
$userInitial = strtoupper(substr($userName, 0, 1));

$message = '';
$messageType = '';

if (isset($_POST['add_user'])) {

    $fullName = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'user';

    if ($fullName === '' || $email === '' || $password === '') {
        $message = 'Please complete all required fields.';
        $messageType = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Please enter a valid email address.';
        $messageType = 'error';
    } elseif (!in_array($role, ['user', 'admin'], true)) {
        $message = 'Invalid account role.';
        $messageType = 'error';
    } else {

        $check = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $check->execute([':email' => $email]);

        if ($check->fetch()) {
            $message = 'An account with that email already exists.';
            $messageType = 'error';
        } else {

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $pdo->prepare("
                INSERT INTO users
                (
                    full_name,
                    email,
                    password,
                    role
                )
                VALUES
                (
                    :full_name,
                    :email,
                    :password,
                    :role
                )
            ");

            $stmt->execute([
                ':full_name' => $fullName,
                ':email' => $email,
                ':password' => $hashedPassword,
                ':role' => $role
            ]);

            $message = 'User account created successfully.';
            $messageType = 'success';
        }
    }
}

if (isset($_POST['edit_user'])) {

    $id = (int)($_POST['id'] ?? 0);
    $fullName = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'user';

    if ($id <= 0 || $fullName === '' || $email === '') {
        $message = 'Please complete all required fields.';
        $messageType = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Please enter a valid email address.';
        $messageType = 'error';
    } elseif (!in_array($role, ['user', 'admin'], true)) {
        $message = 'Invalid account role.';
        $messageType = 'error';
    } else {

        $check = $pdo->prepare("
            SELECT id
            FROM users
            WHERE email = :email
            AND id != :id
            LIMIT 1
        ");

        $check->execute([
            ':email' => $email,
            ':id' => $id
        ]);

        if ($check->fetch()) {

            $message = 'Another account is already using that email.';
            $messageType = 'error';

        } else {

            if ($password !== '') {

                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("
                    UPDATE users
                    SET
                        full_name = :full_name,
                        email = :email,
                        password = :password,
                        role = :role
                    WHERE id = :id
                ");

                $stmt->execute([
                    ':full_name' => $fullName,
                    ':email' => $email,
                    ':password' => $hashedPassword,
                    ':role' => $role,
                    ':id' => $id
                ]);

            } else {

                $stmt = $pdo->prepare("
                    UPDATE users
                    SET
                        full_name = :full_name,
                        email = :email,
                        role = :role
                    WHERE id = :id
                ");

                $stmt->execute([
                    ':full_name' => $fullName,
                    ':email' => $email,
                    ':role' => $role,
                    ':id' => $id
                ]);
            }

            $message = 'User account updated successfully.';
            $messageType = 'success';
        }
    }
}

if (isset($_GET['delete'])) {

    $deleteId = (int)$_GET['delete'];

    if ($deleteId === (int)$_SESSION['user_id']) {

        $message = 'You cannot delete your own administrator account.';
        $messageType = 'error';

    } elseif ($deleteId > 0) {

        $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
        $stmt->execute([':id' => $deleteId]);

        $message = 'User account deleted successfully.';
        $messageType = 'success';
    }
}

$search = trim($_GET['search'] ?? '');
$roleFilter = $_GET['role'] ?? '';

$totalUsers = (int)$pdo->query("
    SELECT COUNT(*) FROM users
")->fetchColumn();

$totalAdmins = (int)$pdo->query("
    SELECT COUNT(*) FROM users
    WHERE role = 'admin'
")->fetchColumn();

$totalRegularUsers = (int)$pdo->query("
    SELECT COUNT(*) FROM users
    WHERE role = 'user'
")->fetchColumn();

$todayUsers = (int)$pdo->query("
    SELECT COUNT(*)
    FROM users
    WHERE DATE(created_at) = CURDATE()
")->fetchColumn();

$where = [];
$params = [];

if ($search !== '') {
    $where[] = "(full_name LIKE :search OR email LIKE :search)";
    $params[':search'] = '%' . $search . '%';
}

if (in_array($roleFilter, ['user', 'admin'], true)) {
    $where[] = "role = :role";
    $params[':role'] = $roleFilter;
}

$sql = "
    SELECT
        id,
        full_name,
        email,
        role,
        created_at
    FROM users
";

if ($where) {
    $sql .= " WHERE " . implode(" AND ", $where);
}

$sql .= " ORDER BY created_at DESC LIMIT 200";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$users = $stmt->fetchAll();

$pageTitle = 'User Accounts';
$pageSubtitle = 'Manage PhishGuard user and administrator accounts';

function userRoleClass($role)
{
    return $role === 'admin'
        ? 'pg-badge-dangerous'
        : 'pg-badge-safe';
}

function userRoleLabel($role)
{
    return $role === 'admin'
        ? 'Administrator'
        : 'User';
}

function formatUserDate($date)
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
                        <i class="fa-solid fa-users"></i>
                        ACCOUNT MANAGEMENT
                    </div>

                    <h2>User Accounts</h2>

                    <p>
                        Manage registered users and administrator accounts
                        securely from one location.
                    </p>

                </div>

                <button
                    type="button"
                    class="pg-primary-button"
                    id="openAddUser"
                >
                    <i class="fa-solid fa-user-plus"></i>
                    Add User
                </button>

            </div>

            <?php if ($message !== ''): ?>

                <div class="pg-user-message <?= $messageType === 'success' ? 'success' : 'error' ?>">

                    <i class="fa-solid <?= $messageType === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation' ?>"></i>

                    <span><?= htmlspecialchars($message) ?></span>

                </div>

            <?php endif; ?>

            <div class="pg-stats pg-admin-stats">

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-users"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Total Users</span>
                        <strong><?= number_format($totalUsers) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-user-shield"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Administrators</span>
                        <strong><?= number_format($totalAdmins) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-user"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">Regular Users</span>
                        <strong><?= number_format($totalRegularUsers) ?></strong>
                    </div>

                </div>

                <div class="pg-stat-card">

                    <div class="pg-stat-icon">
                        <i class="fa-solid fa-user-clock"></i>
                    </div>

                    <div>
                        <span class="pg-stat-label">New Today</span>
                        <strong><?= number_format($todayUsers) ?></strong>
                    </div>

                </div>

            </div>

            <div class="pg-card">

                <div class="pg-card-header">

                    <div>
                        <h3>
                            <i class="fa-solid fa-filter"></i>
                            Account Search
                        </h3>

                        <p>
                            Search accounts by name, email, or role.
                        </p>
                    </div>

                </div>

                <div class="pg-card-body">

                    <form method="GET" class="pg-user-filter-grid">

                        <div>

                            <label class="pg-filter-label">
                                Search
                            </label>

                            <input
                                type="text"
                                name="search"
                                class="pg-filter-input"
                                placeholder="Name or email"
                                value="<?= htmlspecialchars($search) ?>"
                            >

                        </div>

                        <div>

                            <label class="pg-filter-label">
                                Role
                            </label>

                            <select
                                name="role"
                                class="pg-filter-input"
                            >
                                <option value="">All Roles</option>
                                <option
                                    value="user"
                                    <?= $roleFilter === 'user' ? 'selected' : '' ?>
                                >
                                    User
                                </option>
                                <option
                                    value="admin"
                                    <?= $roleFilter === 'admin' ? 'selected' : '' ?>
                                >
                                    Administrator
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
                                href="users.php"
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
                            <i class="fa-solid fa-address-book"></i>
                            Registered Accounts
                        </h3>

                        <p>
                            <?= number_format(count($users)) ?> account(s) displayed
                        </p>

                    </div>

                </div>

                <div class="pg-table-wrap">

                    <table class="pg-table">

                        <thead>

                            <tr>
                                <th>ID</th>
                                <th>User</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>

                        </thead>

                        <tbody>

                        <?php if (!$users): ?>

                            <tr>

                                <td colspan="6">

                                    <div class="pg-empty-state">

                                        <i class="fa-solid fa-user-slash"></i>

                                        <strong>No user accounts found</strong>

                                        <span>
                                            Try another search or add a new user.
                                        </span>

                                    </div>

                                </td>

                            </tr>

                        <?php else: ?>

                            <?php foreach ($users as $user): ?>

                                <?php
                                $displayInitial = strtoupper(
                                    substr($user['full_name'], 0, 1)
                                );
                                ?>

                                <tr>

                                    <td>
                                        #<?= (int)$user['id'] ?>
                                    </td>

                                    <td>

                                        <div class="pg-user-table-info">

                                            <div class="pg-user-table-avatar">
                                                <?= htmlspecialchars($displayInitial) ?>
                                            </div>

                                            <div>
                                                <strong>
                                                    <?= htmlspecialchars($user['full_name']) ?>
                                                </strong>

                                                <?php if ((int)$user['id'] === (int)$_SESSION['user_id']): ?>
                                                    <span class="pg-current-user">
                                                        Current account
                                                    </span>
                                                <?php endif; ?>

                                            </div>

                                        </div>

                                    </td>

                                    <td>
                                        <?= htmlspecialchars($user['email']) ?>
                                    </td>

                                    <td>

                                        <span class="pg-badge <?= userRoleClass($user['role']) ?>">
                                            <i class="fa-solid <?= $user['role'] === 'admin' ? 'fa-user-shield' : 'fa-user' ?>"></i>
                                            <?= htmlspecialchars(userRoleLabel($user['role'])) ?>
                                        </span>

                                    </td>

                                    <td>
                                        <span class="pg-time">
                                            <?= htmlspecialchars(formatUserDate($user['created_at'])) ?>
                                        </span>
                                    </td>

                                    <td>

                                        <div class="pg-user-actions">

                                            <button
                                                type="button"
                                                class="pg-icon-button pg-edit-user"
                                                title="Edit user"
                                                data-id="<?= (int)$user['id'] ?>"
                                                data-name="<?= htmlspecialchars($user['full_name'], ENT_QUOTES) ?>"
                                                data-email="<?= htmlspecialchars($user['email'], ENT_QUOTES) ?>"
                                                data-role="<?= htmlspecialchars($user['role'], ENT_QUOTES) ?>"
                                            >
                                                <i class="fa-solid fa-pen"></i>
                                            </button>

                                            <?php if ((int)$user['id'] !== (int)$_SESSION['user_id']): ?>

                                                <a
                                                    href="users.php?delete=<?= (int)$user['id'] ?>"
                                                    class="pg-icon-button pg-delete-user"
                                                    title="Delete user"
                                                    onclick="return confirm('Are you sure you want to delete this user account?');"
                                                >
                                                    <i class="fa-solid fa-trash"></i>
                                                </a>

                                            <?php endif; ?>

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

<div class="pg-modal" id="userModal">

    <div class="pg-modal-box">

        <div class="pg-modal-header">

            <div>

                <h3 id="userModalTitle">
                    Add User
                </h3>

                <p id="userModalSubtitle">
                    Create a new PhishGuard account.
                </p>

            </div>

            <button
                type="button"
                class="pg-modal-close"
                id="closeUserModal"
            >
                <i class="fa-solid fa-xmark"></i>
            </button>

        </div>

        <form method="POST" id="userForm">

            <input
                type="hidden"
                name="id"
                id="userId"
                value=""
            >

            <div class="pg-modal-body">

                <div class="pg-form-group">

                    <label for="userFullName">
                        Full Name
                    </label>

                    <input
                        type="text"
                        name="full_name"
                        id="userFullName"
                        class="pg-filter-input"
                        maxlength="100"
                        required
                    >

                </div>

                <div class="pg-form-group">

                    <label for="userEmail">
                        Email Address
                    </label>

                    <input
                        type="email"
                        name="email"
                        id="userEmail"
                        class="pg-filter-input"
                        maxlength="150"
                        required
                    >

                </div>

                <div class="pg-form-group">

                    <label for="userPassword">
                        Password
                    </label>

                    <input
                        type="password"
                        name="password"
                        id="userPassword"
                        class="pg-filter-input"
                        minlength="6"
                    >

                    <small id="passwordHelp">
                        Minimum 6 characters.
                    </small>

                </div>

                <div class="pg-form-group">

                    <label for="userRole">
                        Account Role
                    </label>

                    <select
                        name="role"
                        id="userRole"
                        class="pg-filter-input"
                        required
                    >
                        <option value="user">User</option>
                        <option value="admin">Administrator</option>
                    </select>

                </div>

            </div>

            <div class="pg-modal-footer">

                <button
                    type="button"
                    class="pg-secondary-button"
                    id="cancelUserModal"
                >
                    Cancel
                </button>

                <button
                    type="submit"
                    name="add_user"
                    value="1"
                    class="pg-primary-button"
                    id="saveUserButton"
                >
                    <i class="fa-solid fa-user-plus"></i>
                    Create User
                </button>

            </div>

        </form>

    </div>

</div>

<script src="../assets/js/app.js"></script>

<script>

document.addEventListener('DOMContentLoaded', function () {

    const modal = document.getElementById('userModal');
    const openButton = document.getElementById('openAddUser');
    const closeButton = document.getElementById('closeUserModal');
    const cancelButton = document.getElementById('cancelUserModal');

    const form = document.getElementById('userForm');

    const modalTitle = document.getElementById('userModalTitle');
    const modalSubtitle = document.getElementById('userModalSubtitle');

    const userId = document.getElementById('userId');
    const userFullName = document.getElementById('userFullName');
    const userEmail = document.getElementById('userEmail');
    const userPassword = document.getElementById('userPassword');
    const userRole = document.getElementById('userRole');

    const passwordHelp = document.getElementById('passwordHelp');
    const saveButton = document.getElementById('saveUserButton');

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

        userId.value = '';

        userRole.value = 'user';

        userPassword.required = true;

        modalTitle.textContent = 'Add User';
        modalSubtitle.textContent = 'Create a new PhishGuard account.';

        passwordHelp.textContent = 'Minimum 6 characters.';

        saveButton.name = 'add_user';
        saveButton.value = '1';

        saveButton.innerHTML =
            '<i class="fa-solid fa-user-plus"></i> Create User';
    }

    openButton.addEventListener('click', function () {

        resetAddForm();

        openModal();

        setTimeout(function () {
            userFullName.focus();
        }, 100);

    });

    closeButton.addEventListener('click', closeModal);
    cancelButton.addEventListener('click', closeModal);

    modal.addEventListener('click', function (event) {

        if (event.target === modal) {
            closeModal();
        }

    });

    document.querySelectorAll('.pg-edit-user').forEach(function (button) {

        button.addEventListener('click', function () {

            userId.value = button.dataset.id || '';
            userFullName.value = button.dataset.name || '';
            userEmail.value = button.dataset.email || '';
            userRole.value = button.dataset.role || 'user';

            userPassword.value = '';
            userPassword.required = false;

            modalTitle.textContent = 'Edit User';
            modalSubtitle.textContent =
                'Update this PhishGuard account.';

            passwordHelp.textContent =
                'Leave blank to keep the current password.';

            saveButton.name = 'edit_user';
            saveButton.value = '1';

            saveButton.innerHTML =
                '<i class="fa-solid fa-floppy-disk"></i> Save Changes';

            openModal();

            setTimeout(function () {
                userFullName.focus();
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