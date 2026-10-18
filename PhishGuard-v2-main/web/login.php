<?php

session_start();

require_once '../config.php';
require_once '../db.php';

if (isset($_SESSION['user_id'])) {
    if (($_SESSION['role'] ?? '') === 'admin') {
        header('Location: ../admin/dashboard.php');
    } else {
        header('Location: home.php');
    }
    exit;
}

$token     = trim($_GET['token'] ?? '');
$error     = '';
$success   = '';
$magicLink = '';

if ($token !== '') {
    try {
        $stmt = $pdo->prepare("
            SELECT ml.id AS magic_id, ml.user_id, ml.expires_at, ml.used_at,
                   u.full_name, u.email, u.role
            FROM magic_links ml
            INNER JOIN users u ON u.id = ml.user_id
            WHERE ml.token = :token
            LIMIT 1
        ");
        $stmt->execute([':token' => $token]);
        $magic = $stmt->fetch();

        if (!$magic) {
            $error = 'Invalid magic login link.';
        } elseif (!empty($magic['used_at'])) {
            $error = 'This magic login link has already been used.';
        } elseif (strtotime($magic['expires_at']) < time()) {
            $error = 'This magic login link has expired.';
        } else {
            $update = $pdo->prepare("
                UPDATE magic_links
                SET used_at = NOW()
                WHERE id = :id AND used_at IS NULL
            ");
            $update->execute([':id' => $magic['magic_id']]);

            if ($update->rowCount() === 1) {
                session_regenerate_id(true);

                $_SESSION['user_id']   = (int) $magic['user_id'];
                $_SESSION['full_name'] = $magic['full_name'];
                $_SESSION['email']     = $magic['email'];
                $_SESSION['role']      = $magic['role'];

                if (strtolower($magic['role']) === 'admin') {
                    header('Location: ../admin/dashboard.php');
                } else {
                    header('Location: home.php');
                }
                exit;
            } else {
                $error = 'This magic login link has already been used.';
            }
        }
    } catch (PDOException $e) {
        error_log('PhishGuard login error (magic link): ' . $e->getMessage());
        $error = 'Unable to process the magic login link.';
    }
}

elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_login'])) {
    $email    = trim($_POST['admin_email'] ?? '');
    $password = $_POST['admin_password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Please enter both email and password.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } else {
        try {
            $stmt = $pdo->prepare("
                SELECT id, full_name, email, password, role
                FROM users WHERE email = :email LIMIT 1
            ");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();

            if (!$user) {
                $error = 'Invalid email or password.';
            } elseif (strtolower($user['role']) !== 'admin') {
                $error = 'This account does not have admin access.';
            } elseif (!password_verify($password, $user['password'])) {
                $error = 'Invalid email or password.';
            } else {
                session_regenerate_id(true);

                $_SESSION['user_id']   = (int) $user['id'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['email']     = $user['email'];
                $_SESSION['role']      = $user['role'];

                header('Location: ../admin/dashboard.php');
                exit;
            }
        } catch (PDOException $e) {
            error_log('PhishGuard login error (admin): ' . $e->getMessage());
            $error = 'Unable to process the login request.';
        }
    }
}

elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    if ($email === '') {
        $error = 'Please enter your email address.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif (!preg_match('/@gmail\.com$/i', $email)) {
        $error = 'Only @gmail.com email addresses are accepted.';
    } else {
        try {

            $cutoff = date('Y-m-d H:i:s', time() - 870);

            $rateCheck = $pdo->prepare("
                SELECT COUNT(*) AS cnt
                FROM magic_links ml
                INNER JOIN users u ON u.id = ml.user_id
                WHERE u.email = :email
                  AND ml.expires_at > :cutoff
            ");
            $rateCheck->execute([
                ':email'  => $email,
                ':cutoff' => $cutoff,
            ]);
            $recentCount = (int) $rateCheck->fetchColumn();

            if ($recentCount > 0) {

                $latestStmt = $pdo->prepare("
                    SELECT ml.expires_at
                    FROM magic_links ml
                    INNER JOIN users u ON u.id = ml.user_id
                    WHERE u.email = :email
                    ORDER BY ml.id DESC
                    LIMIT 1
                ");
                $latestStmt->execute([':email' => $email]);
                $latest = $latestStmt->fetch();

                $waitSeconds = 30;

                if ($latest) {
                    $createdAt   = strtotime($latest['expires_at']) - 900;
                    $elapsed     = time() - $createdAt;
                    $waitSeconds = max(1, 30 - $elapsed);
                }

                $error = 'Please wait <strong id="rateTimer" data-seconds="' . $waitSeconds . '">' . $waitSeconds . '</strong> seconds before generating another magic link for this email.';

            } else {

                $stmt = $pdo->prepare("
                    SELECT id, full_name, email
                    FROM users
                    WHERE email = :email
                    LIMIT 1
                ");
                $stmt->execute([':email' => $email]);
                $user = $stmt->fetch();

                if (!$user) {

                    $prefix   = explode('@', $email)[0];
                    $fullName = ucwords(str_replace(['.', '_', '-'], ' ', $prefix));

                    $insertUser = $pdo->prepare("
                        INSERT INTO users (full_name, email, password, role, created_at)
                        VALUES (:full_name, :email, :password, 'user', NOW())
                    ");
                    $insertUser->execute([
                        ':full_name' => $fullName,
                        ':email'     => $email,
                        ':password'  => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
                    ]);

                    $user = [
                        'id'        => (int) $pdo->lastInsertId(),
                        'full_name' => $fullName,
                        'email'     => $email,
                    ];
                }

                $newToken  = bin2hex(random_bytes(32));
                $expiresAt = date('Y-m-d H:i:s', time() + 900);

                $insert = $pdo->prepare("
                    INSERT INTO magic_links (user_id, token, expires_at)
                    VALUES (:user_id, :token, :expires_at)
                ");
                $insert->execute([
                    ':user_id'    => $user['id'],
                    ':token'      => $newToken,
                    ':expires_at' => $expiresAt,
                ]);

                $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                $host   = $_SERVER['HTTP_HOST'];
                $dir    = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
                $magicLink = $scheme . '://' . $host . $dir . '/login.php?token=' . urlencode($newToken);

                $success = 'Your magic login link has been generated.';
            }

        } catch (PDOException $e) {
            error_log('PhishGuard login error (magic link generation): ' . $e->getMessage());
            $error = 'Unable to generate the magic login link.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | PhishGuard</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">

    <style>
        <?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
    </style>

    <style>
        .pg-login-card {
            width: 100%;
            max-width: 460px;
            padding: 44px 42px 36px;
        }
        .pg-login-form .pg-login-field { margin-bottom: 18px; }
        .pg-login-form .pg-login-input-wrap input {
            height: 48px;
            font-size: 14.5px;
            padding: 12px 14px 12px 42px;
        }
        .pg-login-form .pg-login-input-wrap > i {
            top: 50%;
            transform: translateY(-50%);
        }
        .pg-login-form .pg-login-button {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            min-height: 48px;
            padding: 12px 18px;
            box-sizing: border-box;
            font-size: 14.5px;
            font-weight: 600;
            gap: 8px;
            border: none;
            cursor: pointer;
            text-decoration: none;
        }
        .pg-login-form .pg-login-secondary {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            min-height: 42px;
            padding: 10px 18px;
            box-sizing: border-box;
            font-size: 13.5px;
            font-weight: 500;
            gap: 8px;
            cursor: pointer;
            margin-top: 12px;
            background: transparent;
            border: 1px solid rgba(148, 163, 184, 0.35);
            color: #cbd5e1;
            border-radius: 8px;
            transition: background .15s ease, border-color .15s ease, color .15s ease;
        }
        .pg-login-form .pg-login-secondary:hover {
            background: rgba(148, 163, 184, 0.08);
            border-color: rgba(148, 163, 184, 0.6);
            color: #e2e8f0;
        }
        .pg-login-header h1 { font-size: 26px; }
        .pg-login-header p  { font-size: 13.5px; }
        .pg-login-security  { margin-top: 22px; }
    </style>
</head>

<body class="pg-login-page">

<div class="pg-login-wrapper">

    <div class="pg-login-card">

        <div class="pg-login-brand">
            <div class="pg-login-logo">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div class="pg-login-brand-name">PHISHGUARD</div>
            <div class="pg-login-brand-sub">AI-Powered Phishing Detection System</div>
        </div>

        <div class="pg-login-header" id="welcomeHeader">
            <h1>Sign in to PhishGuard</h1>
            <p>Enter your Gmail address to receive a secure login link.</p>
        </div>

        <?php if ($error): ?>
            <div class="pg-login-alert pg-login-alert-danger" role="alert">
                <i class="fa-solid fa-circle-exclamation"></i>
                <span><?= strpos($error, 'rateTimer') !== false ? $error : htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></span>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="pg-login-alert pg-login-alert-success" role="status">
                <i class="fa-solid fa-circle-check"></i>
                <span><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></span>
            </div>
        <?php endif; ?>

        <?php if ($magicLink !== ''): ?>

            <a href="<?= htmlspecialchars($magicLink, ENT_QUOTES, 'UTF-8') ?>"
               class="pg-login-button"
               style="display:flex;text-decoration:none;margin-top:18px;">
                <i class="fa-solid fa-wand-magic-sparkles"></i>
                Open Magic Login Link
            </a>

        <?php else: ?>

            <form method="POST" class="pg-login-form" id="userForm">
                <div class="pg-login-field">
                    <label for="email">Gmail Address</label>
                    <div class="pg-login-input-wrap">
                        <i class="fa-solid fa-envelope"></i>
                        <input type="email" id="email" name="email"
                               placeholder="Enter your @gmail.com address"
                               autocomplete="email" required autofocus>
                    </div>
                </div>

                <button type="submit" class="pg-login-button">
                    <i class="fa-solid fa-wand-magic-sparkles"></i>
                    Generate Magic Link
                </button>

                <button type="button" id="showAdminLogin" class="pg-login-secondary">
                    <i class="fa-solid fa-lock"></i>
                    Admin
                </button>
            </form>

            <form method="POST" class="pg-login-form" id="adminForm" style="display:none;">
                <input type="hidden" name="admin_login" value="1">

                <div class="pg-login-field">
                    <label for="admin_email">Email Address</label>
                    <div class="pg-login-input-wrap">
                        <i class="fa-solid fa-envelope"></i>
                        <input type="email" id="admin_email" name="admin_email"
                               placeholder="Enter your admin email"
                               autocomplete="username" required>
                    </div>
                </div>

                <div class="pg-login-field">
                    <label for="admin_password">Password</label>
                    <div class="pg-login-input-wrap">
                        <i class="fa-solid fa-lock"></i>
                        <input type="password" id="admin_password" name="admin_password"
                               placeholder="Enter your password"
                               autocomplete="current-password" required>
                    </div>
                </div>

                <button type="submit" class="pg-login-button">
                    <i class="fa-solid fa-right-to-bracket"></i>
                    Sign In as Admin
                </button>

                <button type="button" id="backToUser" class="pg-login-secondary">
                    <i class="fa-solid fa-arrow-left"></i>
                    Back
                </button>
            </form>

        <?php endif; ?>

        <div class="pg-login-security">
            <i class="fa-solid fa-shield-halved"></i>
            <span>Your security is protected by PhishGuard.</span>
        </div>

    </div>

    <div class="pg-login-footer">
        PhishGuard © 2026 • AI-Powered Phishing Detection System
    </div>

</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    const userForm    = document.getElementById('userForm');
    const adminForm   = document.getElementById('adminForm');
    const showAdmin   = document.getElementById('showAdminLogin');
    const backToUser  = document.getElementById('backToUser');
    const headerTitle = document.querySelector('#welcomeHeader h1');
    const headerSub   = document.querySelector('#welcomeHeader p');

    if (showAdmin && userForm && adminForm) {
        showAdmin.addEventListener('click', function () {
            userForm.style.display  = 'none';
            adminForm.style.display = 'block';
            headerTitle.textContent = 'Admin Login';
            headerSub.textContent   = 'Sign in with your admin credentials.';
            document.getElementById('admin_email').focus();
        });

        backToUser.addEventListener('click', function () {
            adminForm.style.display = 'none';
            userForm.style.display  = 'block';
            headerTitle.textContent = 'Sign in to PhishGuard';
            headerSub.textContent   = "Enter your Gmail address to receive a secure login link.";
            document.getElementById('email').focus();
        });

        <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_login'])): ?>
            userForm.style.display  = 'none';
            adminForm.style.display = 'block';
            headerTitle.textContent = 'Admin Login';
            headerSub.textContent   = 'Sign in with your admin credentials.';
        <?php endif; ?>
    }

    const rateTimer = document.getElementById('rateTimer');

    if (rateTimer) {

        const submitBtn  = document.querySelector('#userForm button[type="submit"]');
        const emailInput = document.getElementById('email');

        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.style.opacity = '0.5';
            submitBtn.style.cursor = 'not-allowed';
        }

        if (emailInput) {
            emailInput.disabled = true;
        }

        let seconds = parseInt(rateTimer.dataset.seconds, 10) || 30;

        rateTimer.textContent = seconds;

        const interval = setInterval(function () {

            seconds--;

            if (seconds <= 0) {

                clearInterval(interval);

                const alertBox = rateTimer.closest('.pg-login-alert');

                if (alertBox) {
                    alertBox.style.transition = 'opacity 0.4s ease';
                    alertBox.style.opacity = '0';
                    setTimeout(function () {
                        alertBox.remove();
                    }, 400);
                }

                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.style.opacity = '';
                    submitBtn.style.cursor = '';
                }

                if (emailInput) {
                    emailInput.disabled = false;
                    emailInput.focus();
                }

                return;
            }

            rateTimer.textContent = seconds;

        }, 1000);
    }
});
</script>

</body>
</html>