<?php

session_start();

require_once "../db.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: ../web/login.php");
    exit;
}

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if ($email === '' || $password === '') {
    $_SESSION['login_error'] = "Please enter your email and password.";
    header("Location: ../web/login.php");
    exit;
}

$stmt = $pdo->prepare("
    SELECT id, full_name, email, password, role
    FROM users
    WHERE email = ?
    LIMIT 1
");

$stmt->execute([$email]);

$user = $stmt->fetch();

if (!$user || empty($user['password']) || !password_verify($password, $user['password'])) {
    $_SESSION['login_error'] = "Invalid email or password.";
    header("Location: ../web/login.php");
    exit;
}

session_regenerate_id(true);

$_SESSION['user_id'] = $user['id'];
$_SESSION['full_name'] = $user['full_name'];
$_SESSION['email'] = $user['email'];
$_SESSION['role'] = $user['role'];

$stmt = $pdo->prepare("
    INSERT INTO activity_logs
    (user_id, action, description, ip_address, source)
    VALUES (?, 'LOGIN', 'User logged in', ?, 'web')
");

$stmt->execute([
    $user['id'],
    $_SERVER['REMOTE_ADDR'] ?? null
]);

if ($user['role'] === 'admin') {
    header("Location: ../admin/dashboard.php");
} else {
    header("Location: ../web/home.php");
}

exit;