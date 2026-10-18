<?php

session_start();

require_once "../db.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: ../web/register.php");
    exit;
}

$full_name = trim($_POST['full_name'] ?? '');
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$confirm_password = $_POST['confirm_password'] ?? '';

if ($full_name === '' || $email === '' || $password === '') {
    $_SESSION['register_error'] = "Please complete all required fields.";
    header("Location: ../web/register.php");
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['register_error'] = "Please enter a valid email address.";
    header("Location: ../web/register.php");
    exit;
}

if (strlen($password) < 8) {
    $_SESSION['register_error'] = "Password must contain at least 8 characters.";
    header("Location: ../web/register.php");
    exit;
}

if ($password !== $confirm_password) {
    $_SESSION['register_error'] = "Passwords do not match.";
    header("Location: ../web/register.php");
    exit;
}

$stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);

if ($stmt->fetch()) {
    $_SESSION['register_error'] = "An account with that email already exists.";
    header("Location: ../web/register.php");
    exit;
}

$hashed_password = password_hash($password, PASSWORD_DEFAULT);

$stmt = $pdo->prepare("
    INSERT INTO users (full_name, email, password, role)
    VALUES (?, ?, ?, 'user')
");

$stmt->execute([
    $full_name,
    $email,
    $hashed_password
]);

$_SESSION['login_success'] = "Account created successfully. Please log in.";

header("Location: ../web/login.php");
exit;