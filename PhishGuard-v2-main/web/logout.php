<?php

session_start();

if (isset($_SESSION['user_id'])) {
    require_once "../db.php";

    $stmt = $pdo->prepare("
        INSERT INTO activity_logs
        (user_id, action, description, ip_address, source)
        VALUES (?, 'LOGOUT', 'User logged out', ?, 'web')
    ");

    $stmt->execute([
        $_SESSION['user_id'],
        $_SERVER['REMOTE_ADDR'] ?? null
    ]);
}

$_SESSION = [];

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

session_destroy();

header("Location: login.php");
exit;